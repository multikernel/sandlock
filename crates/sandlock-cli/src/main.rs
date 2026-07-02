use clap::{Parser, Subcommand};
use sandlock_core::Sandbox;
use sandlock_core::sandbox::{BranchAction, ByteSize, SandboxBuilder};
use sandlock_core::profile;
use anyhow::{Result, anyhow};
use std::path::PathBuf;
use std::time::SystemTime;

mod network_registry;
mod learn;

#[derive(Parser)]
#[command(name = "sandlock", about = "Lightweight process sandbox", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command in a sandbox
    Run(RunArgs),
    /// Check kernel feature support
    Check,
    /// List all running sandboxes
    List,
    /// Kill a running sandbox by name
    Kill {
        /// Sandbox name (as shown by `sandlock list`)
        name: String,
    },
    /// Manage profiles
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Observe a workload and emit a sandlock profile
    Learn(LearnArgs),
}

/// Arguments for the `run` subcommand.
///
/// Sandbox-level flags come from `SandboxBuilder` via `#[clap(flatten)]`.
/// CLI-only flags (profile, timeout, image, etc.) and non-clap-friendly
/// sandbox fields (max_memory, fs_mount, env, gpu, cpu-cores) remain here.
/// GPU visibility for `--gpu`: `all` for every present GPU, or explicit
/// indices like `0,2`. Absence of the flag means no GPU access.
#[derive(Clone, Debug)]
enum GpuSelection {
    All,
    Devices(Vec<u32>),
}

impl std::str::FromStr for GpuSelection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("all") {
            return Ok(GpuSelection::All);
        }
        let devices = s
            .split(',')
            .map(|p| {
                let p = p.trim();
                p.parse::<u32>().map_err(|_| {
                    format!("invalid GPU index '{p}'; expected 'all' or indices like 0,2")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GpuSelection::Devices(devices))
    }
}

#[derive(clap::Args)]
struct RunArgs {
    // ── Sandbox flags (flattened from SandboxBuilder) ───────────────────────
    #[clap(flatten)]
    sandbox_builder: SandboxBuilder,

    // ── Sandbox-builder fields that need special parsing (not in SandboxBuilder's clap derive) ──
    #[arg(short = 'm', long = "max-memory")]
    max_memory: Option<String>,

    #[arg(long = "max-disk")]
    max_disk: Option<String>,

    #[arg(long)]
    time_start: Option<String>,

    /// Mount a host path inside the sandbox; append :ro for read-only
    /// (e.g. --fs-mount /work:/host/path or --fs-mount /work:/host/path:ro)
    #[arg(long = "fs-mount", value_name = "VIRTUAL:HOST[:ro]")]
    fs_mount: Vec<String>,

    /// COW branch action on normal sandbox exit: commit | abort | keep
    /// (default: commit).
    #[arg(long = "on-exit", value_name = "ACTION")]
    on_exit: Option<String>,

    /// COW branch action on sandbox error: commit | abort | keep
    /// (default: abort).
    #[arg(long = "on-error", value_name = "ACTION")]
    on_error: Option<String>,

    #[arg(long = "env", value_name = "KEY=VALUE")]
    env_vars: Vec<String>,

    /// CPU cores to pin the sandbox to (e.g. --cpu-cores 0,2,3)
    #[arg(long = "cpu-cores", value_delimiter = ',')]
    cpu_cores: Vec<u32>,

    /// GPUs visible to the sandbox: `all` for every GPU, or indices (e.g. --gpu 0,2)
    #[arg(long = "gpu", value_name = "all|N,N,...")]
    gpu: Option<GpuSelection>,

    // ── CLI-only flags ───────────────────────────────────────────────────────
    #[arg(short = 't', long)]
    timeout: Option<u64>,

    #[arg(short = 'p', long, conflicts_with = "profile_file")]
    profile: Option<String>,

    /// Load a profile directly from a file path (TOML format)
    #[arg(long = "profile-file", value_name = "PATH", conflicts_with = "profile")]
    profile_file: Option<PathBuf>,

    #[arg(long = "status-fd", value_name = "FD")]
    status_fd: Option<i32>,

    /// Sandbox name (also exposed as the virtual hostname; auto-generated if omitted)
    #[arg(long)]
    name: Option<String>,

    #[arg(short = 'e', long = "exec-shell", value_name = "CMD")]
    exec_shell: Option<String>,

    #[arg(short = 'i', long)]
    interactive: bool,

    /// Use a local Docker image as chroot rootfs, given by reference
    /// (e.g. `python:3.12-slim`, a digest, or an image id). The image
    /// must already be present in local Docker storage; sandlock never
    /// pulls from a registry. Requires a running Docker daemon and an
    /// accessible socket; the run fails early if neither is reachable.
    #[arg(long, value_name = "IMAGE")]
    image: Option<String>,

    /// Dry-run: run the command, show filesystem changes, then discard
    #[arg(long)]
    dry_run: bool,

    /// No-supervisor mode: apply Landlock rules + deny-only seccomp filter, then exec directly
    #[arg(long)]
    no_supervisor: bool,

    /// Allow the named protection to degrade silently if the host kernel ABI lacks support.
    /// Repeatable. Accepted values: fs-refer, fs-truncate, net-tcp, fs-ioctl-dev,
    /// signal-scope, abstract-unix-socket-scope.
    #[arg(long = "allow-degraded", value_name = "PROTECTION")]
    allow_degraded: Vec<String>,

    /// Disable the named protection entirely (no rule emitted, no error on missing ABI).
    /// Repeatable. Accepts the same values as --allow-degraded, except fs-refer:
    /// the kernel denies REFER by default even when unhandled, so disabling it
    /// only tightens the sandbox and is rejected.
    #[arg(long = "disable", value_name = "PROTECTION")]
    disable: Vec<String>,

    #[arg(last = true)]
    cmd: Vec<String>,
}

/// Parse a kebab-case protection name into a `Protection` value.
///
/// The canonical names match the Landlock kernel constants
/// (`LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` → `abstract-unix-socket-scope`,
/// etc.) and are case-insensitive. Accepted: `fs-refer`, `fs-truncate`,
/// `net-tcp`, `fs-ioctl-dev`, `signal-scope`,
/// `abstract-unix-socket-scope`.
fn parse_protection(s: &str) -> Result<sandlock_core::Protection, String> {
    use sandlock_core::Protection;
    match s.to_ascii_lowercase().as_str() {
        "fs-refer" => Ok(Protection::FsRefer),
        "fs-truncate" => Ok(Protection::FsTruncate),
        "net-tcp" => Ok(Protection::NetTcp),
        "fs-ioctl-dev" => Ok(Protection::FsIoctlDev),
        "signal-scope" => Ok(Protection::SignalScope),
        "abstract-unix-socket-scope" => Ok(Protection::AbstractUnixSocketScope),
        other => Err(format!(
            "unknown protection: {} (valid: fs-refer, fs-truncate, net-tcp, fs-ioctl-dev, signal-scope, abstract-unix-socket-scope)",
            other,
        )),
    }
}

#[derive(Subcommand)]
enum ProfileAction {
    /// List available profiles
    List,
    /// Show profile contents
    Show { name: String },
    /// Delete a profile
    Delete { name: String },
}

/// Arguments for the `learn` subcommand.
#[derive(clap::Args)]
struct LearnArgs {
    /// Write observed profile to this file (default: print to stdout)
    #[arg(short = 'o', long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Command to observe (everything after --)
    #[arg(last = true, required = true)]
    cmd: Vec<String>,
}

#[derive(serde::Serialize)]
struct SandboxStatus {
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<i32>,
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => {
            let code = run_command(args).await?;
            std::process::exit(code);
        }

        Command::List => {
            match network_registry::list() {
                Ok(reg) if reg.is_empty() => {
                    println!("No running sandboxes.");
                }
                Ok(reg) => {
                    println!("{:<20} {:>6}  {:<30} {}", "NAME", "PID", "PORTS", "ALLOWED HOSTS");
                    for (name, entry) in &reg {
                        let ports: Vec<String> = entry.ports.iter()
                            .map(|(v, r)| if v == r { format!("{}", v) } else { format!("{} -> {}", v, r) })
                            .collect();
                        let ports_str = if ports.is_empty() { "-".to_string() } else { ports.join(", ") };
                        let hosts_str = if entry.allowed_hosts.is_empty() {
                            "*".to_string()
                        } else {
                            entry.allowed_hosts.join(", ")
                        };
                        println!("{:<20} {:>6}  {:<30} {}", name, entry.pid, ports_str, hosts_str);
                    }
                }
                Err(e) => {
                    eprintln!("sandlock: failed to read registry: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Command::Kill { name } => {
            match network_registry::list() {
                Ok(reg) => {
                    if let Some(entry) = reg.get(&name) {
                        let ret = unsafe { libc::killpg(entry.pid, libc::SIGKILL) };
                        if ret == 0 {
                            let _ = network_registry::unregister(&name);
                            println!("Killed sandbox '{}' (PID {})", name, entry.pid);
                        } else {
                            let err = std::io::Error::last_os_error();
                            eprintln!("sandlock: failed to kill '{}' (PID {}): {}", name, entry.pid, err);
                            std::process::exit(1);
                        }
                    } else {
                        eprintln!("sandlock: no sandbox named '{}'", name);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("sandlock: failed to read registry: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Command::Check => {
            println!("Kernel feature support:");
            match sandlock_core::landlock_abi_version() {
                Ok(v) => {
                    println!("  Landlock:       ABI v{}", v);
                    println!("  Minimum required: ABI v{}", sandlock_core::MIN_LANDLOCK_ABI);
                    if v < sandlock_core::MIN_LANDLOCK_ABI {
                        println!("  Status:         UNSUPPORTED (upgrade kernel)");
                    } else {
                        println!("  Status:         OK");
                    }
                    println!("  Filesystem:     supported (ABI v1+)");
                    println!("  File truncate:  {}", if v >= 3 { "supported (ABI v3+)" } else { "not supported" });
                    println!("  TCP ports:      {}", if v >= 4 { "supported (ABI v4+)" } else { "not supported" });
                    println!("  Device ioctl:   {}", if v >= 5 { "supported (ABI v5+)" } else { "not supported" });
                    println!("  IPC scoping:    {}", if v >= 6 { "supported (ABI v6+)" } else { "not supported" });
                    println!("  Signal scoping: {}", if v >= 6 { "supported (ABI v6+)" } else { "not supported" });

                    println!();
                    println!("Per-protection availability (host Landlock ABI v{}):", v);
                    for p in sandlock_core::Protection::all() {
                        let available = v >= p.min_abi();
                        let marker = if available { "available" } else { "unavailable" };
                        println!("  {:<22} requires v{} — {}", format!("{:?}", p), p.min_abi(), marker);
                    }
                }
                Err(e) => {
                    println!("  Landlock: unavailable ({})", e);
                    println!("  Status:   UNSUPPORTED");
                }
            }
            println!("  Platform: {}", std::env::consts::ARCH);
        }

        Command::Learn(args) => {
            learn::run(args).await?;
        }

        Command::Profile { action } => {
            match action {
                ProfileAction::List => {
                    let profiles = profile::list_profiles()?;
                    if profiles.is_empty() {
                        println!("No profiles found in {}", profile::profile_dir().display());
                    } else {
                        for name in profiles { println!("  {}", name); }
                    }
                }
                ProfileAction::Show { name } => {
                    let path = profile::profile_dir().join(format!("{}.toml", name));
                    let content = std::fs::read_to_string(&path)?;
                    println!("{}", content);
                }
                ProfileAction::Delete { name } => {
                    let path = profile::profile_dir().join(format!("{}.toml", name));
                    std::fs::remove_file(&path)?;
                    println!("Deleted profile '{}'", name);
                }
            }
        }
    }

    Ok(())
}

/// Implementation of `sandlock run`.
/// Returns the desired process exit code; the caller does
/// `process::exit`. Calling `process::exit` here would bypass
/// `Sandbox::Drop`, which is where COW commit/abort runs.
async fn run_command(args: RunArgs) -> Result<i32> {
    let pb = &args.sandbox_builder;

    // `--no-supervisor` reaches the same `Sandbox::run` path as everything
    // else; the deny-only filter and skipped supervisor are gated on the
    // sandbox's `no_supervisor` field. Validate flag/profile combinations
    // upfront so users hit the error before any setup happens.
    if args.no_supervisor {
        validate_no_supervisor(&args)?;
    }

    // Hoist the profile load so we don't read+parse twice.
    let (base_from_profile, profile_program_spec) = if let Some(ref name) = args.profile {
        let (base, spec) = profile::load_profile(name)?;
        (Some(base), Some(spec))
    } else if let Some(ref path) = args.profile_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read profile file {}: {}", path.display(), e))?;
        let (base, spec) = profile::parse_profile(&content)?;
        (Some(base), Some(spec))
    } else {
        (None, None)
    };

    if args.no_supervisor {
        if let Some(ref base) = base_from_profile {
            validate_no_supervisor_profile(base, &profile_source(&args))?;
        }
    }

    // Start from profile or default
    let mut builder = if let Some(base) = base_from_profile {
        // Rebuild builder from loaded profile as base
        let mut b = Sandbox::builder();
        for p in &base.fs_readable { b = b.fs_read(p); }
        for p in &base.fs_writable { b = b.fs_write(p); }
        for p in &base.fs_denied { b = b.fs_deny(p); }
        for rule in &base.net_allow {
            b = b.net_allow(format_net_rule(rule));
        }
        for rule in &base.net_deny {
            b = b.net_deny(format_net_rule(rule));
        }
        for p in &base.net_allow_bind { b = b.net_allow_bind_port(*p); }
        for p in &base.net_deny_bind { b = b.net_deny_bind_port(*p); }
        for rule in &base.http_allow {
            let s = format!("{} {}{}", rule.method, rule.host, rule.path);
            b = b.http_allow(&s);
        }
        for rule in &base.http_deny {
            let s = format!("{} {}{}", rule.method, rule.host, rule.path);
            b = b.http_deny(&s);
        }
        for port in &base.http_ports {
            b = b.http_port(*port);
        }
        if let Some(mem) = base.max_memory { b = b.max_memory(mem); }
        b = b.max_processes(base.max_processes);
        if let Some(cpu) = base.max_cpu { b = b.max_cpu(cpu); }
        if let Some(seed) = base.random_seed { b = b.random_seed(seed); }
        if let Some(n) = base.num_cpus { b = b.num_cpus(n); }
        if let Some(n) = base.max_open_files { b = b.max_open_files(n); }
        if let Some(disk) = base.max_disk { b = b.max_disk(disk); }
        if !base.extra_deny_syscalls.is_empty() { b = b.extra_deny_syscalls(base.extra_deny_syscalls.clone()); }
        if !base.extra_allow_syscalls.is_empty() { b = b.extra_allow_syscalls(base.extra_allow_syscalls.clone()); }
        b = b.clean_env(base.clean_env);
        for (k, v) in &base.env { b = b.env_var(k, v); }
        if let Some(ref w) = base.workdir { b = b.workdir(w); }
        if let Some(ref c) = base.cwd { b = b.cwd(c); }
        // HTTP MITM material
        if let Some(ref ca) = base.http_ca { b = b.http_ca(ca); }
        if let Some(ref key) = base.http_key { b = b.http_key(key); }
        for p in &base.http_inject_ca { b = b.http_inject_ca(p); }
        if let Some(ref out) = base.http_ca_out { b = b.http_ca_out(out); }
        // Filesystem extras
        if let Some(ref path) = base.chroot { b = b.chroot(path); }
        if let Some(ref path) = base.fs_storage { b = b.fs_storage(path); }
        for (virt, host) in &base.fs_mount {
            if base.fs_mount_ro.iter().any(|d| d == virt) {
                b = b.fs_mount_ro(virt, host);
            } else {
                b = b.fs_mount(virt, host);
            }
        }
        b = b.on_exit(base.on_exit.clone());
        b = b.on_error(base.on_error.clone());
        b = b.deterministic_dirs(base.deterministic_dirs);
        // Determinism / process knobs
        b = b.no_randomize_memory(base.no_randomize_memory);
        b = b.no_huge_pages(base.no_huge_pages);
        b = b.no_coredump(base.no_coredump);
        if let Some(t) = base.time_start { b = b.time_start(t); }
        // Network virtualization
        b = b.port_remap(base.port_remap);
        // Process identity
        if let Some(user) = base.user { b = b.user(user.uid, user.gid); }
        // Hardware constraints
        if let Some(ref devs) = base.gpu_devices { b = b.gpu_devices(devs.clone()); }
        if let Some(ref cores) = base.cpu_cores { b = b.cpu_cores(cores.clone()); }
        b
    } else {
        Sandbox::builder()
    };

    // CLI overrides — fields from flattened SandboxBuilder
    for p in &pb.fs_readable { builder = builder.fs_read(p); }
    for p in &pb.fs_writable { builder = builder.fs_write(p); }
    if let Some(n) = pb.max_processes { builder = builder.max_processes(n); }
    for spec in &pb.net_allow { builder = builder.net_allow(spec); }
    for spec in &pb.net_deny { builder = builder.net_deny(spec); }
    for spec in &pb.net_allow_bind { builder = builder.net_allow_bind(spec); }
    for spec in &pb.net_deny_bind { builder = builder.net_deny_bind(spec); }
    if let Some(seed) = pb.random_seed { builder = builder.random_seed(seed); }
    if pb.clean_env { builder = builder.clean_env(true); }
    if let Some(n) = pb.num_cpus { builder = builder.num_cpus(n); }
    if let Some(cpu) = pb.max_cpu { builder = builder.max_cpu(cpu); }
    if let Some(n) = pb.max_open_files { builder = builder.max_open_files(n); }
    for p in &pb.fs_denied { builder = builder.fs_deny(p); }
    if let Some(ref path) = pb.chroot { builder = builder.chroot(path); }
    if let Some(user) = pb.user { builder = builder.user(user.uid, user.gid); }
    if let Some(ref path) = pb.workdir { builder = builder.workdir(path); }
    if let Some(ref path) = pb.cwd { builder = builder.cwd(path); }
    if let Some(ref path) = pb.fs_storage { builder = builder.fs_storage(path); }
    if !pb.extra_allow_syscalls.is_empty() { builder = builder.extra_allow_syscalls(pb.extra_allow_syscalls.clone()); }
    if !pb.extra_deny_syscalls.is_empty() { builder = builder.extra_deny_syscalls(pb.extra_deny_syscalls.clone()); }
    for rule in &pb.http_allow { builder = builder.http_allow(rule); }
    for rule in &pb.http_deny { builder = builder.http_deny(rule); }
    for port in &pb.http_ports { builder = builder.http_port(*port); }
    if let Some(ref ca) = pb.http_ca { builder = builder.http_ca(ca); }
    if let Some(ref key) = pb.http_key { builder = builder.http_key(key); }
    for p in &pb.http_inject_ca { builder = builder.http_inject_ca(p); }
    if let Some(ref out) = pb.http_ca_out { builder = builder.http_ca_out(out); }
    if pb.port_remap { builder = builder.port_remap(true); }
    if pb.no_randomize_memory { builder = builder.no_randomize_memory(true); }
    if pb.no_huge_pages { builder = builder.no_huge_pages(true); }
    if pb.deterministic_dirs { builder = builder.deterministic_dirs(true); }
    if pb.no_coredump { builder = builder.no_coredump(true); }

    // CLI overrides — non-clap-friendly fields (still parsed here)
    if let Some(ref m) = args.max_memory { builder = builder.max_memory(ByteSize::parse(m)?); }
    if let Some(ref ts) = args.time_start {
        let t = parse_time_start(ts)?;
        builder = builder.time_start(t);
    }
    if let Some(ref s) = args.max_disk { builder = builder.max_disk(ByteSize::parse(s)?); }
    if let Some(ref s) = args.on_exit {
        builder = builder.on_exit(parse_branch_action("--on-exit", s)?);
    }
    if let Some(ref s) = args.on_error {
        builder = builder.on_error(parse_branch_action("--on-error", s)?);
    }
    for spec in &args.fs_mount {
        let (virt, host, read_only) = profile::parse_mount_spec(spec)?;
        builder = if read_only {
            builder.fs_mount_ro(virt, host)
        } else {
            builder.fs_mount(virt, host)
        };
    }
    if !args.cpu_cores.is_empty() { builder = builder.cpu_cores(args.cpu_cores.clone()); }
    match &args.gpu {
        // `all` maps to an empty device list, which the core expands to every
        // present GPU; explicit indices pass through unchanged.
        Some(GpuSelection::All) => builder = builder.gpu_devices(Vec::new()),
        Some(GpuSelection::Devices(devs)) => builder = builder.gpu_devices(devs.clone()),
        None => {}
    }
    for spec in &args.env_vars {
        if let Some((k, v)) = spec.split_once('=') {
            builder = builder.env_var(k, v);
        } else {
            return Err(anyhow!("--env requires KEY=VALUE, got: {}", spec));
        }
    }

    let sandbox_name = args.name.clone().unwrap_or_else(|| network_registry::next_name());

    // Handle --image: extract rootfs, set chroot, get default cmd.
    // Auto-set workdir to the rootfs path when the user hasn't passed one,
    // so seccomp COW stages writes in an upper layer instead of mutating
    // the shared image cache directly.
    let image_cmd: Option<Vec<String>>;
    if let Some(ref img) = args.image {
        let rootfs = sandlock_core::image::extract(img, None).await?;
        builder = builder.chroot(&rootfs).fs_read("/");
        if pb.workdir.is_none() {
            builder = builder.workdir(&rootfs);
        }
        if args.cmd.is_empty() {
            image_cmd = Some(sandlock_core::image::inspect_cmd(img).await?);
        } else {
            image_cmd = None;
        }
    } else {
        image_cmd = None;
    }

    // Derive the effective command: profile's [program] section supplies a
    // default; a trailing positional command on the CLI overrides it.
    let profile_cmd: Option<Vec<String>> = if args.cmd.is_empty() && args.exec_shell.is_none() && image_cmd.is_none() {
        if let Some(spec) = profile_program_spec {
            if let Some(exec) = spec.exec {
                let exec_str = exec.into_os_string().into_string()
                    .map_err(|_| anyhow!("non-UTF-8 exec path in profile"))?;
                let mut v = vec![exec_str];
                v.extend(spec.args);
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    if args.exec_shell.is_none() && args.cmd.is_empty() && image_cmd.is_none() && profile_cmd.is_none() {
        return Err(anyhow!("no command specified (no trailing command and no [program].exec in profile)"));
    }

    if args.no_supervisor {
        builder = builder.no_supervisor(true);
    }

    // CLI overrides — protection policy
    for s in &args.allow_degraded {
        builder = builder.allow_degraded(parse_protection(s).map_err(|e| anyhow!(e))?);
    }
    for s in &args.disable {
        builder = builder.disable(parse_protection(s).map_err(|e| anyhow!(e))?);
    }

    let policy = builder.build()?;
    let cmd_strs: Vec<&str> = if let Some(ref shell_cmd) = args.exec_shell {
        vec!["/bin/sh", "-c", shell_cmd.as_str()]
    } else if let Some(ref ic) = image_cmd {
        ic.iter().map(|s| s.as_str()).collect()
    } else if !args.cmd.is_empty() {
        args.cmd.iter().map(|s| s.as_str()).collect()
    } else if let Some(ref pc) = profile_cmd {
        pc.iter().map(|s| s.as_str()).collect()
    } else {
        // Unreachable: the check above would have returned an error.
        unreachable!("no command source available")
    };

    // Bake the instance name into the sandbox so all lifecycle methods use it.
    let mut policy = policy.with_name(sandbox_name.clone());

    let result = if args.dry_run {
        if policy.workdir.is_none() {
            return Err(anyhow!("--dry-run requires --workdir"));
        }
        let dr = if let Some(secs) = args.timeout {
            match tokio::time::timeout(
                std::time::Duration::from_secs(secs),
                policy.dry_run_interactive(&cmd_strs),
            ).await {
                Ok(r) => r?,
                Err(_) => {
                    eprintln!("sandlock: timeout after {}s", secs);
                    return Ok(124);
                }
            }
        } else {
            policy.dry_run_interactive(&cmd_strs).await?
        };

        if dr.changes.is_empty() {
            eprintln!("sandlock: dry-run: no filesystem changes");
        } else {
            eprintln!("sandlock: dry-run: filesystem changes:");
            for change in &dr.changes {
                eprintln!("{}", change);
            }
        }
        dr.run_result
    } else if policy.port_remap {
        // Use spawn+wait so we can register/unregister network state.

        // Set up callback to update registry on each port bind.
        let reg_name = sandbox_name.clone();
        policy.set_on_bind(move |ports| {
            let _ = network_registry::update_ports(&reg_name, ports.clone());
        });

        policy.create_interactive(&cmd_strs).await?;
        policy.start()?;

        let pid = policy.pid().unwrap_or(0);
        let registered_hosts: Vec<String> = policy
            .net_allow
            .iter()
            .filter_map(|r| match &r.target {
                sandlock_core::sandbox::NetTarget::Host(h) => Some(h.clone()),
                sandlock_core::sandbox::NetTarget::Cidr(c) => Some(c.to_string()),
                sandlock_core::sandbox::NetTarget::AnyIp => None,
            })
            .collect();
        if let Err(e) = network_registry::register(
            &sandbox_name, pid, std::collections::HashMap::new(),
            registered_hosts,
            None, // virtual_etc_hosts populated by core at runtime
        ) {
            eprintln!("sandlock: network registry: {}", e);
        }

        let result = if let Some(secs) = args.timeout {
            match tokio::time::timeout(
                std::time::Duration::from_secs(secs),
                policy.wait(),
            ).await {
                Ok(r) => r?,
                Err(_) => {
                    let _ = network_registry::unregister(&sandbox_name);
                    eprintln!("sandlock: timeout after {}s", secs);
                    return Ok(124);
                }
            }
        } else {
            policy.wait().await?
        };
        let _ = network_registry::unregister(&sandbox_name);
        result
    } else if let Some(secs) = args.timeout {
        match tokio::time::timeout(
            std::time::Duration::from_secs(secs),
            policy.run_interactive(&cmd_strs),
        ).await {
            Ok(r) => r?,
            Err(_) => {
                eprintln!("sandlock: timeout after {}s", secs);
                return Ok(124);
            }
        }
    } else {
        policy.run_interactive(&cmd_strs).await?
    };

    if let Some(fd) = args.status_fd {
        use std::io::Write as _;
        use std::os::unix::io::FromRawFd;
        use sandlock_core::ExitStatus as SandlockExitStatus;
        let (code, signal) = match &result.exit_status {
            SandlockExitStatus::Code(c) => (*c, None),
            SandlockExitStatus::Signal(s) => (-1, Some(*s)),
            SandlockExitStatus::Killed => (-1, None),
            SandlockExitStatus::Timeout => (-1, None),
        };
        let status = SandboxStatus { exit_code: code, signal };
        if let Ok(json) = serde_json::to_string(&status) {
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            let _ = writeln!(file, "{}", json);
            std::mem::forget(file); // Don't close the fd
        }
    }

    Ok(result.code().unwrap_or(1))
}

/// Validate that no flags incompatible with --no-supervisor are set.
fn validate_no_supervisor(args: &RunArgs) -> Result<()> {
    let pb = &args.sandbox_builder;
    let mut bad = Vec::new();

    if args.max_memory.is_some() { bad.push("--max-memory"); }
    if pb.max_processes.is_some() { bad.push("--max-processes"); }
    if pb.max_cpu.is_some() { bad.push("--max-cpu"); }
    if pb.max_open_files.is_some() { bad.push("--max-open-files"); }
    if args.timeout.is_some() { bad.push("--timeout"); }
    if !pb.net_allow.is_empty() { bad.push("--net-allow"); }
    if !pb.net_deny.is_empty() { bad.push("--net-deny"); }
    if !pb.net_allow_bind.is_empty() { bad.push("--net-allow-bind"); }
    if !pb.net_deny_bind.is_empty() { bad.push("--net-deny-bind"); }
    if !pb.http_allow.is_empty() { bad.push("--http-allow"); }
    if !pb.http_deny.is_empty() { bad.push("--http-deny"); }
    if !pb.http_ports.is_empty() { bad.push("--http-port"); }
    if pb.num_cpus.is_some() { bad.push("--num-cpus"); }
    if pb.random_seed.is_some() { bad.push("--random-seed"); }
    if args.time_start.is_some() { bad.push("--time-start"); }
    if pb.no_randomize_memory { bad.push("--no-randomize-memory"); }
    if pb.no_huge_pages { bad.push("--no-huge-pages"); }
    if pb.deterministic_dirs { bad.push("--deterministic-dirs"); }
    if args.name.is_some() { bad.push("--name"); }
    if pb.chroot.is_some() { bad.push("--chroot"); }
    if args.image.is_some() { bad.push("--image"); }
    if pb.user.is_some() { bad.push("--user"); }
    if pb.workdir.is_some() { bad.push("--workdir"); }
    if pb.cwd.is_some() { bad.push("--cwd"); }
    if pb.fs_storage.is_some() { bad.push("--fs-storage"); }
    if args.max_disk.is_some() { bad.push("--max-disk"); }
    if pb.port_remap { bad.push("--port-remap"); }
    if !args.cpu_cores.is_empty() { bad.push("--cpu-cores"); }
    if args.gpu.is_some() { bad.push("--gpu"); }
    if args.dry_run { bad.push("--dry-run"); }
    if args.status_fd.is_some() { bad.push("--status-fd"); }
    if !pb.fs_denied.is_empty() { bad.push("--fs-deny"); }
    if !args.fs_mount.is_empty() { bad.push("--fs-mount"); }

    if !bad.is_empty() {
        return Err(anyhow!(
            "--no-supervisor is incompatible with: {}",
            bad.join(", ")
        ));
    }

    Ok(())
}

fn profile_source(args: &RunArgs) -> String {
    args.profile.as_deref()
        .map(|n| format!("profile {n}"))
        .unwrap_or_else(|| {
            let path = args.profile_file
                .as_ref()
                .expect("profile_source called without a loaded profile");
            format!("profile file {}", path.display())
        })
}

/// Validate profile fields against the smaller no-supervisor execution model.
///
/// No-supervisor mode only applies Landlock filesystem allow rules, the
/// deny-only seccomp blocklist, and environment changes before exec. Reject
/// profile fields that require the supervisor or other setup paths so profile
/// users do not get a silently weakened sandbox.
fn validate_no_supervisor_profile(profile: &Sandbox, source: &str) -> Result<()> {
    let mut bad = Vec::new();

    if !profile.fs_denied.is_empty() { bad.push("[filesystem].deny"); }
    if !profile.net_allow.is_empty() { bad.push("[network].allow"); }
    if !profile.net_deny.is_empty() { bad.push("[network].deny"); }
    if !profile.net_allow_bind.is_empty() { bad.push("[network].allow_bind"); }
    if !profile.net_deny_bind.is_empty() { bad.push("[network].deny_bind"); }
    if profile.port_remap { bad.push("[network].port_remap"); }
    if !profile.http_allow.is_empty() { bad.push("[http].allow"); }
    if !profile.http_deny.is_empty() { bad.push("[http].deny"); }
    if !profile.http_ports.is_empty() { bad.push("[http].ports"); }
    if profile.http_ca.is_some() { bad.push("[config].http_ca"); }
    if profile.http_key.is_some() { bad.push("[config].http_key"); }
    if profile.max_memory.is_some() { bad.push("[limits].memory"); }
    if profile.max_processes != 64 { bad.push("[limits].processes"); }
    if profile.max_open_files.is_some() { bad.push("[limits].open_files"); }
    if profile.max_cpu.is_some() { bad.push("[limits].cpu"); }
    if profile.max_disk.is_some() { bad.push("[limits].disk"); }
    if profile.gpu_devices.is_some() { bad.push("[limits].gpu_devices"); }
    if profile.cpu_cores.is_some() { bad.push("[limits].cpu_cores"); }
    if profile.num_cpus.is_some() { bad.push("[limits].num_cpus"); }
    if profile.random_seed.is_some() { bad.push("[determinism].random_seed"); }
    if profile.time_start.is_some() { bad.push("[determinism].time_start"); }
    if profile.deterministic_dirs { bad.push("[determinism].deterministic_dirs"); }
    if profile.no_randomize_memory { bad.push("[determinism].no_randomize_memory"); }
    if profile.no_huge_pages { bad.push("[program].no_huge_pages"); }
    if profile.no_coredump { bad.push("[program].no_coredump"); }
    if profile.workdir.is_some() { bad.push("[config].workdir"); }
    if profile.fs_storage.is_some() { bad.push("[config].fs_storage"); }
    if profile.cwd.is_some() { bad.push("[program].cwd"); }
    if profile.user.is_some() { bad.push("[program].uid"); }
    if profile.chroot.is_some() { bad.push("[filesystem].chroot"); }
    if !profile.fs_mount.is_empty() { bad.push("[filesystem].mount"); }
    if profile.on_exit != BranchAction::Commit { bad.push("[filesystem].on_exit"); }
    if profile.on_error != BranchAction::Abort { bad.push("[filesystem].on_error"); }

    if !bad.is_empty() {
        return Err(anyhow!(
            "--no-supervisor is incompatible with {} field(s): {}",
            source,
            bad.join(", ")
        ));
    }

    Ok(())
}

/// Render a parsed `NetRule` back into a `--net-allow` / `--net-deny` spec
/// string, so a profile loaded via `--profile-file` round-trips through the
/// builder. Allow and deny share one grammar: bare TCP, explicit
/// `udp://`/`icmp://`, IPv6 bracketed only when a port follows, and the
/// all-ports case drops the redundant `:*`.
fn format_net_rule(rule: &sandlock_core::sandbox::NetRule) -> String {
    use sandlock_core::sandbox::{NetTarget, Protocol};
    let target = match &rule.target {
        NetTarget::AnyIp => "*".to_string(),
        NetTarget::Host(h) => h.clone(),
        NetTarget::Cidr(c) => {
            // Bracket IPv6 only when a port suffix will follow, because a
            // bare addr:port is itself a valid IPv6 address.
            if matches!(c.addr, std::net::IpAddr::V6(_)) && !rule.all_ports {
                format!("[{}]", c)
            } else {
                c.to_string()
            }
        }
    };
    match rule.protocol {
        Protocol::Icmp => format!("icmp://{}", target),
        proto => {
            let scheme = if matches!(proto, Protocol::Udp) { "udp://" } else { "" };
            if rule.all_ports {
                format!("{}{}", scheme, target)
            } else {
                let ports = format_ports(&rule.ports);
                format!("{}{}:{}", scheme, target, ports)
            }
        }
    }
}

/// Render a concrete port list into the comma-separated port-suffix form
/// (`80,443`). The all-ports case is handled by the callers, which drop the
/// suffix entirely rather than emitting `:*`.
fn format_ports(ports: &[u16]) -> String {
    ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
}

/// Parse an ISO 8601 timestamp (e.g. "2000-01-01T00:00:00Z") into a SystemTime.
fn parse_time_start(s: &str) -> Result<SystemTime> {
    let ts: jiff::Timestamp = s.parse()
        .map_err(|e| anyhow!("invalid --time-start '{}': {}", s, e))?;
    Ok(ts.into())
}

fn parse_branch_action(flag: &str, s: &str) -> Result<BranchAction> {
    match s {
        "commit" => Ok(BranchAction::Commit),
        "abort"  => Ok(BranchAction::Abort),
        "keep"   => Ok(BranchAction::Keep),
        other    => Err(anyhow!("invalid {} value '{}': expected commit | abort | keep", flag, other)),
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use sandlock_core::sandbox::NetRule;

    #[test]
    fn render_allow_drops_redundant_all_ports_star() {
        let r = NetRule::parse_allow("udp://*:*").unwrap();
        assert_eq!(format_net_rule(&r), "udp://*");
    }

    #[test]
    fn render_allow_any_ip_all_ports_tcp_is_bare_star() {
        let r = NetRule::parse_allow(":*").unwrap();
        assert_eq!(format_net_rule(&r), "*");
    }

    #[test]
    fn render_allow_host_ports() {
        let r = NetRule::parse_allow("example.com:443").unwrap();
        assert_eq!(format_net_rule(&r), "example.com:443");
    }

    #[test]
    fn render_cidr_and_ipv6_round_trip() {
        // CIDR and IPv6-literal targets render identically for allow/deny.
        assert_eq!(format_net_rule(&NetRule::parse_allow("10.0.0.0/8:80").unwrap()), "10.0.0.0/8:80");
        assert_eq!(format_net_rule(&NetRule::parse_deny("10.0.0.0/8").unwrap()), "10.0.0.0/8");
        assert_eq!(format_net_rule(&NetRule::parse_allow("[::1]:443").unwrap()), "[::1]:443");
        assert_eq!(format_net_rule(&NetRule::parse_allow("::1").unwrap()), "::1");
    }

    #[test]
    fn render_roundtrips_through_parse() {
        for spec in [
            "example.com:443", "udp://1.1.1.1:53", "icmp://github.com", "*", "udp://*",
            "10.0.0.0/8:80", "[fc00::/7]:443", "::1", "1.2.3.4",
        ] {
            let r = NetRule::parse_allow(spec).unwrap();
            let rendered = format_net_rule(&r);
            let r2 = NetRule::parse_allow(&rendered).unwrap();
            assert_eq!(r.target, r2.target, "target mismatch for {spec}");
            assert_eq!(r.ports, r2.ports, "ports mismatch for {spec}");
            assert_eq!(r.all_ports, r2.all_ports, "all_ports mismatch for {spec}");
            assert_eq!(r.protocol, r2.protocol, "protocol mismatch for {spec}");
        }
    }
}

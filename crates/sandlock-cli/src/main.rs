use clap::{Parser, Subcommand};
use sandlock_core::Sandbox;
use sandlock_core::sandbox::{BranchAction, ByteSize, FsIsolation, SandboxBuilder};
use sandlock_core::profile;
use anyhow::{Result, anyhow};
use std::path::PathBuf;
use std::time::SystemTime;

mod network_registry;

#[derive(Parser)]
#[command(name = "sandlock", about = "Lightweight process sandbox", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command in a sandbox
    Run(Box<RunArgs>),
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
}

/// Arguments for the `run` subcommand.
///
/// `sandlock run` is a drop-in for `docker run`: the first positional is the
/// image, the rest is the command, and the common Docker flags below are
/// honoured. To sandbox a *host* command (no image) put it after `--`, e.g.
/// `sandlock run --fs-write /tmp -- ./script.sh`.
///
/// Sandbox-level flags come from `SandboxBuilder` via `#[clap(flatten)]`.
/// CLI-only flags and non-clap-friendly sandbox fields (max_memory, fs_mount,
/// env, gpu, cpu-cores) remain here.
#[derive(clap::Args)]
struct RunArgs {
    // ── Sandbox flags (flattened from SandboxBuilder) ───────────────────────
    #[clap(flatten)]
    sandbox_builder: SandboxBuilder,

    // ── Sandbox-builder fields that need special parsing (not in SandboxBuilder's clap derive) ──
    /// Memory limit, e.g. 512M, 1G (Docker: -m/--memory)
    #[arg(short = 'm', long = "memory", visible_alias = "max-memory", value_name = "SIZE")]
    max_memory: Option<String>,

    #[arg(long = "max-disk")]
    max_disk: Option<String>,

    #[arg(long = "fs-isolation", value_name = "MODE")]
    fs_isolation: Option<String>,

    #[arg(long)]
    time_start: Option<String>,

    /// Mount a host path inside the sandbox (e.g. --fs-mount /work:/host/path)
    #[arg(long = "fs-mount", value_name = "VIRTUAL:HOST")]
    fs_mount: Vec<String>,

    /// Set an environment variable (Docker: -e/--env)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    env_vars: Vec<String>,

    /// CPU cores to pin the sandbox to (e.g. --cpu-cores 0,2,3)
    #[arg(long = "cpu-cores", value_delimiter = ',')]
    cpu_cores: Vec<u32>,

    /// GPU device indices visible to the sandbox (e.g. --gpu 0,2)
    #[arg(long = "gpu", value_delimiter = ',')]
    gpu_devices: Vec<u32>,

    // ── Docker-compatible flags ───────────────────────────────────────────────
    /// Bind mount a volume: HOST:CONTAINER[:ro|:rw] (Docker: -v/--volume)
    #[arg(short = 'v', long = "volume", value_name = "HOST:CONTAINER")]
    volume: Vec<String>,

    /// Working directory inside the container (Docker: -w/--workdir)
    #[arg(short = 'w', long = "workdir", value_name = "DIR")]
    docker_workdir: Option<String>,

    /// Publish/allow a port: [HOST:]CONTAINER (Docker: -p/--publish)
    #[arg(short = 'p', long = "publish", value_name = "PORT")]
    publish: Vec<String>,

    /// Username or UID to run as (Docker: -u/--user)
    #[arg(short = 'u', long = "user", value_name = "UID")]
    user: Option<String>,

    /// Read environment variables from a file (Docker: --env-file)
    #[arg(long = "env-file", value_name = "PATH")]
    env_file: Vec<PathBuf>,

    /// Container hostname; also used as the sandbox name (Docker: --hostname)
    #[arg(long = "hostname", value_name = "NAME")]
    hostname: Option<String>,

    /// Override the image ENTRYPOINT (Docker: --entrypoint)
    #[arg(long = "entrypoint", value_name = "CMD")]
    entrypoint: Option<String>,

    /// Number of CPUs (Docker: --cpus)
    #[arg(long = "cpus", value_name = "N")]
    cpus: Option<f64>,

    /// Network mode: `none` (default deny) or `host` (allow all egress) (Docker: --network)
    #[arg(long = "network", visible_alias = "net", value_name = "MODE")]
    network: Option<String>,

    /// Allocate a pseudo-TTY; implies --interactive (Docker: -t/--tty)
    #[arg(short = 't', long = "tty")]
    tty: bool,

    /// Accepted for Docker compatibility; sandboxes are always ephemeral (Docker: --rm)
    #[arg(long = "rm")]
    rm: bool,

    /// Accepted for Docker compatibility but ignored: --detach/-d, --privileged,
    /// --cap-add, --cap-drop, --pull are not supported by the sandbox model.
    #[arg(short = 'd', long = "detach")]
    detach: bool,
    #[arg(long = "privileged")]
    privileged: bool,
    #[arg(long = "cap-add", value_name = "CAP")]
    cap_add: Vec<String>,
    #[arg(long = "cap-drop", value_name = "CAP")]
    cap_drop: Vec<String>,
    #[arg(long = "pull", value_name = "POLICY")]
    pull: Option<String>,

    // ── CLI-only flags ───────────────────────────────────────────────────────
    #[arg(long = "timeout")]
    timeout: Option<u64>,

    #[arg(long = "profile", conflicts_with = "profile_file")]
    profile: Option<String>,

    /// Load a profile directly from a file path (TOML format)
    #[arg(long = "profile-file", value_name = "PATH", conflicts_with = "profile")]
    profile_file: Option<PathBuf>,

    #[arg(long = "status-fd", value_name = "FD")]
    status_fd: Option<i32>,

    /// Sandbox name (also exposed as the virtual hostname; auto-generated if omitted)
    #[arg(long)]
    name: Option<String>,

    #[arg(long = "exec-shell", value_name = "CMD")]
    exec_shell: Option<String>,

    #[arg(short = 'i', long)]
    interactive: bool,

    /// Use a local Docker/OCI image as the rootfs. Usually given as the first
    /// positional argument (Docker style); this flag is an explicit alternative.
    #[arg(long)]
    image: Option<String>,

    /// Dry-run: run the command, show filesystem changes, then discard
    #[arg(long)]
    dry_run: bool,

    /// No-supervisor mode: apply Landlock rules + deny-only seccomp filter, then exec directly
    #[arg(long)]
    no_supervisor: bool,

    /// `IMAGE [COMMAND] [ARG...]` (Docker style), or — after `--` — a host
    /// command to sandbox with no image.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_name = "IMAGE | COMMAND")]
    image_and_cmd: Vec<String>,
}

/// Resolved run target: which image to use (if any) and the command to run.
struct RunTarget {
    image: Option<String>,
    cmd: Vec<String>,
}

/// Did the invocation use a *leading* `--` options terminator — one that came
/// before any positional argument? That selects native (host-command) mode.
///
/// clap strips this leading `--` and leaves the trailing positionals as exactly
/// the argv tokens that followed it, so we detect it by checking whether the
/// positionals equal the argv tail after the first `--`. A `--` that appears
/// *after* the image (Docker's `IMAGE -- args`) is instead retained by clap
/// inside the positionals, so it does not match here and stays in Docker mode.
fn leading_terminator(positionals: &[String]) -> bool {
    let argv: Vec<String> = std::env::args().collect();
    match argv.iter().position(|a| a == "--") {
        Some(t) => argv[t + 1..] == *positionals,
        None => false,
    }
}

/// Decide whether we are running a Docker image or a host command, and split
/// the trailing positionals accordingly.
///
/// * `--image IMG`  → image mode; positionals are the command.
/// * `... -- CMD`   → native mode; positionals are the host command, no image.
/// * `IMG [CMD...]` → Docker mode; first positional is the image.
fn resolve_run_target(args: &RunArgs) -> RunTarget {
    split_run_target(args.image.as_deref(), &args.image_and_cmd, leading_terminator(&args.image_and_cmd))
}

/// Pure core of [`resolve_run_target`], split out for testing.
///
/// `native_mode` is true when a leading `--` terminator selected host-command
/// mode (see [`leading_terminator`]).
fn split_run_target(image_flag: Option<&str>, positionals: &[String], native_mode: bool) -> RunTarget {
    if let Some(img) = image_flag {
        return RunTarget { image: Some(img.to_string()), cmd: positionals.to_vec() };
    }
    if native_mode {
        return RunTarget { image: None, cmd: positionals.to_vec() };
    }
    match positionals.split_first() {
        Some((first, rest)) => RunTarget { image: Some(first.clone()), cmd: rest.to_vec() },
        None => RunTarget { image: None, cmd: Vec::new() },
    }
}

/// A parsed Docker `-v/--volume` spec.
struct Volume {
    host: PathBuf,
    container: PathBuf,
    read_only: bool,
}

/// Parse a Docker volume spec `HOST:CONTAINER[:ro|:rw]`. Relative host paths are
/// resolved against the current directory (as `docker` does for bind mounts).
fn parse_volume(spec: &str) -> Result<Volume> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (host, container, mode) = match parts.as_slice() {
        [h, c] => (*h, *c, "rw"),
        [h, c, m] => (*h, *c, *m),
        _ => return Err(anyhow!(
            "-v/--volume requires HOST:CONTAINER[:ro|:rw], got: {}", spec
        )),
    };
    let read_only = match mode {
        "ro" => true,
        "rw" => false,
        other => return Err(anyhow!("volume mode must be ro or rw, got: {}", other)),
    };
    let host = if host.starts_with('/') {
        PathBuf::from(host)
    } else {
        std::env::current_dir()?.join(host)
    };
    Ok(Volume { host, container: PathBuf::from(container), read_only })
}

/// Parse a Docker `-p/--publish` spec `[IP:][HOST:]CONTAINER[/proto]`, returning
/// the container port (the port the process binds inside the sandbox).
fn parse_publish(spec: &str) -> Result<u16> {
    let without_proto = spec.split('/').next().unwrap_or(spec);
    let container_port = without_proto.rsplit(':').next().unwrap_or(without_proto);
    container_port
        .parse::<u16>()
        .map_err(|_| anyhow!("invalid --publish port in {:?}", spec))
}

/// Parse a Docker `-u/--user` value (`UID` or `UID:GID`, or a `name`), returning
/// the numeric UID if it is numeric. Names cannot be resolved without the
/// image's /etc/passwd, so they yield `None`.
fn parse_user(user: &str) -> Option<u32> {
    user.split(':').next().unwrap_or(user).parse::<u32>().ok()
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
        Command::Run(args) => run_command(*args).await?,

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
                }
                Err(e) => {
                    println!("  Landlock: unavailable ({})", e);
                    println!("  Status:   UNSUPPORTED");
                }
            }
            println!("  Platform: {}", std::env::consts::ARCH);
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
async fn run_command(args: RunArgs) -> Result<()> {
    let pb = &args.sandbox_builder;

    // Warn on Docker flags we accept but cannot honour.
    if args.detach {
        return Err(anyhow!("--detach/-d is not supported: sandlock runs in the foreground"));
    }
    for (set, flag) in [
        (args.privileged, "--privileged"),
        (!args.cap_add.is_empty(), "--cap-add"),
        (!args.cap_drop.is_empty(), "--cap-drop"),
        (args.pull.is_some(), "--pull"),
    ] {
        if set {
            eprintln!("sandlock: warning: {} is ignored (no Docker compatibility for it)", flag);
        }
    }

    // Resolve Docker-style `IMAGE [CMD...]` vs native `-- CMD` up front.
    let target = resolve_run_target(&args);

    if args.no_supervisor {
        if target.image.is_some() {
            return Err(anyhow!("--no-supervisor is incompatible with running an image"));
        }
        validate_no_supervisor(&args)?;

        // Load profile once (if any) and split into policy base + program spec.
        let (ns_profile_base, ns_profile_spec) = if let Some(ref name) = args.profile {
            let (base, spec) = sandlock_core::profile::load_profile(name)?;
            (Some(base), Some(spec))
        } else if let Some(ref path) = args.profile_file {
            let content = std::fs::read_to_string(path)
                .map_err(|e| anyhow!("failed to read profile file {}: {}", path.display(), e))?;
            let (base, spec) = sandlock_core::profile::parse_profile(&content)?;
            (Some(base), Some(spec))
        } else {
            (None, None)
        };

        // Build a minimal policy with only fs rules
        let mut builder = if let Some(ref base) = ns_profile_base {
            validate_no_supervisor_profile(base, &profile_source(&args))?;
            let mut b = Sandbox::builder();
            for p in &base.fs_readable { b = b.fs_read(p); }
            for p in &base.fs_writable { b = b.fs_write(p); }
            if !base.extra_allow_syscalls.is_empty() {
                b = b.extra_allow_syscalls(base.extra_allow_syscalls.clone());
            }
            if !base.extra_deny_syscalls.is_empty() {
                b = b.extra_deny_syscalls(base.extra_deny_syscalls.clone());
            }
            b = b.clean_env(base.clean_env);
            for (k, v) in &base.env { b = b.env_var(k, v); }
            b
        } else {
            Sandbox::builder()
        };

        // Derive the effective command: profile's [program] section supplies the
        // default; a trailing positional command on the CLI overrides it.
        let effective_cmd: Vec<String> = if !target.cmd.is_empty() || args.exec_shell.is_some() {
            target.cmd.clone()
        } else if let Some(spec) = ns_profile_spec {
            if let Some(exec) = spec.exec {
                let exec_str = exec.into_os_string().into_string()
                    .map_err(|_| anyhow!("non-UTF-8 exec path in profile"))?;
                let mut v = vec![exec_str];
                v.extend(spec.args);
                v
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Apply CLI fs/syscall/env flags on top of the profile base.
        for p in &pb.fs_readable { builder = builder.fs_read(p); }
        for p in &pb.fs_writable { builder = builder.fs_write(p); }
        for p in &pb.fs_denied { builder = builder.fs_deny(p); }
        if !pb.extra_allow_syscalls.is_empty() { builder = builder.extra_allow_syscalls(pb.extra_allow_syscalls.clone()); }
        if !pb.extra_deny_syscalls.is_empty() { builder = builder.extra_deny_syscalls(pb.extra_deny_syscalls.clone()); }
        if pb.clean_env { builder = builder.clean_env(true); }
        for path in &args.env_file {
            let content = std::fs::read_to_string(path)
                .map_err(|e| anyhow!("failed to read --env-file {}: {}", path.display(), e))?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                if let Some((k, v)) = line.split_once('=') {
                    builder = builder.env_var(k.trim(), v);
                }
            }
        }
        for spec in &args.env_vars {
            if let Some((k, v)) = spec.split_once('=') {
                builder = builder.env_var(k, v);
            } else if let Ok(v) = std::env::var(spec) {
                builder = builder.env_var(spec, v);
            } else {
                eprintln!("sandlock: warning: -e {}: not set in host environment, not forwarded", spec);
            }
        }

        let policy = builder.build()?;

        if args.exec_shell.is_none() && effective_cmd.is_empty() {
            return Err(anyhow!("no command specified (no trailing command and no [program].exec in profile)"));
        }

        let cmd_strs: Vec<&str> = if let Some(ref shell_cmd) = args.exec_shell {
            vec!["/bin/sh", "-c", shell_cmd.as_str()]
        } else {
            effective_cmd.iter().map(|s| s.as_str()).collect()
        };

        return no_supervisor_exec(&policy, &cmd_strs);
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

    // Capture the profile's program identity before `base` is consumed below.
    // Image defaults sit *below* the profile in precedence, so we only let the
    // image fill cwd/uid/env that the profile did not already set.
    let profile_cwd: Option<String> = base_from_profile
        .as_ref()
        .and_then(|b| b.cwd.as_ref())
        .map(|p| p.to_string_lossy().into_owned());
    let profile_uid: Option<u32> = base_from_profile.as_ref().and_then(|b| b.uid);
    let profile_env_keys: std::collections::HashSet<String> = base_from_profile
        .as_ref()
        .map(|b| b.env.iter().map(|(k, _)| k.clone()).collect())
        .unwrap_or_default();

    // Start from profile or default
    let mut builder = if let Some(base) = base_from_profile {
        // Rebuild builder from loaded profile as base
        let mut b = Sandbox::builder();
        for p in &base.fs_readable { b = b.fs_read(p); }
        for p in &base.fs_writable { b = b.fs_write(p); }
        for p in &base.fs_denied { b = b.fs_deny(p); }
        for rule in &base.net_allow {
            let host_part = rule.host.as_deref().unwrap_or("*");
            let spec = match rule.protocol {
                sandlock_core::sandbox::Protocol::Tcp => {
                    let ports = format_ports(&rule.ports, rule.all_ports);
                    format!("tcp://{}:{}", host_part, ports)
                }
                sandlock_core::sandbox::Protocol::Udp => {
                    let ports = format_ports(&rule.ports, rule.all_ports);
                    format!("udp://{}:{}", host_part, ports)
                }
                sandlock_core::sandbox::Protocol::Icmp => {
                    format!("icmp://{}", host_part)
                }
            };
            b = b.net_allow(spec);
        }
        for p in &base.net_bind { b = b.net_bind_port(*p); }
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
        // Filesystem extras
        if let Some(ref path) = base.chroot { b = b.chroot(path); }
        if let Some(ref path) = base.fs_storage { b = b.fs_storage(path); }
        if base.fs_isolation != sandlock_core::sandbox::FsIsolation::None {
            b = b.fs_isolation(base.fs_isolation.clone());
        }
        for (virt, host) in &base.fs_mount { b = b.fs_mount(virt, host); }
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
        if let Some(uid) = base.uid { b = b.uid(uid); }
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
    for p in &pb.net_bind { builder = builder.net_bind_port(*p); }
    if let Some(seed) = pb.random_seed { builder = builder.random_seed(seed); }
    if pb.clean_env { builder = builder.clean_env(true); }
    if let Some(n) = pb.num_cpus { builder = builder.num_cpus(n); }
    if let Some(cpu) = pb.max_cpu { builder = builder.max_cpu(cpu); }
    if let Some(n) = pb.max_open_files { builder = builder.max_open_files(n); }
    for p in &pb.fs_denied { builder = builder.fs_deny(p); }
    if let Some(ref path) = pb.chroot { builder = builder.chroot(path); }
    if let Some(id) = pb.uid { builder = builder.uid(id); }
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
    if let Some(ref mode) = args.fs_isolation {
        use sandlock_core::sandbox::FsIsolation;
        let iso = match mode.as_str() {
            "none" => FsIsolation::None,
            "overlayfs" => FsIsolation::OverlayFs,
            "branchfs" => FsIsolation::BranchFs,
            other => return Err(anyhow!("unknown --fs-isolation mode: {}", other)),
        };
        builder = builder.fs_isolation(iso);
    }
    if let Some(ref s) = args.max_disk { builder = builder.max_disk(ByteSize::parse(s)?); }
    for spec in &args.fs_mount {
        let (virt, host) = spec.split_once(':')
            .ok_or_else(|| anyhow!("--fs-mount requires VIRTUAL:HOST, got: {}", spec))?;
        builder = builder.fs_mount(virt, host);
    }
    if !args.cpu_cores.is_empty() { builder = builder.cpu_cores(args.cpu_cores.clone()); }
    if !args.gpu_devices.is_empty() { builder = builder.gpu_devices(args.gpu_devices.clone()); }
    // ── Image: extract rootfs, then layer in the image's baked-in config ──────
    // (env, working dir, user) the way `docker run` does. The image's defaults
    // sit at the lowest precedence; the CLI flags below override them.
    let image_config = if let Some(ref img) = target.image {
        let rootfs = sandlock_core::image::extract(img, None)?;
        builder = builder.chroot(rootfs).fs_read("/");
        Some(sandlock_core::image::inspect_config(img)?)
    } else {
        None
    };
    // Precedence (low → high): image defaults < profile < CLI flags. The profile
    // values were already layered into the builder above, so the image only
    // supplies cwd/uid/env that the profile left unset; CLI flags override both.
    let mut effective_cwd: Option<String> = profile_cwd;
    let mut effective_uid: Option<u32> = profile_uid;
    if let Some(ref cfg) = image_config {
        for kv in &cfg.env {
            if let Some((k, v)) = kv.split_once('=') {
                if !profile_env_keys.contains(k) { builder = builder.env_var(k, v); }
            }
        }
        if effective_cwd.is_none() { effective_cwd = cfg.workdir.clone(); }
        if effective_uid.is_none() { effective_uid = cfg.user.as_deref().and_then(parse_user); }
    }

    // ── Environment: --env-file, then -e/--env (later wins, like Docker) ──────
    for path in &args.env_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read --env-file {}: {}", path.display(), e))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Some((k, v)) = line.split_once('=') {
                builder = builder.env_var(k.trim(), v);
            }
        }
    }
    for spec in &args.env_vars {
        if let Some((k, v)) = spec.split_once('=') {
            builder = builder.env_var(k, v);
        } else if let Ok(v) = std::env::var(spec) {
            // Docker: `-e VAR` (no `=value`) forwards the host's value.
            builder = builder.env_var(spec, v);
        } else {
            // Docker leaves an unset `-e VAR` out of the child's environment;
            // warn so it is not a silent no-op.
            eprintln!("sandlock: warning: -e {}: not set in host environment, not forwarded", spec);
        }
    }

    // ── Docker -v/--volume → per-sandbox mount + filesystem access ────────────
    for spec in &args.volume {
        let vol = parse_volume(spec)?;
        builder = builder.fs_mount(&vol.container, &vol.host);
        builder = if vol.read_only {
            builder.fs_read(&vol.container)
        } else {
            builder.fs_write(&vol.container)
        };
    }

    // ── Docker -w/--workdir and -u/--user (override image defaults) ───────────
    if let Some(ref wd) = args.docker_workdir { effective_cwd = Some(wd.clone()); }
    if let Some(ref u) = args.user {
        effective_uid = Some(parse_user(u)
            .ok_or_else(|| anyhow!("--user must be a numeric UID or UID:GID, got: {}", u))?);
    }
    if let Some(ref wd) = effective_cwd { builder = builder.cwd(wd); }
    if let Some(uid) = effective_uid { builder = builder.uid(uid); }

    // ── Docker -p/--publish → allow binding + port virtualization ─────────────
    if !args.publish.is_empty() {
        for spec in &args.publish {
            builder = builder.net_bind_port(parse_publish(spec)?);
        }
        builder = builder.port_remap(true);
    }

    // ── Docker --network (none = default deny, host = allow all egress) ───────
    if let Some(ref mode) = args.network {
        match mode.as_str() {
            "none" => {}
            "host" => { builder = builder.net_allow(":*").net_allow("udp://*:*"); }
            other => return Err(anyhow!("unsupported --network mode: {} (use none or host)", other)),
        }
    }

    // ── Docker --cpus → CPU count ─────────────────────────────────────────────
    if let Some(n) = args.cpus {
        if !n.is_finite() || n <= 0.0 {
            return Err(anyhow!("--cpus must be a positive, finite number, got: {}", n));
        }
        // max_cpu takes a u8; reject values whose ceiling would not fit.
        if n > 255.0 {
            return Err(anyhow!("--cpus must be at most 255, got: {}", n));
        }
        builder = builder.max_cpu(n.ceil() as u8);
    }

    // Sandbox name: --name, else --hostname, else auto-generated.
    let sandbox_name = args.name.clone()
        .or_else(|| args.hostname.clone())
        .unwrap_or_else(network_registry::next_name);

    // ── Resolve the command ───────────────────────────────────────────────────
    // Precedence: --exec-shell > CLI command > image ENTRYPOINT/CMD > profile.
    // --entrypoint overrides the image ENTRYPOINT for both forms.
    let cli_cmd: Option<Vec<String>> = if !target.cmd.is_empty() {
        Some(match &args.entrypoint {
            Some(ep) => {
                let mut v = vec![ep.clone()];
                v.extend(target.cmd.clone());
                v
            }
            None => target.cmd.clone(),
        })
    } else {
        None
    };
    let image_cmd: Option<Vec<String>> = match (&image_config, cli_cmd.is_some()) {
        (Some(cfg), false) => Some(match &args.entrypoint {
            // Override ENTRYPOINT but keep the image's default CMD as arguments.
            Some(ep) => {
                let mut v = vec![ep.clone()];
                if let Some(ref c) = cfg.cmd { v.extend(c.clone()); }
                v
            }
            None => cfg.default_command(),
        }),
        _ => None,
    };

    // Derive the effective command: profile's [program] section supplies a
    // default; a CLI command, an image, or --exec-shell overrides it.
    let profile_cmd: Option<Vec<String>> = if cli_cmd.is_none() && image_cmd.is_none() && args.exec_shell.is_none() {
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

    if args.exec_shell.is_none() && cli_cmd.is_none() && image_cmd.is_none() && profile_cmd.is_none() {
        return Err(anyhow!("no command specified (no image, no trailing command, and no [program].exec in profile)"));
    }

    let policy = builder.build()?;
    let cmd_strs: Vec<&str> = if let Some(ref shell_cmd) = args.exec_shell {
        vec!["/bin/sh", "-c", shell_cmd.as_str()]
    } else if let Some(ref cc) = cli_cmd {
        cc.iter().map(|s| s.as_str()).collect()
    } else if let Some(ref ic) = image_cmd {
        ic.iter().map(|s| s.as_str()).collect()
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
            tokio::time::timeout(
                std::time::Duration::from_secs(secs),
                policy.dry_run_interactive(&cmd_strs)
            ).await.unwrap_or_else(|_| {
                eprintln!("sandlock: timeout after {}s", secs);
                std::process::exit(124);
            })?
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
            .filter_map(|r| r.host.clone())
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
                policy.wait()
            ).await {
                Ok(r) => r?,
                Err(_) => {
                    let _ = network_registry::unregister(&sandbox_name);
                    eprintln!("sandlock: timeout after {}s", secs);
                    std::process::exit(124);
                }
            }
        } else {
            policy.wait().await?
        };
        let _ = network_registry::unregister(&sandbox_name);
        result
    } else if let Some(secs) = args.timeout {
        tokio::time::timeout(
            std::time::Duration::from_secs(secs),
            policy.run_interactive(&cmd_strs)
        ).await.unwrap_or_else(|_| {
            eprintln!("sandlock: timeout after {}s", secs);
            std::process::exit(124);
        })?
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

    std::process::exit(result.code().unwrap_or(1));
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
    if !pb.net_bind.is_empty() { bad.push("--net-bind"); }
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
    if pb.uid.is_some() { bad.push("--uid"); }
    if pb.workdir.is_some() { bad.push("--fs-workdir"); }
    if pb.cwd.is_some() { bad.push("--cwd"); }
    if args.fs_isolation.is_some() { bad.push("--fs-isolation"); }
    if pb.fs_storage.is_some() { bad.push("--fs-storage"); }
    if args.max_disk.is_some() { bad.push("--max-disk"); }
    if pb.port_remap { bad.push("--port-remap"); }
    if !args.cpu_cores.is_empty() { bad.push("--cpu-cores"); }
    if !args.gpu_devices.is_empty() { bad.push("--gpu"); }
    if args.dry_run { bad.push("--dry-run"); }
    if args.status_fd.is_some() { bad.push("--status-fd"); }
    if !pb.fs_denied.is_empty() { bad.push("--fs-deny"); }
    if !args.fs_mount.is_empty() { bad.push("--fs-mount"); }
    // Docker-compatible flags that map onto supervisor-only features.
    if !args.volume.is_empty() { bad.push("--volume"); }
    if !args.publish.is_empty() { bad.push("--publish"); }
    if args.docker_workdir.is_some() { bad.push("--workdir"); }
    if args.user.is_some() { bad.push("--user"); }
    if args.hostname.is_some() { bad.push("--hostname"); }
    if args.network.is_some() { bad.push("--network"); }
    if args.cpus.is_some() { bad.push("--cpus"); }

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
    if !profile.net_bind.is_empty() { bad.push("[network].bind"); }
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
    if profile.fs_isolation != FsIsolation::None { bad.push("[filesystem].isolation"); }
    if profile.workdir.is_some() { bad.push("[config].workdir"); }
    if profile.fs_storage.is_some() { bad.push("[config].fs_storage"); }
    if profile.cwd.is_some() { bad.push("[program].cwd"); }
    if profile.uid.is_some() { bad.push("[program].uid"); }
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

/// Execute a command with no-supervisor confinement.
/// Applies Landlock + deny-only seccomp filter, handles env, then execs.
fn no_supervisor_exec(policy: &Sandbox, cmd: &[&str]) -> Result<()> {
    use std::ffi::CString;

    // 1. Apply Landlock confinement (sets NO_NEW_PRIVS + Landlock rules)
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(anyhow!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    sandlock_core::landlock::confine(policy)
        .map_err(|e| anyhow!("Landlock confinement failed: {}", e))?;

    // 2. Install deny-only seccomp filter (blocks dangerous syscalls without supervisor)
    let deny_nrs = sandlock_core::context::no_supervisor_blocklist_syscall_numbers(policy);
    let filter = sandlock_core::seccomp::bpf::assemble_filter(&[], &deny_nrs, &[])
        .map_err(|e| anyhow!("seccomp assemble failed: {}", e))?;
    sandlock_core::seccomp::bpf::install_deny_filter(&filter)
        .map_err(|e| anyhow!("seccomp deny filter failed: {}", e))?;

    // 3. Apply environment settings
    if policy.clean_env {
        // Preserve only essential vars, clear the rest
        let keep: Vec<(String, String)> = ["PATH", "HOME", "USER", "TERM", "LANG"]
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
            .collect();
        // Clear all env vars
        for (k, _) in std::env::vars() {
            std::env::remove_var(&k);
        }
        // Restore kept ones
        for (k, v) in &keep {
            std::env::set_var(k, v);
        }
    }
    for (k, v) in &policy.env {
        std::env::set_var(k, v);
    }

    // 4. exec the command
    let c_prog = CString::new(cmd[0])
        .map_err(|_| anyhow!("invalid command name: {}", cmd[0]))?;
    let c_args: Vec<CString> = cmd
        .iter()
        .map(|a| CString::new(*a).map_err(|_| anyhow!("invalid argument: {}", a)))
        .collect::<Result<Vec<_>>>()?;
    let c_arg_ptrs: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        libc::execvp(c_prog.as_ptr(), c_arg_ptrs.as_ptr());
    }

    // If we get here, execvp failed
    Err(anyhow!(
        "execvp({}) failed: {}",
        cmd[0],
        std::io::Error::last_os_error()
    ))
}

/// Parse an ISO 8601 timestamp (e.g. "2000-01-01T00:00:00Z") into a SystemTime.
/// Render a port list back into the `--net-allow` port-suffix form:
/// concrete ports become `80,443`; the all-ports wildcard becomes `*`.
fn format_ports(ports: &[u16], all_ports: bool) -> String {
    if all_ports {
        "*".to_string()
    } else {
        ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
    }
}

fn parse_time_start(s: &str) -> Result<SystemTime> {
    let ts: jiff::Timestamp = s.parse()
        .map_err(|e| anyhow!("invalid --time-start '{}': {}", s, e))?;
    Ok(ts.into())
}

#[cfg(test)]
mod docker_compat_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn docker_mode_first_positional_is_image() {
        // `sandlock run ubuntu bash` → image=ubuntu, cmd=[bash]
        let t = split_run_target(None, &s(&["ubuntu", "bash"]), false);
        assert_eq!(t.image.as_deref(), Some("ubuntu"));
        assert_eq!(t.cmd, s(&["bash"]));
    }

    #[test]
    fn docker_mode_image_only_uses_default_cmd() {
        let t = split_run_target(None, &s(&["python:3.12"]), false);
        assert_eq!(t.image.as_deref(), Some("python:3.12"));
        assert!(t.cmd.is_empty());
    }

    #[test]
    fn terminator_selects_native_host_command() {
        // `sandlock run --fs-write /tmp -- echo hi` → no image, cmd=[echo, hi]
        let t = split_run_target(None, &s(&["echo", "hi"]), true);
        assert_eq!(t.image, None);
        assert_eq!(t.cmd, s(&["echo", "hi"]));
    }

    #[test]
    fn internal_terminator_after_image_stays_docker_mode() {
        // `sandlock run alpine -- echo hi`: clap retains the `--` in the
        // positionals (it follows the image), so leading_terminator() is false
        // and alpine is still treated as the image, not a host command.
        let t = split_run_target(None, &s(&["alpine", "--", "echo", "hi"]), false);
        assert_eq!(t.image.as_deref(), Some("alpine"));
        assert_eq!(t.cmd, s(&["--", "echo", "hi"]));
    }

    #[test]
    fn explicit_image_flag_takes_all_positionals_as_cmd() {
        let t = split_run_target(Some("alpine"), &s(&["sh", "-c", "true"]), true);
        assert_eq!(t.image.as_deref(), Some("alpine"));
        assert_eq!(t.cmd, s(&["sh", "-c", "true"]));
    }

    #[test]
    fn parse_volume_forms() {
        let cwd = std::env::current_dir().unwrap();
        let v = parse_volume("/data:/app").unwrap();
        assert_eq!(v.host, std::path::PathBuf::from("/data"));
        assert_eq!(v.container, std::path::PathBuf::from("/app"));
        assert!(!v.read_only);

        let v = parse_volume("/data:/app:ro").unwrap();
        assert!(v.read_only);

        // relative host path is resolved against cwd
        let v = parse_volume("src:/app").unwrap();
        assert_eq!(v.host, cwd.join("src"));

        assert!(parse_volume("/app").is_err());
        assert!(parse_volume("/h:/c:bogus").is_err());
    }

    #[test]
    fn parse_publish_extracts_container_port() {
        assert_eq!(parse_publish("8080").unwrap(), 8080);
        assert_eq!(parse_publish("8080:80").unwrap(), 80);
        assert_eq!(parse_publish("127.0.0.1:8080:80").unwrap(), 80);
        assert_eq!(parse_publish("80/tcp").unwrap(), 80);
        assert!(parse_publish("notaport").is_err());
    }

    #[test]
    fn parse_user_numeric_only() {
        assert_eq!(parse_user("1000"), Some(1000));
        assert_eq!(parse_user("1000:1000"), Some(1000));
        assert_eq!(parse_user("node"), None);
    }
}

use clap::{Parser, Subcommand};
use sandlock_core::{Policy, Sandbox};
use sandlock_core::policy::ByteSize;
use sandlock_core::profile;
use anyhow::{Result, anyhow};
use std::time::SystemTime;

#[derive(Parser)]
#[command(name = "sandlock", about = "Lightweight process sandbox")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command in a sandbox
    Run {
        #[arg(short = 'r', long = "fs-read", value_name = "PATH")]
        fs_read: Vec<String>,
        #[arg(short = 'w', long = "fs-write", value_name = "PATH")]
        fs_write: Vec<String>,
        #[arg(short = 'm', long = "max-memory")]
        max_memory: Option<String>,
        #[arg(short = 'P', long = "max-processes")]
        max_processes: Option<u32>,
        #[arg(short = 't', long)]
        timeout: Option<u64>,
        #[arg(long = "net-allow-host")]
        net_allow_host: Vec<String>,
        #[arg(long = "net-bind")]
        net_bind: Vec<u16>,
        #[arg(long = "net-connect")]
        net_connect: Vec<u16>,
        #[arg(long)]
        time_start: Option<String>,
        #[arg(long)]
        random_seed: Option<u64>,
        #[arg(long)]
        isolate_ipc: bool,
        #[arg(long)]
        isolate_signals: bool,
        #[arg(long)]
        clean_env: bool,
        #[arg(long)]
        num_cpus: Option<u32>,
        #[arg(short = 'p', long)]
        profile: Option<String>,
        #[arg(long = "status-fd", value_name = "FD")]
        status_fd: Option<i32>,
        #[arg(short = 'c', long = "cpu")]
        max_cpu: Option<u8>,
        #[arg(long)]
        max_open_files: Option<u32>,
        #[arg(long)]
        chroot: Option<String>,
        /// Map to the given UID inside a user namespace (e.g. --uid 0 for fake root)
        #[arg(long)]
        uid: Option<u32>,
        #[arg(long)]
        workdir: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long = "fs-isolation", value_name = "MODE")]
        fs_isolation: Option<String>,
        #[arg(long = "fs-storage", value_name = "PATH")]
        fs_storage: Option<String>,
        #[arg(long = "max-disk")]
        max_disk: Option<String>,
        #[arg(long = "net-allow", value_name = "PROTO")]
        net_allow: Vec<String>,
        #[arg(long = "net-deny", value_name = "PROTO")]
        net_deny: Vec<String>,
        #[arg(long = "http-allow", value_name = "RULE")]
        http_allow: Vec<String>,
        #[arg(long = "http-deny", value_name = "RULE")]
        http_deny: Vec<String>,
        #[arg(long)]
        port_remap: bool,
        #[arg(long)]
        no_randomize_memory: bool,
        #[arg(long)]
        no_huge_pages: bool,
        #[arg(long)]
        deterministic_dirs: bool,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        no_coredump: bool,
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env_vars: Vec<String>,
        #[arg(short = 'e', long = "exec-shell", value_name = "CMD")]
        exec_shell: Option<String>,
        #[arg(short = 'i', long)]
        interactive: bool,
        #[arg(long = "fs-deny", value_name = "PATH")]
        fs_deny: Vec<String>,
        /// CPU cores to pin the sandbox to (e.g. --cpu-cores 0,2,3)
        #[arg(long = "cpu-cores", value_delimiter = ',')]
        cpu_cores: Vec<u32>,
        /// GPU device indices visible to the sandbox (e.g. --gpu 0,2)
        #[arg(long = "gpu", value_delimiter = ',')]
        gpu_devices: Vec<u32>,
        /// Use a local Docker image as chroot rootfs
        #[arg(long)]
        image: Option<String>,
        /// Dry-run: run the command, show filesystem changes, then discard
        #[arg(long)]
        dry_run: bool,
        /// No-supervisor mode: apply Landlock rules + deny-only seccomp filter, then exec directly
        #[arg(long)]
        no_supervisor: bool,
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Check kernel feature support
    Check,
    /// Manage profiles
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run { fs_read, fs_write, max_memory, max_processes, timeout,
            net_allow_host, net_bind, net_connect, time_start, random_seed,
            isolate_ipc, isolate_signals, clean_env, num_cpus, profile: profile_name, status_fd,
            max_cpu, max_open_files, chroot, uid, workdir, cwd,
            fs_isolation, fs_storage, max_disk, net_allow, net_deny,
            http_allow, http_deny,
            port_remap, no_randomize_memory, no_huge_pages, deterministic_dirs, hostname, no_coredump,
            env_vars, exec_shell, interactive: _, fs_deny, cpu_cores, gpu_devices, image, dry_run, no_supervisor, cmd } =>
        {
            if no_supervisor {
                validate_no_supervisor(
                    &max_memory, &max_processes, &max_cpu, &max_open_files,
                    &timeout, &net_allow_host, &net_bind, &net_connect,
                    &net_allow, &net_deny, &http_allow, &http_deny,
                    &num_cpus, &random_seed, &time_start, no_randomize_memory,
                    no_huge_pages, deterministic_dirs, &hostname, &chroot,
                    &image, &uid, &workdir, &cwd, &fs_isolation, &fs_storage,
                    &max_disk, port_remap, &cpu_cores, &gpu_devices, dry_run,
                    &status_fd, &fs_deny,
                )?;

                // Build a minimal policy with only fs rules
                let mut builder = if let Some(ref name) = profile_name {
                    let base = sandlock_core::profile::load_profile(name)?;
                    if !base.fs_denied.is_empty() {
                        return Err(anyhow!(
                            "--no-supervisor is incompatible with: --fs-deny (from profile {})",
                            name
                        ));
                    }
                    let mut b = Policy::builder();
                    for p in &base.fs_readable { b = b.fs_read(p); }
                    for p in &base.fs_writable { b = b.fs_write(p); }
                    b
                } else {
                    Policy::builder()
                };

                for p in &fs_read { builder = builder.fs_read(p); }
                for p in &fs_write { builder = builder.fs_write(p); }
                for p in &fs_deny { builder = builder.fs_deny(p); }
                if clean_env { builder = builder.clean_env(true); }
                for spec in &env_vars {
                    if let Some((k, v)) = spec.split_once('=') {
                        builder = builder.env_var(k, v);
                    } else {
                        return Err(anyhow!("--env requires KEY=VALUE, got: {}", spec));
                    }
                }
                if isolate_ipc { builder = builder.isolate_ipc(true); }
                if isolate_signals { builder = builder.isolate_signals(true); }

                let policy = builder.build()?;

                if exec_shell.is_none() && cmd.is_empty() {
                    return Err(anyhow!("no command specified"));
                }

                let cmd_strs: Vec<&str> = if let Some(ref shell_cmd) = exec_shell {
                    vec!["/bin/sh", "-c", shell_cmd.as_str()]
                } else {
                    cmd.iter().map(|s| s.as_str()).collect()
                };

                return no_supervisor_exec(&policy, &cmd_strs);
            }

            // Start from profile or default
            let mut builder = if let Some(ref name) = profile_name {
                let base = profile::load_profile(name)?;
                // Rebuild builder from loaded profile as base
                let mut b = Policy::builder();
                for p in &base.fs_readable { b = b.fs_read(p); }
                for p in &base.fs_writable { b = b.fs_write(p); }
                for p in &base.fs_denied { b = b.fs_deny(p); }
                for h in &base.net_allow_hosts { b = b.net_allow_host(h); }
                for p in &base.net_bind { b = b.net_bind_port(*p); }
                for p in &base.net_connect { b = b.net_connect_port(*p); }
                for rule in &base.http_allow {
                    let s = format!("{} {}{}", rule.method, rule.host, rule.path);
                    b = b.http_allow(&s);
                }
                for rule in &base.http_deny {
                    let s = format!("{} {}{}", rule.method, rule.host, rule.path);
                    b = b.http_deny(&s);
                }
                if let Some(mem) = base.max_memory { b = b.max_memory(mem); }
                b = b.max_processes(base.max_processes);
                if let Some(cpu) = base.max_cpu { b = b.max_cpu(cpu); }
                if let Some(seed) = base.random_seed { b = b.random_seed(seed); }
                if let Some(n) = base.num_cpus { b = b.num_cpus(n); }
                b = b.no_raw_sockets(base.no_raw_sockets);
                b = b.no_udp(base.no_udp);
                b = b.isolate_ipc(base.isolate_ipc);
                b = b.isolate_signals(base.isolate_signals);
                b = b.clean_env(base.clean_env);
                b
            } else {
                Policy::builder()
            };

            // CLI overrides
            for p in &fs_read { builder = builder.fs_read(p); }
            for p in &fs_write { builder = builder.fs_write(p); }
            if let Some(ref m) = max_memory { builder = builder.max_memory(ByteSize::parse(m)?); }
            if let Some(n) = max_processes { builder = builder.max_processes(n); }
            for h in &net_allow_host { builder = builder.net_allow_host(h); }
            for p in &net_bind { builder = builder.net_bind_port(*p); }
            for p in &net_connect { builder = builder.net_connect_port(*p); }
            if let Some(seed) = random_seed { builder = builder.random_seed(seed); }
            if isolate_ipc { builder = builder.isolate_ipc(true); }
            if isolate_signals { builder = builder.isolate_signals(true); }
            if clean_env { builder = builder.clean_env(true); }
            if let Some(n) = num_cpus { builder = builder.num_cpus(n); }
            if let Some(ref ts) = time_start {
                let t = parse_time_start(ts)?;
                builder = builder.time_start(t);
            }
            if let Some(cpu) = max_cpu { builder = builder.max_cpu(cpu); }
            if let Some(n) = max_open_files { builder = builder.max_open_files(n); }
            for p in &fs_deny { builder = builder.fs_deny(p); }
            if let Some(ref path) = chroot { builder = builder.chroot(path); }
            if let Some(id) = uid { builder = builder.uid(id); }
            if let Some(ref path) = workdir { builder = builder.workdir(path); }
            if let Some(ref path) = cwd { builder = builder.cwd(path); }
            if let Some(ref mode) = fs_isolation {
                use sandlock_core::policy::FsIsolation;
                let iso = match mode.as_str() {
                    "none" => FsIsolation::None,
                    "overlayfs" => FsIsolation::OverlayFs,
                    "branchfs" => FsIsolation::BranchFs,
                    other => return Err(anyhow!("unknown --fs-isolation mode: {}", other)),
                };
                builder = builder.fs_isolation(iso);
            }
            if let Some(ref path) = fs_storage { builder = builder.fs_storage(path); }
            if let Some(ref s) = max_disk { builder = builder.max_disk(ByteSize::parse(s)?); }
            for proto in &net_allow {
                match proto.as_str() {
                    "icmp" => { builder = builder.no_raw_sockets(false); }
                    other => return Err(anyhow!("unknown --net-allow protocol: {}", other)),
                }
            }
            for proto in &net_deny {
                match proto.as_str() {
                    "raw" => { builder = builder.no_raw_sockets(true); }
                    "udp" => { builder = builder.no_udp(true); }
                    other => return Err(anyhow!("unknown --net-deny protocol: {}", other)),
                }
            }
            for rule in &http_allow { builder = builder.http_allow(rule); }
            for rule in &http_deny { builder = builder.http_deny(rule); }
            if port_remap { builder = builder.port_remap(true); }
            if !cpu_cores.is_empty() { builder = builder.cpu_cores(cpu_cores); }
            if !gpu_devices.is_empty() { builder = builder.gpu_devices(gpu_devices); }
            if no_randomize_memory { builder = builder.no_randomize_memory(true); }
            if no_huge_pages { builder = builder.no_huge_pages(true); }
            if deterministic_dirs { builder = builder.deterministic_dirs(true); }
            if let Some(h) = hostname { builder = builder.hostname(h); }
            if no_coredump { builder = builder.no_coredump(true); }
            for spec in &env_vars {
                if let Some((k, v)) = spec.split_once('=') {
                    builder = builder.env_var(k, v);
                } else {
                    return Err(anyhow!("--env requires KEY=VALUE, got: {}", spec));
                }
            }

            // Handle --image: extract rootfs, set chroot, get default cmd
            let image_cmd: Option<Vec<String>>;
            if let Some(ref img) = image {
                let rootfs = sandlock_core::image::extract(img, None)?;
                builder = builder.chroot(rootfs);
                // Add standard paths inside the chroot
                builder = builder.fs_read("/usr").fs_read("/lib").fs_read("/lib64")
                    .fs_read("/bin").fs_read("/sbin").fs_read("/etc")
                    .fs_read("/proc").fs_read("/dev");
                if cmd.is_empty() {
                    image_cmd = Some(sandlock_core::image::inspect_cmd(img)?);
                } else {
                    image_cmd = None;
                }
            } else {
                image_cmd = None;
            }

            if exec_shell.is_none() && cmd.is_empty() && image_cmd.is_none() {
                return Err(anyhow!("no command specified"));
            }

            let policy = builder.build()?;
            let cmd_strs: Vec<&str> = if let Some(ref shell_cmd) = exec_shell {
                vec!["/bin/sh", "-c", shell_cmd.as_str()]
            } else if let Some(ref ic) = image_cmd {
                ic.iter().map(|s| s.as_str()).collect()
            } else {
                cmd.iter().map(|s| s.as_str()).collect()
            };

            let result = if dry_run {
                if policy.workdir.is_none() {
                    return Err(anyhow!("--dry-run requires --workdir"));
                }
                let dr = if let Some(secs) = timeout {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(secs),
                        Sandbox::dry_run_interactive(&policy, &cmd_strs)
                    ).await.unwrap_or_else(|_| {
                        eprintln!("sandlock: timeout after {}s", secs);
                        std::process::exit(124);
                    })?
                } else {
                    Sandbox::dry_run_interactive(&policy, &cmd_strs).await?
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
            } else if let Some(secs) = timeout {
                tokio::time::timeout(
                    std::time::Duration::from_secs(secs),
                    Sandbox::run_interactive(&policy, &cmd_strs)
                ).await.unwrap_or_else(|_| {
                    eprintln!("sandlock: timeout after {}s", secs);
                    std::process::exit(124);
                })?
            } else {
                Sandbox::run_interactive(&policy, &cmd_strs).await?
            };

            if let Some(fd) = status_fd {
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

/// Validate that no flags incompatible with --no-supervisor are set.
#[allow(clippy::too_many_arguments)]
fn validate_no_supervisor(
    max_memory: &Option<String>,
    max_processes: &Option<u32>,
    max_cpu: &Option<u8>,
    max_open_files: &Option<u32>,
    timeout: &Option<u64>,
    net_allow_host: &[String],
    net_bind: &[u16],
    net_connect: &[u16],
    net_allow: &[String],
    net_deny: &[String],
    http_allow: &[String],
    http_deny: &[String],
    num_cpus: &Option<u32>,
    random_seed: &Option<u64>,
    time_start: &Option<String>,
    no_randomize_memory: bool,
    no_huge_pages: bool,
    deterministic_dirs: bool,
    hostname: &Option<String>,
    chroot: &Option<String>,
    image: &Option<String>,
    uid: &Option<u32>,
    workdir: &Option<String>,
    cwd: &Option<String>,
    fs_isolation: &Option<String>,
    fs_storage: &Option<String>,
    max_disk: &Option<String>,
    port_remap: bool,
    cpu_cores: &[u32],
    gpu_devices: &[u32],
    dry_run: bool,
    status_fd: &Option<i32>,
    fs_deny: &[String],
) -> Result<()> {
    let mut bad = Vec::new();

    if max_memory.is_some() { bad.push("--max-memory"); }
    if max_processes.is_some() { bad.push("--max-processes"); }
    if max_cpu.is_some() { bad.push("--max-cpu"); }
    if max_open_files.is_some() { bad.push("--max-open-files"); }
    if timeout.is_some() { bad.push("--timeout"); }
    if !net_allow_host.is_empty() { bad.push("--net-allow-host"); }
    if !net_bind.is_empty() { bad.push("--net-bind"); }
    if !net_connect.is_empty() { bad.push("--net-connect"); }
    if !net_allow.is_empty() { bad.push("--net-allow"); }
    if !net_deny.is_empty() { bad.push("--net-deny"); }
    if !http_allow.is_empty() { bad.push("--http-allow"); }
    if !http_deny.is_empty() { bad.push("--http-deny"); }
    if num_cpus.is_some() { bad.push("--num-cpus"); }
    if random_seed.is_some() { bad.push("--random-seed"); }
    if time_start.is_some() { bad.push("--time-start"); }
    if no_randomize_memory { bad.push("--no-randomize-memory"); }
    if no_huge_pages { bad.push("--no-huge-pages"); }
    if deterministic_dirs { bad.push("--deterministic-dirs"); }
    if hostname.is_some() { bad.push("--hostname"); }
    if chroot.is_some() { bad.push("--chroot"); }
    if image.is_some() { bad.push("--image"); }
    if uid.is_some() { bad.push("--uid"); }
    if workdir.is_some() { bad.push("--workdir"); }
    if cwd.is_some() { bad.push("--cwd"); }
    if fs_isolation.is_some() { bad.push("--fs-isolation"); }
    if fs_storage.is_some() { bad.push("--fs-storage"); }
    if max_disk.is_some() { bad.push("--max-disk"); }
    if port_remap { bad.push("--port-remap"); }
    if !cpu_cores.is_empty() { bad.push("--cpu-cores"); }
    if !gpu_devices.is_empty() { bad.push("--gpu"); }
    if dry_run { bad.push("--dry-run"); }
    if status_fd.is_some() { bad.push("--status-fd"); }
    if !fs_deny.is_empty() { bad.push("--fs-deny"); }

    if !bad.is_empty() {
        return Err(anyhow!(
            "--no-supervisor is incompatible with: {}",
            bad.join(", ")
        ));
    }

    Ok(())
}

/// Execute a command with no-supervisor confinement.
/// Applies Landlock + deny-only seccomp filter, handles env, then execs.
fn no_supervisor_exec(policy: &Policy, cmd: &[&str]) -> Result<()> {
    use std::ffi::CString;

    // 1. Apply Landlock confinement (sets NO_NEW_PRIVS + Landlock rules)
    sandlock_core::confine_current_process(policy)
        .map_err(|e| anyhow!("Landlock confinement failed: {}", e))?;

    // 2. Install deny-only seccomp filter (blocks dangerous syscalls without supervisor)
    let deny_nrs = sandlock_core::context::no_supervisor_deny_syscall_numbers();
    let filter = sandlock_core::seccomp::bpf::assemble_filter(&[], &deny_nrs, &[]);
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
fn parse_time_start(s: &str) -> Result<SystemTime> {
    let ts: jiff::Timestamp = s.parse()
        .map_err(|e| anyhow!("invalid --time-start '{}': {}", s, e))?;
    Ok(ts.into())
}

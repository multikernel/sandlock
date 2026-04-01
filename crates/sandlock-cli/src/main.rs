use clap::{Parser, Subcommand};
use sandlock_core::{Policy, Sandbox};
use sandlock_core::policy::ByteSize;
use sandlock_core::profile;
use anyhow::{Result, anyhow};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        #[arg(long)]
        privileged: bool,
        #[arg(long)]
        workdir: Option<String>,
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
        #[arg(long)]
        port_remap: bool,
        #[arg(long)]
        no_randomize_memory: bool,
        #[arg(long)]
        no_huge_pages: bool,
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
            max_cpu, max_open_files, chroot, privileged, workdir,
            fs_isolation, fs_storage, max_disk, net_allow, net_deny,
            port_remap, no_randomize_memory, no_huge_pages, no_coredump,
            env_vars, exec_shell, interactive: _, fs_deny, cpu_cores, gpu_devices, image, cmd } =>
        {
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
            if privileged { builder = builder.privileged(true); }
            if let Some(ref path) = workdir { builder = builder.workdir(path); }
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
            if port_remap { builder = builder.port_remap(true); }
            if !cpu_cores.is_empty() { builder = builder.cpu_cores(cpu_cores); }
            if !gpu_devices.is_empty() { builder = builder.gpu_devices(gpu_devices); }
            if no_randomize_memory { builder = builder.no_randomize_memory(true); }
            if no_huge_pages { builder = builder.no_huge_pages(true); }
            if no_coredump { builder = builder.close_fds(true); }
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

            let result = if let Some(secs) = timeout {
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

/// Days since Unix epoch (1970-01-01) for a given civil date.
/// Uses Hinnant's algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Parse an ISO 8601 datetime string "YYYY-MM-DDTHH:MM:SS" (UTC) into a SystemTime.
fn parse_time_start(s: &str) -> Result<SystemTime> {
    let (date_part, time_part) = s.split_once('T')
        .ok_or_else(|| anyhow!("--time-start must be in YYYY-MM-DDTHH:MM:SS format, got: {}", s))?;

    let date_parts: Vec<&str> = date_part.splitn(3, '-').collect();
    if date_parts.len() != 3 {
        return Err(anyhow!("invalid date in --time-start: {}", date_part));
    }
    let year: i64 = date_parts[0].parse()
        .map_err(|_| anyhow!("invalid year in --time-start: {}", date_parts[0]))?;
    let month: u32 = date_parts[1].parse()
        .map_err(|_| anyhow!("invalid month in --time-start: {}", date_parts[1]))?;
    let day: u32 = date_parts[2].parse()
        .map_err(|_| anyhow!("invalid day in --time-start: {}", date_parts[2]))?;

    let time_parts: Vec<&str> = time_part.splitn(3, ':').collect();
    if time_parts.len() != 3 {
        return Err(anyhow!("invalid time in --time-start: {}", time_part));
    }
    let hour: u64 = time_parts[0].parse()
        .map_err(|_| anyhow!("invalid hour in --time-start: {}", time_parts[0]))?;
    let minute: u64 = time_parts[1].parse()
        .map_err(|_| anyhow!("invalid minute in --time-start: {}", time_parts[1]))?;
    let second: u64 = time_parts[2].parse()
        .map_err(|_| anyhow!("invalid second in --time-start: {}", time_parts[2]))?;

    let days = days_from_civil(year, month, day);
    if days < 0 {
        return Err(anyhow!("--time-start date is before Unix epoch: {}", s));
    }
    let total_secs = days as u64 * 86400 + hour * 3600 + minute * 60 + second;
    Ok(UNIX_EPOCH + Duration::from_secs(total_secs))
}

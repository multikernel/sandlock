//! Implementation of `sandlock learn -o <output.toml>`.
//!
//! Runs a workload under observation and emits a sandlock profile TOML
//! usable by `sandlock run -p`.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, Result};
use sandlock_core::policy_fn::{SyscallEvent, Verdict};
use sandlock_core::profile::{FilesystemSection, ProfileInput};
use sandlock_core::sandbox::BranchAction;
use sandlock_core::Sandbox;

/// Returns true for pid/session-specific paths that are meaningless across runs.
fn is_junk_path(p: &std::path::Path) -> bool {
    let b = p.as_os_str().as_encoded_bytes();
    // /proc/self/... and /proc/<pid>/... are pid-specific;
    let proc_pid = b.starts_with(b"/proc/self")
        || (b.starts_with(b"/proc/") && b.get(6).map_or(false, u8::is_ascii_digit));
    proc_pid
        || b.starts_with(b"/dev/pts/") || b == b"/dev/pts"
        || b.starts_with(b"/dev/tty")
}

use crate::LearnArgs;

// openat flags (from fcntl.h)
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;

fn is_write_open(flags: u64) -> bool {
    // No valid open flag has bits 32+; a value that large is a pointer or
    // garbage (e.g. from a mis-decoded syscall arg). Treat it as read-only
    // so a misdecoded flag never puts a file in writes incorrectly.
    if flags >> 32 != 0 {
        return false;
    }
    flags & (O_WRONLY | O_RDWR | O_CREAT) != 0
}

/// Read the dynamic linker path from `/proc/<pid>/maps`. The kernel loads it
/// during execve (bypassing seccomp), so this is the way to discover it
/// after the execve completes and `/proc/<pid>/maps` reflects the new binary.
fn read_linker_from_maps(pid: u32) -> Option<PathBuf> {
    use std::io::BufRead;
    let file = std::fs::File::open(format!("/proc/{pid}/maps")).ok()?;
    for line in std::io::BufReader::new(file).lines() {
        let line = line.ok()?;
        // Format: "addr-addr perms offset dev inode pathname"
        let pathname = line.splitn(6, ' ').nth(5).map(str::trim).unwrap_or("");
        if !pathname.is_empty() && !pathname.starts_with('[') {
            let p = std::path::Path::new(pathname);
            if p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("ld-"))
                .unwrap_or(false)
            {
                return Some(p.to_path_buf());
            }
        }
    }
    None
}

/// Accumulated observations from the policy_fn callback during learn.
#[derive(Clone)]
struct LearnObserver {
    reads: Arc<Mutex<BTreeSet<PathBuf>>>,
    writes: Arc<Mutex<BTreeSet<PathBuf>>>,
    connects: Arc<Mutex<BTreeSet<String>>>,
    /// PIDs that just completed an execve — on the NEXT event from that PID,
    /// /proc/<pid>/maps will reflect the new binary's dynamic linker.
    pending_maps: Arc<Mutex<HashSet<u32>>>,
}

impl LearnObserver {
    fn new() -> Self {
        Self {
            reads: Arc::new(Mutex::new(BTreeSet::new())),
            writes: Arc::new(Mutex::new(BTreeSet::new())),
            connects: Arc::new(Mutex::new(BTreeSet::new())),
            pending_maps: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// The policy_fn callback: classifies each intercepted syscall into
    /// reads, writes, or connects for profile generation.
    fn on_event(&self, event: SyscallEvent) -> Verdict {
        // After an execve, the NEXT event from that PID fires once the
        // new binary is running — /proc/<pid>/maps now shows the dynamic
        // linker loaded by the kernel (which bypassed seccomp).
        if self.pending_maps.lock().unwrap().remove(&event.pid) {
            if let Some(linker) = read_linker_from_maps(event.pid) {
                self.reads.lock().unwrap().insert(linker);
            }
        }

        match event.syscall.as_str() {
            "execve" | "execveat" => {
                if let Some(path) = event.path {
                    self.reads.lock().unwrap().insert(path);
                }
                // Mark PID: read maps on next event after execve completes.
                self.pending_maps.lock().unwrap().insert(event.pid);
            }
            "openat" | "open" => {
                if let Some(path) = event.path {
                    if let Some(fl) = event.flags {
                        if is_write_open(fl) {
                            self.writes.lock().unwrap().insert(path);
                        } else {
                            self.reads.lock().unwrap().insert(path);
                        }
                    }
                }
            }
            // mkdir/unlink/rmdir/symlink: Landlock MAKE_*/REMOVE_* are directory
            // rights, so the parent dir is what sandlock run needs, not the target.
            "mkdirat" | "unlinkat" | "symlinkat" => {
                if let Some(p) = event.path {
                    if let Some(parent) = p.parent() {
                        self.writes.lock().unwrap().insert(parent.to_path_buf());
                    }
                }
            }
            // rename: needs RENAME_OLD on parent of old path + RENAME_NEW on parent of new path.
            "renameat2" => {
                for p in [event.path, event.path2].into_iter().flatten() {
                    if let Some(parent) = p.parent() {
                        self.writes.lock().unwrap().insert(parent.to_path_buf());
                    }
                }
            }
            // link: source needs read access (ln doesn't open() it); dst parent needs MAKE_HARDLINK.
            "linkat" => {
                if let Some(src) = event.path {
                    self.reads.lock().unwrap().insert(src);
                }
                if let Some(dst) = event.path2 {
                    if let Some(parent) = dst.parent() {
                        self.writes.lock().unwrap().insert(parent.to_path_buf());
                    }
                }
            }
            // truncate: LANDLOCK_ACCESS_FS_TRUNCATE applies to the file itself.
            "truncate" => {
                if let Some(p) = event.path {
                    self.writes.lock().unwrap().insert(p);
                }
            }
            // Simplified: connect is assumed TCP, sendto/sendmsg UDP.
            // Ideally we'd check SO_PROTOCOL on the socket fd (need emit_policy_event to expose that info in SyscallEvent)
            "connect" => {
                if let (Some(ip), Some(port)) = (event.host, event.port) {
                    self.connects.lock().unwrap().insert(format!("tcp://{ip}:{port}"));
                }
            }
            "sendto" | "sendmsg" | "sendmmsg" => {
                if let (Some(ip), Some(port)) = (event.host, event.port) {
                    self.connects.lock().unwrap().insert(format!("udp://{ip}:{port}"));
                }
            }
            _ => {}
        }
        Verdict::Allow
    }
}


pub async fn run(args: LearnArgs) -> Result<()> {
    if args.cmd.is_empty() {
        anyhow::bail!("no command given — use: sandlock learn [flags] -- <cmd> [args...]");
    }

    let cmd_str = args.cmd.join(" ");
    let cmd_refs: Vec<&str> = args.cmd.iter().map(String::as_str).collect();

    // COW workdir="/" covers every path: seccomp fires before Landlock, so the
    // supervisor intercepts every write openat and redirects it to an upper layer
    // the real filesystem is untouched and no write is blocked.
    let observer = LearnObserver::new();
    let observer_cb = observer.clone();
    let policy = Sandbox::builder()
        .fs_read("/")
        .workdir("/")
        // Discard all COW changes after observation; learn is read-only from
        // the real filesystem's perspective.
        .on_exit(BranchAction::Abort)
        .on_error(BranchAction::Abort)
        .net_allow("*")
        .net_allow("udp://*")
        .net_allow("icmp://*")
        .policy_fn(move |event, _ctx| observer_cb.on_event(event))
        .build()
        .map_err(|e| anyhow!("failed to build sandbox policy: {e}"))?;

    eprintln!("sandlock learn: observing {cmd_str} ...");

    // Use the three-step lifecycle (create/start/wait) so we can get the child
    // PID from sandbox.pid() and sample /proc/<pid> for resource peaks.
    let mut sandbox = policy.with_name("sandlock-learn");
    sandbox.create_interactive(&cmd_refs).await
        .map_err(|e| anyhow!("sandbox error: {e}"))?;
    let child_pid = sandbox.pid().expect("child pid after create") as u32;
    sandbox.start()
        .map_err(|e| anyhow!("sandbox error: {e}"))?;

    // Resource peak sampler: polls /proc/<pid> every 100ms until the process exits.
    let max_threads = Arc::new(AtomicU64::new(0));
    let max_fds = Arc::new(AtomicU64::new(0));
    let peak_rss_kb_atomic = Arc::new(AtomicU64::new(0));
    let (max_threads_s, max_fds_s, peak_rss_s) = (
        Arc::clone(&max_threads), Arc::clone(&max_fds), Arc::clone(&peak_rss_kb_atomic),
    );
    let sampler = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            match std::fs::read_to_string(format!("/proc/{child_pid}/status")) {
                Err(_) => break, // process gone
                Ok(s) => {
                    for line in s.lines() {
                        if let Some(v) = line.strip_prefix("Threads:") {
                            if let Ok(n) = v.trim().parse::<u64>() {
                                max_threads_s.fetch_max(n, Ordering::Relaxed);
                            }
                        }
                        if let Some(v) = line.strip_prefix("VmHWM:") {
                            if let Ok(n) = v.trim().trim_end_matches("kB").trim().parse::<u64>() {
                                peak_rss_s.fetch_max(n, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
            if let Ok(entries) = std::fs::read_dir(format!("/proc/{child_pid}/fd")) {
                max_fds_s.fetch_max(entries.count() as u64, Ordering::Relaxed);
            }
        }
    });

    // Wait for the process, optionally with a timeout.
    let timed_out = if let Some(secs) = args.timeout {
        let deadline = std::time::Duration::from_secs(secs);
        match tokio::time::timeout(deadline, sandbox.wait()).await {
            Ok(r) => {
                let result = r.map_err(|e| anyhow!("sandbox error: {e}"))?;
                sampler.abort();
                match result.exit_status {
                    sandlock_core::ExitStatus::Code(0) => eprintln!("sandlock learn: done"),
                    sandlock_core::ExitStatus::Code(n) => {
                        eprintln!("sandlock learn: process exited with code {n}, not writing profile");
                        std::process::exit(1);
                    }
                    sandlock_core::ExitStatus::Signal(sig) => {
                        eprintln!("sandlock learn: process killed by signal {sig}, not writing profile");
                        std::process::exit(1);
                    }
                    sandlock_core::ExitStatus::Killed | sandlock_core::ExitStatus::Timeout => {
                        eprintln!("sandlock learn: process terminated abnormally, not writing profile");
                        std::process::exit(1);
                    }
                }
                false
            }
            Err(_elapsed) => {
                // Timeout: kill the child, drain the supervisor, write a partial profile.
                eprintln!("sandlock learn: timeout after {secs}s, killing process");
                unsafe { libc::kill(child_pid as i32, libc::SIGKILL); }
                // Drain without timeout so the supervisor releases its resources cleanly.
                let _ = sandbox.wait().await;
                sampler.abort();
                true
            }
        }
    } else {
        let result = sandbox.wait().await
            .map_err(|e| anyhow!("sandbox error: {e}"))?;
        sampler.abort();
        match result.exit_status {
            sandlock_core::ExitStatus::Code(0) => eprintln!("sandlock learn: done"),
            sandlock_core::ExitStatus::Code(n) => {
                eprintln!("sandlock learn: process exited with code {n}, not writing profile");
                std::process::exit(1);
            }
            sandlock_core::ExitStatus::Signal(sig) => {
                eprintln!("sandlock learn: process killed by signal {sig}, not writing profile");
                std::process::exit(1);
            }
            sandlock_core::ExitStatus::Killed | sandlock_core::ExitStatus::Timeout => {
                eprintln!("sandlock learn: process terminated abnormally, not writing profile");
                std::process::exit(1);
            }
        }
        false
    };

    if timed_out {
        eprintln!("sandlock learn: writing partial profile from observations before timeout");
    }

    let peak_rss_kb = peak_rss_kb_atomic.load(Ordering::Relaxed);
    let threads = max_threads.load(Ordering::Relaxed);
    let fds = max_fds.load(Ordering::Relaxed);

    // Build the profile.
    let mut profile_out = ProfileInput::default();

    // Record the observed command so `sandlock run -p profile.toml` works
    // without repeating the command on the CLI.
    profile_out.program.exec = Some(PathBuf::from(&args.cmd[0]));
    profile_out.program.args = args.cmd[1..].to_vec();

    profile_out.filesystem = FilesystemSection {
        // Filter reads by existence to drop failed PATH-probe openats.
        // Executed binaries are merged into read.
        read: observer.reads.lock().unwrap().iter()
            .filter(|p| p.exists() && !is_junk_path(p))
            .cloned()
            .collect(),
        // For writes: if the file exists on the real FS, record the specific path
        // (COW kept the original intact; the file was there before the run).
        // If it doesn't exist (COW intercepted a create → new file in upper layer),
        // record the parent directory instead; Landlock requires existing paths,
        // and the program needs directory write access to create new files.
        write: observer.writes.lock().unwrap().iter()
            .filter(|p| !is_junk_path(p))
            .filter_map(|p| {
                if p.exists() {
                    Some(p.clone())
                } else {
                    // Walk up to the nearest existing ancestor.
                    p.ancestors().skip(1).find(|a| a.exists()).map(|a| a.to_path_buf())
                }
            })
            .collect(),
        ..Default::default()
    };
    profile_out.network.allow = observer.connects.lock().unwrap().iter().cloned().collect();

    // Fill limits with observed peaks + headroom so the profile is usable with sandlock run.
    if peak_rss_kb > 0 {
        let mib = (peak_rss_kb + 1023) / 1024;          // ceil to MiB
        let headroom = (mib * 5 / 4).max(16);            // +25%, min 16M
        profile_out.limits.memory = Some(format!("{headroom}M"));
    }
    if threads > 0 {
        profile_out.limits.processes = Some((threads * 2).max(4) as u32);
    }
    if fds > 0 {
        profile_out.limits.open_files = Some((fds * 2).max(32) as u32);
    }

    let kernel = std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    let header = format!(
        "# generated by sandlock learn\n\
         # command: {}\n\
         # kernel: {kernel}\n\
         # timestamp: {timestamp}\n\n",
        cmd_str.replace('\n', " ")
    );
    let body = profile_out.to_toml()
        .map_err(|e| anyhow!("failed to serialize profile: {e}"))?;
    let toml_out = format!("{header}{body}");

    match args.output {
        Some(ref path) => {
            std::fs::write(path, &toml_out)
                .map_err(|e| anyhow!("failed to write {}: {e}", path.display()))?;
            eprintln!("sandlock learn: profile written to {}", path.display());
        }
        None => print!("{toml_out}"),
    }

    Ok(())
}

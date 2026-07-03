//! Implementation of `sandlock learn -o <output.toml>`.
//!
//! Runs a workload under observation and emits a sandlock profile TOML
//! usable by `sandlock run -p`.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, Result};
use sandlock_core::profile::{FilesystemSection, ProfileInput};
use sandlock_core::Sandbox;

use crate::LearnArgs;

// openat flags (from fcntl.h)
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;

fn is_write_open(flags: u64) -> bool {
    flags & (O_WRONLY | O_RDWR | O_CREAT) != 0
}


pub async fn run(args: LearnArgs) -> Result<()> {
    if args.cmd.is_empty() {
        anyhow::bail!("no command given — use: sandlock learn [flags] -- <cmd> [args...]");
    }

    let cmd_str = args.cmd.join(" ");
    let cmd_refs: Vec<&str> = args.cmd.iter().map(String::as_str).collect();

    // Fully permissive Landlock so nothing is blocked during observation.
    // workdir (COW overlay) lets writes go anywhere without touching the real filesystem.
    let cow_dir = tempfile::Builder::new()
        .prefix("sandlock-learn-")
        .tempdir_in("/var/tmp")
        .map_err(|e| anyhow!("failed to create COW tempdir: {e}"))?;

    let reads: Arc<Mutex<BTreeSet<PathBuf>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let writes: Arc<Mutex<BTreeSet<PathBuf>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let execs: Arc<Mutex<BTreeSet<PathBuf>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let connects: Arc<Mutex<BTreeSet<String>>> = Arc::new(Mutex::new(BTreeSet::new()));

    let (reads_c, writes_c, execs_c, connects_c) = (
        Arc::clone(&reads), Arc::clone(&writes),
        Arc::clone(&execs), Arc::clone(&connects),
    );
    let policy = Sandbox::builder()
        .fs_read("/")
        .workdir(cow_dir.path())
        .on_file_access(move |path, flags| {
            if is_write_open(flags) {
                writes_c.lock().unwrap().insert(path.to_path_buf());
            } else {
                reads_c.lock().unwrap().insert(path.to_path_buf());
            }
        })
        .on_execve(move |path| {
            execs_c.lock().unwrap().insert(path.to_path_buf());
        })
        .on_net_connect(move |ip, port| {
            connects_c.lock().unwrap().insert(format!("tcp://{ip}:{port}"));
        })
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

    let result = sandbox.wait().await
        .map_err(|e| anyhow!("sandbox error: {e}"))?;

    sampler.abort();

    eprintln!("sandlock learn: done (exit={:?})", result.code());

    let peak_rss_kb = peak_rss_kb_atomic.load(Ordering::Relaxed);
    let threads = max_threads.load(Ordering::Relaxed);
    let fds = max_fds.load(Ordering::Relaxed);

    // Build the profile.
    let mut profile_out = ProfileInput::default();

    // Record the observed command so `sandlock run -p profile.toml` works
    // without repeating the command on the CLI.
    profile_out.program.exec = Some(PathBuf::from(&args.cmd[0]));
    profile_out.program.args = args.cmd[1..].to_vec();

    let cow_path = cow_dir.path().to_path_buf();
    profile_out.filesystem = FilesystemSection {
        // Filter reads by existence to drop failed PATH-probe openats.
        // Executed binaries are merged into read
        read: reads.lock().unwrap().iter()
            .chain(execs.lock().unwrap().iter())
            .filter(|p| p.exists() && !p.starts_with(&cow_path))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
        // For writes: if the file exists, record the specific path (existing file modified).
        // If it doesn't exist on the real FS (COW intercepted a create), record the parent
        // directory instead, Landlock requires the path to exist, and the program needs
        // write access to the directory to create new files inside it.
        write: writes.lock().unwrap().iter()
            .filter(|p| !p.starts_with(&cow_path))
            .filter_map(|p| {
                if p.exists() {
                    Some(p.clone())
                } else {
                    p.parent().filter(|d| d.exists()).map(|d| d.to_path_buf())
                }
            })
            .collect(),
        ..Default::default()
    };
    profile_out.network.allow = connects.lock().unwrap().iter().cloned().collect();

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

    let header = format!(
        "# generated by sandlock learn\n\
         # command: {}\n\n",
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


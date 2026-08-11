//! Implementation of `sandlock learn -o <output.toml>`.
//!
//! Runs a workload under observation and emits a sandlock profile TOML
//! usable by `sandlock run -p`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use sandlock_core::policy_fn::{SyscallEvent, Verdict};
use sandlock_core::profile::{FilesystemSection, ProfileInput};
use sandlock_core::sandbox::BranchAction;
use sandlock_core::Sandbox;


/// Protected: no legitimate sandboxed workload needs a recursive grant here.
/// Write collapse to these is skipped + error. Read collapse never fires here.
const PROTECTED_PATHS: &[&[u8]] = &[b"/", b"/root"];
const PROTECTED_CRED_SUFFIXES: &[&[u8]] = &[b"/.ssh", b"/.aws", b"/.kube", b"/.gnupg"];

/// Guarded: write grants are sometimes necessary but warrant operator awareness.
/// Write collapse emits + warning + diff. Read collapse never fires here.
const GUARDED_PATHS: &[&[u8]] = &[b"/etc", b"/proc", b"/sys", b"/dev", b"/boot", b"/run/secrets"];

#[derive(PartialEq)]
enum PathTier { Protected, Guarded, Normal }

fn classify_path(p: &std::path::Path) -> PathTier {
    let b = p.as_os_str().as_encoded_bytes();
    if PROTECTED_PATHS.iter().any(|s| b == *s)
        || PROTECTED_CRED_SUFFIXES.iter().any(|suf| b.ends_with(suf))
    {
        return PathTier::Protected;
    }
    if GUARDED_PATHS.iter().any(|s| b == *s) {
        return PathTier::Guarded;
    }
    // $HOME itself (non-root) is guarded — apps do legitimately write dotfiles there.
    if let Ok(home) = std::env::var("HOME") {
        if b == home.as_bytes() && home != "/root" {
            return PathTier::Guarded;
        }
    }
    PathTier::Normal
}

/// Print immediate children of `dir` that the workload did NOT observe writing.
fn print_observed_vs_granted_diff(dir: &std::path::Path, observed: &BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut unobserved: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| !observed.contains(p))
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    if unobserved.is_empty() { return }
    unobserved.sort();
    eprintln!(
        "  unobserved siblings now writable under {}: {}",
        dir.display(),
        unobserved.join(", ")
    );
}

/// Collapse write paths for the profile, with safety guards.
///
/// For paths that exist on the real FS: record as-is.
/// For paths that don't exist (COW-created): walk up to the nearest existing
/// ancestor, which is required for Landlock. Guards:
/// - "/" → skip entirely and print an error
/// - sensitive dirs → emit but print a warning + observed-vs-granted diff
fn collapse_write_paths(writes: &BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut out: BTreeSet<PathBuf> = BTreeSet::new();
    for p in writes {
        if is_junk_path(p) { continue; }
        if p.exists() {
            out.insert(p.clone());
            continue;
        }
        let Some(ancestor) = p.ancestors().skip(1).find(|a| a.exists()) else { continue };
        // "/" is always skipped: granting write access to the filesystem root
        // is never useful and would override every other policy entry.
        if ancestor.as_os_str().as_encoded_bytes() == b"/" {
            eprintln!(
                "sandlock learn: WARNING: write collapse for '{}' reaches filesystem root, skipping",
                p.display()
            );
            continue;
        }
        match classify_path(&ancestor) {
            PathTier::Protected => {
                eprintln!(
                    "sandlock learn: WARNING: write collapse for '{}' reaches protected path '{}', skipping",
                    p.display(), ancestor.display()
                );
                continue;
            }
            PathTier::Guarded => {
                eprintln!(
                    "sandlock learn: WARNING: write collapse '{}' to '{}' (guarded directory)",
                    p.display(), ancestor.display()
                );
                print_observed_vs_granted_diff(&ancestor, writes);
            }
            PathTier::Normal => {}
        }
        out.insert(ancestor.to_path_buf());
    }
    out.into_iter().collect()
}

/// Remove paths that are already covered by a shorter ancestor in the same list.
/// Landlock PATH_BENEATH grants are recursive, so if /usr/lib is in the list,
/// /usr/lib/x86_64/libfoo.so is redundant and can be dropped.
fn dedup_subsumed(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let set: std::collections::HashSet<PathBuf> = paths.iter().cloned().collect();
    paths.into_iter()
        .filter(|p| {
            // Keep p unless one of its strict ancestors is already in the set.
            !p.ancestors().skip(1).any(|a| set.contains(a))
        })
        .collect()
}

/// Collapse paths using the N-threshold heuristic and explicit prefixes.
///
/// Protected/guarded directories are never collapsed by the N-threshold.
/// Sensitive --collapse-prefix targets are refused up front in `run`, before
/// the workload executes; prefixes reaching here are already vetted.
fn collapse_by_threshold(
    paths: Vec<PathBuf>,
    n: usize,
    force_prefixes: &[PathBuf],
    observed: &BTreeSet<PathBuf>,
) -> Vec<PathBuf> {
    // Count how many paths share the same parent directory.
    let mut dir_counts: std::collections::HashMap<PathBuf, usize> = Default::default();
    for p in &paths {
        if let Some(parent) = p.parent() {
            *dir_counts.entry(parent.to_path_buf()).or_insert(0) += 1;
        }
    }

    let mut out: BTreeSet<PathBuf> = BTreeSet::new();
    for p in paths {
        let forced = force_prefixes.iter()
            .filter(|prefix| p.starts_with(prefix))
            .max_by_key(|prefix| prefix.as_os_str().len());

        let target: PathBuf = if let Some(prefix) = forced {
            prefix.clone()
        } else if let Some(parent) = p.parent() {
            if dir_counts.get(parent).copied().unwrap_or(0) >= n {
                parent.to_path_buf()
            } else {
                out.insert(p);
                continue;
            }
        } else {
            out.insert(p);
            continue;
        };

        match classify_path(&target) {
            PathTier::Normal => {
                out.insert(target);
            }
            tier => {
                if forced.is_some() {
                    // Explicit --collapse-prefix + --force-sensitive-collapse: emit with warning + diff.
                    let label = if tier == PathTier::Protected { "protected" } else { "guarded" };
                    eprintln!(
                        "sandlock learn: WARNING: collapse '{}' to '{}' ({label} directory)",
                        p.display(), target.display()
                    );
                    print_observed_vs_granted_diff(&target, observed);
                    out.insert(target);
                } else {
                    // N-threshold hit a sensitive dir: keep individual path.
                    out.insert(p);
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Returns true for pid/session-specific paths that are meaningless across runs.
fn is_junk_path(p: &std::path::Path) -> bool {
    let b = p.as_os_str().as_encoded_bytes();
    // /proc/self/... and /proc/<pid>/... are pid-specific;
    let proc_pid = b.starts_with(b"/proc/self")
        || (b.starts_with(b"/proc/") && b.get(6).map_or(false, u8::is_ascii_digit));
    // Only the controlling terminal is session-specific; hardware serial
    // devices (/dev/ttyS*, /dev/ttyUSB*, ...) are stable paths a workload
    // may legitimately need.
    proc_pid
        || b.starts_with(b"/dev/pts/") || b == b"/dev/pts"
        || b == b"/dev/tty"
}

use crate::LearnArgs;

/// Fail learn (writing no profile) unless the workload exited cleanly.
fn require_clean_exit(status: &sandlock_core::ExitStatus) -> Result<()> {
    match status {
        sandlock_core::ExitStatus::Code(0) => {
            eprintln!("sandlock learn: done");
            Ok(())
        }
        sandlock_core::ExitStatus::Code(n) => {
            Err(anyhow!("process exited with code {n}, not writing profile"))
        }
        sandlock_core::ExitStatus::Signal(sig) => {
            Err(anyhow!("process killed by signal {sig}, not writing profile"))
        }
        _ => Err(anyhow!("process terminated abnormally, not writing profile")),
    }
}

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

/// Returns the TGID (thread group leader PID) for a given TID.
fn tgid_of(tid: u32) -> u32 {
    let Ok(s) = std::fs::read_to_string(format!("/proc/{tid}/status")) else {
        return tid;
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:\t") {
            if let Ok(tgid) = rest.trim().parse::<u32>() {
                return tgid;
            }
        }
    }
    tid
}

/// Read all file-backed r-xp (executable) mappings from `/proc/<pid>/maps`.
/// This captures the dynamic linker, all shared libraries, and the main binary
/// as actually mapped by the kernel. 
fn read_rx_mapped_files(pid: u32) -> Vec<PathBuf> {
    use std::io::BufRead;
    let Ok(file) = std::fs::File::open(format!("/proc/{pid}/maps")) else { return vec![] };
    let mut out = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let Ok(line) = line else { break };
        // Format: "addr-addr perms offset dev inode pathname"
        let mut parts = line.splitn(6, ' ');
        let perms = parts.nth(1).unwrap_or("");
        let pathname = parts.nth(3).map(str::trim).unwrap_or("");
        if perms.contains('x') && !pathname.is_empty() && !pathname.starts_with('[') {
            out.push(PathBuf::from(pathname));
        }
    }
    out
}


/// Accumulated observations from the policy_fn callback during learn.
#[derive(Clone)]
struct LearnObserver {
    reads: Arc<Mutex<BTreeSet<PathBuf>>>,
    writes: Arc<Mutex<BTreeSet<PathBuf>>>,
    connects: Arc<Mutex<BTreeSet<String>>>,
    binds: Arc<Mutex<BTreeSet<u16>>>,
    /// PIDs with an exec attempt observed but the post-exec maps scan still
    /// pending; the scan runs on the pid's first non-exec event, which is
    /// guaranteed to run under the new image.
    pending_maps: Arc<Mutex<HashSet<u32>>>,
    /// Resolved path of the first binary the workload exec'd, from
    /// /proc/<pid>/exe. Pins [program].exec to an absolute path; argv[0] may
    /// be relative (resolved through $PATH by execvp) and useless to `run`.
    first_exe: Arc<Mutex<Option<PathBuf>>>,
    /// UDP connect() calls pending confirmation by a subsequent send.
    /// Keyed by (TGID, fd) so a connect observed on one thread can be
    /// confirmed by traffic from a sibling thread using the same fd table.
    /// Connected UDP write(2) is deliberately not observed: trapping write
    /// would catch the child bootstrap pipe writes before the parent receives
    /// the seccomp listener fd.
    pending_udp_connects: Arc<Mutex<HashMap<(u32, i64), String>>>,
}

impl LearnObserver {
    fn new() -> Self {
        Self {
            reads: Arc::new(Mutex::new(BTreeSet::new())),
            writes: Arc::new(Mutex::new(BTreeSet::new())),
            connects: Arc::new(Mutex::new(BTreeSet::new())),
            binds: Arc::new(Mutex::new(BTreeSet::new())),
            pending_maps: Arc::new(Mutex::new(HashSet::new())),
            first_exe: Arc::new(Mutex::new(None)),
            pending_udp_connects: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The policy_fn callback: classifies each intercepted syscall into
    /// reads, writes, or connects for profile generation.
    fn on_event(&self, event: SyscallEvent) -> Verdict {
        // After a successful execve, the NEXT event from that PID runs under
        // the new image, so /proc/<pid>/maps shows the binary and dynamic
        // linker the kernel loaded (which bypassed seccomp). Another exec
        // event from a pending PID instead means the previous attempt failed
        // (execvp walking $PATH; a successful execve never returns), so keep
        // waiting: scanning then would record the old image, which for the
        // workload's first exec is the sandbox runtime itself.
        let is_exec = matches!(event.syscall.as_str(), "execve" | "execveat");
        if !is_exec && self.pending_maps.lock().unwrap().remove(&event.pid) {
            let mut reads = self.reads.lock().unwrap();
            // /proc/<pid>/exe is the canonical real binary path (symlinks resolved by the kernel),
            // race-free at this point since the new image is already loaded.
            if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", event.pid)) {
                let mut first = self.first_exe.lock().unwrap();
                if first.is_none() {
                    *first = Some(exe.clone());
                }
                reads.insert(exe);
            }
            for path in read_rx_mapped_files(event.pid) {
                reads.insert(path);
            }
        }

        match event.syscall.as_str() {
            "execve" | "execveat" => {
                // event.path may be a symlink; canonical real path comes from /proc/<pid>/exe in pending_maps.
                if let Some(path) = event.path {
                    self.reads.lock().unwrap().insert(path);
                }

                // When a non-leader thread calls execve, the new process runs under the TGID,
                // so we must insert the TGID into pending_maps.
                self.pending_maps.lock().unwrap().insert(tgid_of(event.pid));
            }
            "openat" | "open" => {
                if let Some(path) = event.path {
                    let path = canonicalize_or_keep(path);
                    if let Some(fl) = event.flags {
                        if is_write_open(fl) {
                            self.writes.lock().unwrap().insert(path);
                        } else {
                            self.reads.lock().unwrap().insert(path);
                        }
                    }
                }
            }
            // mkdir/unlink/rmdir/symlink/mknod: Landlock MAKE_*/REMOVE_* are directory
            // rights, so the parent dir is what sandlock run needs, not the target.
            "mkdirat" | "mknodat" => {
                if let Some(p) = event.path {
                    let p = canonicalize_or_keep(p);
                    if let Some(parent) = p.parent() {
                        self.writes.lock().unwrap().insert(parent.to_path_buf());
                    }
                }
            }
            // unlinkat/symlinkat operate on the link itself, not its target, so
            // only the parent is canonicalized to avoid following the symlink.
            "unlinkat" | "symlinkat" => {
                if let Some(p) = event.path {
                    let p = canonicalize_parent_or_keep(p);
                    if let Some(parent) = p.parent() {
                        self.writes.lock().unwrap().insert(parent.to_path_buf());
                    }
                }
            }
            // rename: needs RENAME_OLD on parent of old path + RENAME_NEW on parent of new path.
            // Both operate on the link itself, not its target.
            "renameat2" => {
                for p in [event.path, event.path2].into_iter().flatten() {
                    let p = canonicalize_parent_or_keep(p);
                    if let Some(parent) = p.parent() {
                        self.writes.lock().unwrap().insert(parent.to_path_buf());
                    }
                }
            }
            // link: source needs read access (ln doesn't open() it); dst parent needs MAKE_HARDLINK.
            // dst operates on the link itself, so only the parent is canonicalized.
            "linkat" => {
                if let Some(src) = event.path {
                    self.reads.lock().unwrap().insert(canonicalize_or_keep(src));
                }
                if let Some(dst) = event.path2 {
                    let dst = canonicalize_parent_or_keep(dst);
                    if let Some(parent) = dst.parent() {
                        self.writes.lock().unwrap().insert(parent.to_path_buf());
                    }
                }
            }
            // truncate: LANDLOCK_ACCESS_FS_TRUNCATE applies to the file itself.
            "truncate" => {
                if let Some(p) = event.path {
                    self.writes.lock().unwrap().insert(canonicalize_or_keep(p));
                }
            }
            "bind" => {
                if let Some(port) = event.port {
                    if port > 0 {
                        self.binds.lock().unwrap().insert(port);
                    }
                } else if let Some(p) = event.path {
                    // AF_UNIX named bind: Landlock MAKE_SOCK is a directory right,
                    // so the parent dir is what sandlock run needs.
                    let p = canonicalize_or_keep(p);
                    if let Some(parent) = p.parent() {
                        self.writes.lock().unwrap().insert(parent.to_path_buf());
                    }
                }
            }
            "connect" | "sendto" | "sendmsg" | "sendmmsg" => {
                // An address-less send on a connected UDP socket is how the
                // glibc resolver talks to its nameserver (connect, then
                // send with no sockaddr): real traffic, so it promotes the
                // parked connect() the same way an addressed send does.
                if event.host.is_none()
                    && event.syscall != "connect"
                    && event.protocol.as_deref() == Some("udp")
                {
                    if let Some(fd) = event.fd {
                        let key = (tgid_of(event.pid), fd);
                        if let Some(pending) = self.pending_udp_connects
                            .lock().unwrap().remove(&key)
                        {
                            self.connects.lock().unwrap().insert(pending);
                        }
                    }
                }
                if let (Some(ip), Some(port), Some(proto)) = (event.host, event.port, event.protocol) {
                    if proto != "icmp" {
                        let host = if ip.is_ipv6() { format!("[{ip}]") } else { ip.to_string() };
                        let entry = format!("{proto}://{host}:{port}");
                        if proto == "udp" && event.syscall == "connect" {
                            // Park UDP connect() in pending: if a send() follows on the
                            // same socket it is real traffic; if not it was an
                            // address-sorting probe (e.g. glibc getaddrinfo) and is
                            // discarded when the workload exits.
                            if let Some(fd) = event.fd {
                                let key = (tgid_of(event.pid), fd);
                                self.pending_udp_connects.lock().unwrap()
                                    .insert(key, entry);
                            }
                        } else {
                            // For UDP send*, promote any pending connect() on the
                            // same process fd to confirmed traffic.
                            if proto == "udp" {
                                if let Some(fd) = event.fd {
                                    let key = (tgid_of(event.pid), fd);
                                    if let Some(pending) = self.pending_udp_connects
                                        .lock().unwrap().remove(&key)
                                    {
                                        self.connects.lock().unwrap().insert(pending);
                                    }
                                }
                            }
                            self.connects.lock().unwrap().insert(entry);
                        }
                    }
                }
            }
            _ => {}
        }
        Verdict::Allow
    }
}


/// Resolve symlinks to get the canonical path. Falls back to the original
/// if the path doesn't exist yet (e.g. COW-intercepted creates).
fn canonicalize_or_keep(p: PathBuf) -> PathBuf {
    std::fs::canonicalize(&p).unwrap_or(p)
}

/// Canonicalize only the parent directory and rejoin the final component.
/// Used for syscalls that operate on the link itself (unlink, rename, symlink).
fn canonicalize_parent_or_keep(p: PathBuf) -> PathBuf {
    let file_name = match p.file_name() {
        Some(n) => n.to_owned(),
        None => return p,
    };
    let parent = match p.parent() {
        Some(par) => par,
        None => return p,
    };
    let canonical_parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    canonical_parent.join(file_name)
}

pub async fn run(args: LearnArgs) -> Result<()> {
    if args.cmd.is_empty() {
        anyhow::bail!("no command given; use: sandlock learn [flags] -- <cmd> [args...]");
    }

    // Refuse bad flag combinations before the workload runs, not after a
    // full observation pass.
    for prefix in &args.collapse_prefix {
        if classify_path(prefix) != PathTier::Normal && !args.force_sensitive_collapse {
            anyhow::bail!(
                "--collapse-prefix '{}' targets a sensitive path; use --force-sensitive-collapse to proceed",
                prefix.display()
            );
        }
    }

    let cmd_str = args.cmd.join(" ");
    let cmd_refs: Vec<&str> = args.cmd.iter().map(String::as_str).collect();

    // COW workdir="/" covers every path: seccomp fires before Landlock, so the
    // supervisor intercepts every write openat and redirects it to an upper layer
    // the real filesystem is untouched and no write is blocked.
    let observer = LearnObserver::new();
    let observer_cb = observer.clone();
    let policy = Sandbox::builder()
        // Name + mode mark this as a learning sandbox in `sandlock ps`: the
        // observation policy below (read "/", allow-all network) would
        // otherwise look like a dangerously permissive run. One learn
        // sandbox per CLI process, so the pid keeps names unique.
        .name(format!("learn-{}", std::process::id()))
        .mode("learn")
        .fs_read("/")
        .workdir("/")
        // Discard all COW changes after observation; learn is read-only from
        // the real filesystem's perspective.
        .on_exit(BranchAction::Abort)
        .on_error(BranchAction::Abort)
        // A scheme-less "*" covers TCP and UDP; ICMP always needs its own rule.
        .net_allow("*")
        .net_allow("icmp://*")
        .max_memory(sandlock_core::sandbox::ByteSize(1 << 43)) // 8 TiB
        .policy_fn(move |event, _ctx| observer_cb.on_event(event))
        .build()
        .map_err(|e| anyhow!("failed to build sandbox policy: {e}"))?;

    eprintln!("sandlock learn: observing {cmd_str} ...");

    // Use the three-step lifecycle (create/start/wait) so we can get the child
    // PID from sandbox.pid() and sample /proc/<pid> for resource peaks.
    let mut sandbox = policy;
    sandbox.create_interactive(&cmd_refs).await
        .map_err(|e| anyhow!("sandbox error: {e}"))?;
    let child_pid = sandbox.pid().expect("child pid after create") as u32;
    sandbox.start()
        .map_err(|e| anyhow!("sandbox error: {e}"))?;

    // Wait for the process, optionally with a timeout.
    let timed_out = if let Some(secs) = args.timeout {
        let deadline = std::time::Duration::from_secs(secs);
        match tokio::time::timeout(deadline, sandbox.wait()).await {
            Ok(r) => {
                let result = r.map_err(|e| anyhow!("sandbox error: {e}"))?;
                require_clean_exit(&result.exit_status)?;
                false
            }
            Err(_elapsed) => {
                // Timeout: kill the child, drain the supervisor, write a partial profile.
                eprintln!("sandlock learn: timeout after {secs}s, killing process");
                unsafe { libc::kill(child_pid as i32, libc::SIGKILL); }
                // Drain without timeout so the supervisor releases its resources cleanly.
                let _ = sandbox.wait().await;
                true
            }
        }
    } else {
        let result = sandbox.wait().await
            .map_err(|e| anyhow!("sandbox error: {e}"))?;
        require_clean_exit(&result.exit_status)?;
        false
    };

    if timed_out {
        eprintln!("sandlock learn: writing partial profile from observations before timeout");
    }

    let (peak_mem_bytes, peak_procs) = sandbox.resource_peaks().await;

    // Build the profile from observations.
    let mut profile_out = ProfileInput::default();

    // Record the observed command so `sandlock run -p profile.toml` works
    // without repeating the command on the CLI. Prefer the observed absolute
    // binary path over argv[0], which may be a bare name resolved via $PATH.
    let first_exe = observer.first_exe.lock().unwrap().clone();
    profile_out.program.exec = first_exe.or_else(|| Some(PathBuf::from(&args.cmd[0])));
    profile_out.program.args = args.cmd[1..].to_vec();

    let reads_raw: Vec<PathBuf> = observer.reads.lock().unwrap().iter()
        .filter(|p| p.exists() && !is_junk_path(p))
        .filter(|p| {
            // Same guard the write side has: "/" is never a grant. A child
            // whose cwd is the workdir root lists it routinely (python's -c
            // puts the cwd on sys.path), and granting it would subsume every
            // other read in the profile.
            if p.as_path() == std::path::Path::new("/") {
                eprintln!(
                    "sandlock learn: WARNING: observed a read of '/', refusing to grant it"
                );
                return false;
            }
            true
        })
        .cloned()
        .collect();
    let writes_raw = observer.writes.lock().unwrap();
    let observed_all: BTreeSet<PathBuf> = reads_raw.iter()
        .chain(writes_raw.iter())
        .cloned()
        .collect();

    let reads = if let Some(n) = args.collapse {
        dedup_subsumed(collapse_by_threshold(reads_raw, n, &args.collapse_prefix, &observed_all))
    } else if !args.collapse_prefix.is_empty() {
        dedup_subsumed(collapse_by_threshold(reads_raw, usize::MAX, &args.collapse_prefix, &observed_all))
    } else {
        dedup_subsumed(reads_raw)
    };

    let writes_collapsed = collapse_write_paths(&writes_raw);
    let writes = if let Some(n) = args.collapse {
        dedup_subsumed(collapse_by_threshold(writes_collapsed, n, &args.collapse_prefix, &observed_all))
    } else if !args.collapse_prefix.is_empty() {
        dedup_subsumed(collapse_by_threshold(writes_collapsed, usize::MAX, &args.collapse_prefix, &observed_all))
    } else {
        dedup_subsumed(writes_collapsed)
    };

    profile_out.filesystem = FilesystemSection {
        read: reads,
        write: writes,
        ..Default::default()
    };
    profile_out.network.allow = observer.connects.lock().unwrap().iter().cloned().collect();
    profile_out.network.allow_bind = observer.binds.lock().unwrap().iter()
        .map(|&p| sandlock_core::profile::PortSpec::Port(p))
        .collect();

    // Fill limits with observed peaks + headroom so the profile is usable with sandlock run.
    // Memory: tracked via the sentinel max_memory in the builder, which activates handle_memory
    // so peak_mem_bytes uses the same virtual-anonymous accounting that sandlock run enforces.
    if peak_mem_bytes > 0 {
        let mib = (peak_mem_bytes / (1024 * 1024)).max(1);
        let headroom = (mib * 5 / 4).max(16);
        profile_out.limits.memory = Some(format!("{headroom}M"));
    }
    if peak_procs > 0 {
        profile_out.limits.processes = Some((peak_procs * 2).max(4));
    }
    // TODO: learn limits.open_files via supervisor once open_files enforcement is implemented.

    // --merge: union observed profile into an existing one.
    // Start from the existing profile so all fields we don't observe 
    // are preserved. Then union in the observed fields.
    if let Some(ref merge_path) = args.merge {
        let existing_toml = std::fs::read_to_string(merge_path)
            .map_err(|e| anyhow!("failed to read merge file {}: {e}", merge_path.display()))?;
        let existing: ProfileInput = toml::from_str(&existing_toml)
            .map_err(|e| anyhow!("failed to parse merge file {}: {e}", merge_path.display()))?;

        // Base is the existing profile; union observed fields into it.
        let observed = profile_out;
        profile_out = existing.clone();

        // Union filesystem paths, re-run dedup after merging.
        let merged_reads: Vec<PathBuf> = {
            let mut set: BTreeSet<PathBuf> = observed.filesystem.read.iter().cloned().collect();
            set.extend(existing.filesystem.read.iter().cloned());
            dedup_subsumed(set.into_iter().collect())
        };
        let merged_writes: Vec<PathBuf> = {
            let mut set: BTreeSet<PathBuf> = observed.filesystem.write.iter().cloned().collect();
            set.extend(existing.filesystem.write.iter().cloned());
            dedup_subsumed(set.into_iter().collect())
        };
        profile_out.filesystem.read = merged_reads;
        profile_out.filesystem.write = merged_writes;

        // Union network.allow.
        let mut allow_set: std::collections::BTreeSet<String> =
            observed.network.allow.iter().cloned().collect();
        allow_set.extend(existing.network.allow.iter().cloned());
        profile_out.network.allow = allow_set.into_iter().collect();

        // Union allow_bind: preserve PortSpec verbatim (ranges, named specs).
        // Dedup by canonical string: Port(n) -> "n", Spec(s) -> s.
        let port_key = |p: &sandlock_core::profile::PortSpec| -> String {
            match p {
                sandlock_core::profile::PortSpec::Port(n) => n.to_string(),
                sandlock_core::profile::PortSpec::Spec(s) => s.clone(),
            }
        };
        let mut seen = std::collections::HashSet::new();
        let mut merged_bind: Vec<sandlock_core::profile::PortSpec> = Vec::new();
        for p in observed.network.allow_bind.iter().chain(existing.network.allow_bind.iter()) {
            if seen.insert(port_key(p)) {
                merged_bind.push(p.clone());
            }
        }
        profile_out.network.allow_bind = merged_bind;

        // Limits: take the max of old vs observed.
        profile_out.limits.memory = max_bytesize(existing.limits.memory.as_deref(), observed.limits.memory.as_deref());
        profile_out.limits.processes = max_opt(existing.limits.processes, observed.limits.processes);
        profile_out.limits.open_files = max_opt(existing.limits.open_files, observed.limits.open_files);
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

    // Output target: -o overrides --merge's file; --merge writes back in place.
    let output_path = args.output.as_ref().or(args.merge.as_ref());
    match output_path {
        Some(path) => {
            std::fs::write(path, &toml_out)
                .map_err(|e| anyhow!("failed to write {}: {e}", path.display()))?;
            eprintln!("sandlock learn: profile written to {}", path.display());
        }
        None => print!("{toml_out}"),
    }

    Ok(())
}


/// Parse a bytesize string like "128M", "1G", "512K" into bytes.
fn parse_bytesize_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('G') {
        (n, 1024 * 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix('M') {
        (n, 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix('K') {
        (n, 1024u64)
    } else {
        (s, 1u64)
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// Return the larger of two optional bytesize strings.
fn max_bytesize(a: Option<&str>, b: Option<&str>) -> Option<String> {
    match (a, b) {
        (None, None) => None,
        (Some(s), None) | (None, Some(s)) => Some(s.to_string()),
        (Some(sa), Some(sb)) => {
            let va = parse_bytesize_bytes(sa).unwrap_or(0);
            let vb = parse_bytesize_bytes(sb).unwrap_or(0);
            Some(if va >= vb { sa.to_string() } else { sb.to_string() })
        }
    }
}

/// Return the larger of two optional u32 values.
fn max_opt(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (None, None) => None,
        (Some(v), None) | (None, Some(v)) => Some(v),
        (Some(va), Some(vb)) => Some(va.max(vb)),
    }
}

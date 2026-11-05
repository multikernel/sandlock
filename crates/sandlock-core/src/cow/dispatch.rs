//! Seccomp notification handlers for COW filesystem interception.
//!
//! Reads paths from child memory, delegates to SeccompCowBranch,
//! and injects results (fds, stat structs, readlink strings, dirents) back.
//!
//! # Continue safety (issue #27)
//!
//! Every `Continue` in this module is a *fall-through* — the COW layer
//! decided the syscall is outside its scope, so it lets the kernel handle
//! the original syscall normally. No COW path was modified or rewritten
//! when we return Continue, so the kernel's re-read sees exactly what the
//! child originally passed. The fall-through happens when:
//!
//!   * No COW branch is active (`cow_state.branch == None`).
//!   * The path doesn't match the COW prefix (`!cow.matches(path)`).
//!   * `read_path` / `read_child_mem` / `CString::new` failed.
//!   * The supervisor's own open/copy attempt failed and we want the
//!     kernel to surface its own error.
//!
//! Because Continue means "we didn't intervene," the seccomp_unotify
//! TOCTOU concern doesn't apply: we're not making a security decision
//! whose validity depends on the kernel re-reading the same memory we
//! read. Path-based security enforcement for these fall-throughs is
//! provided by Landlock (or by the chroot dispatcher, when chroot mode
//! is active and runs before COW).

use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::sync::Mutex as AsyncMutex;

use crate::arch;
use crate::cow::result::link_result;
use crate::cow::seccomp::{branch_errno, CopyUp, CowCopyPlan, CowOpenPlan, SeccompCowBranch};
use crate::error::BranchError;
use crate::procfs::{build_dirent64, DT_DIR, DT_LNK, DT_REG};
use crate::seccomp::notif::{
    decode_open_args, id_valid, read_child_mem, write_child_mem, write_child_mem_force, NotifAction,
};
use crate::seccomp::state::{CowState, PerProcessState, ProcessIndex};
use crate::sys::structs::SeccompNotif;

/// Acquire the per-process state handle for `notif.pid`. Returns
/// None if the pid isn't tracked (pidfd_open failed at fork on an
/// old kernel, or the process is gone) — callers should fall back
/// to `NotifAction::Continue`.
fn pp_handle(processes: &Arc<ProcessIndex>, pid: u32) -> Option<Arc<AsyncMutex<PerProcessState>>> {
    processes
        .entry_for(i32::try_from(pid).ok()?)
        .map(|(_, s)| s)
}

/// Read the current virtual cwd for `pid` (None if the process
/// hasn't chdir'd into a COW-only directory, or isn't tracked).
async fn current_virtual_cwd(processes: &Arc<ProcessIndex>, pid: u32) -> Option<String> {
    let handle = pp_handle(processes, pid)?;
    let cwd = handle.lock().await.virtual_cwd.clone();
    cwd
}

/// Read a NUL-terminated path from child memory (up to 4096 bytes for filesystem paths).
///
/// Reads page-by-page to avoid crossing into unmapped memory (e.g. when the path
/// pointer is near a page boundary on the stack).
fn read_path(notif: &SeccompNotif, addr: u64, notif_fd: RawFd) -> Option<String> {
    if addr == 0 {
        return None;
    }
    const PAGE_SIZE: u64 = 4096;
    let mut result = Vec::with_capacity(256);
    let mut cur = addr;
    while result.len() < 4096 {
        let page_remaining = PAGE_SIZE - (cur % PAGE_SIZE);
        let to_read = page_remaining.min((4096 - result.len()) as u64) as usize;
        let bytes = read_child_mem(notif_fd, notif.id, notif.pid, cur, to_read).ok()?;
        if let Some(nul) = bytes.iter().position(|&b| b == 0) {
            result.extend_from_slice(&bytes[..nul]);
            return String::from_utf8(result).ok();
        }
        result.extend_from_slice(&bytes);
        cur += to_read as u64;
    }
    String::from_utf8(result).ok()
}

/// Resolve a path that may be relative to a dirfd.
/// For AT_FDCWD (-100), returns the path as-is (assumed absolute or cwd-relative).
/// For other dirfds, reads /proc/{pid}/fd/{dirfd} to get the base path.
fn normalize_path(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

fn resolve_at_path_with_virtual(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    virtual_cwd: Option<&str>,
) -> String {
    // A descriptor path is openat(N, tail) under a spelling the workdir prefix
    // never matches, so resolve the pair it names like any other dirfd path.
    let descriptor = crate::seccomp::notif::descriptor_path_tail(notif, path);
    let (dirfd, path) = match &descriptor {
        Some((fd, tail)) => (*fd as i64, tail.as_str()),
        None => (dirfd, path),
    };
    if Path::new(path).is_absolute() {
        return normalize_path(PathBuf::from(path))
            .to_string_lossy()
            .into_owned();
    }
    // dirfd is stored as u64 in seccomp_data.args but AT_FDCWD is a negative i32.
    // Truncate to i32 for correct sign comparison.
    let dirfd32 = dirfd as i32;
    if dirfd32 == libc::AT_FDCWD {
        if let Some(cwd) = virtual_cwd {
            return normalize_path(Path::new(cwd).join(path))
                .to_string_lossy()
                .into_owned();
        }
        // Relative to cwd — read /proc/{pid}/cwd
        if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
            return normalize_path(cwd.join(path))
                .to_string_lossy()
                .into_owned();
        }
        return path.to_string();
    }
    // Relative to dirfd
    if let Ok(base) = std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd)) {
        normalize_path(base.join(path))
            .to_string_lossy()
            .into_owned()
    } else {
        path.to_string()
    }
}

fn map_cow_upper_path(cow: &SeccompCowBranch, path: &str) -> String {
    let path = PathBuf::from(path);
    if let Ok(rel) = path.strip_prefix(cow.upper_dir()) {
        return normalize_path(cow.workdir().join(rel))
            .to_string_lossy()
            .into_owned();
    }
    normalize_path(path).to_string_lossy().into_owned()
}

// ============================================================
// openat handler
// ============================================================

/// Open `real_path` confined to its layer root, so a symlink or `..` in the
/// child-controlled path cannot escape the upper/lower tree (issue #112).
/// Picks the anchor root by prefix, then defers all resolution to the kernel
/// via `openat2(RESOLVE_IN_ROOT)`.
/// Select the layer root (`upper` first, then `workdir`) that `real_path` lives
/// under and return it with the relative remainder. `Err(EACCES)` if the path
/// is under neither root. This only selects the anchor; the kernel re-resolves
/// the relative path under it with `RESOLVE_IN_ROOT`, so the lexical
/// `strip_prefix` grants no trust.
fn pick_root_rel<'a>(
    upper_root: &'a Path,
    workdir_root: &'a Path,
    real_path: &Path,
) -> Result<(&'a Path, String), i32> {
    let (root, rel) = if let Ok(rel) = real_path.strip_prefix(upper_root) {
        (upper_root, rel)
    } else if let Ok(rel) = real_path.strip_prefix(workdir_root) {
        (workdir_root, rel)
    } else {
        return Err(libc::EACCES);
    };
    Ok((root, rel.to_str().ok_or(libc::EINVAL)?.to_string()))
}

pub(crate) fn open_confined(
    upper_root: &Path,
    workdir_root: &Path,
    real_path: &Path,
    flags: i32,
    mode: u32,
) -> Result<RawFd, i32> {
    let (root, rel) = pick_root_rel(upper_root, workdir_root, real_path)?;
    crate::sys::fs::openat2_in_root(root, &rel, flags, mode)
}

/// The branch's directories, taken under the lock for work done without it.
#[derive(Clone)]
pub(crate) struct Layers {
    upper: PathBuf,
    workdir: PathBuf,
    staging: PathBuf,
}

impl Layers {
    pub(crate) fn of(cow: &SeccompCowBranch) -> Self {
        Self {
            upper: cow.upper_dir().to_path_buf(),
            workdir: cow.workdir().to_path_buf(),
            staging: cow.staging_dir().to_path_buf(),
        }
    }
}

/// The trapped syscall a copy-up is made for.
#[derive(Clone, Copy)]
pub(crate) struct Caller {
    fd: RawFd,
    id: u64,
}

impl Caller {
    pub(crate) fn of(notif: &SeccompNotif, fd: RawFd) -> Self {
        Self { fd, id: notif.id }
    }

    fn waiting(self) -> bool {
        id_valid(self.fd, self.id).is_ok()
    }
}

/// Run `apply` under the branch lock once `need` is in the upper. Only the
/// copy is slow, so only it leaves the loop, and `apply` runs under the lock
/// that found every copy in place.
pub(crate) fn after_copy_up(
    cow_state: &Arc<Mutex<CowState>>,
    caller: Caller,
    cow: &mut SeccompCowBranch,
    need: CopyUp,
    refuse: impl Fn(BranchError) -> NotifAction + Send + 'static,
    apply: impl FnOnce(&mut SeccompCowBranch) -> NotifAction + Send + 'static,
) -> NotifAction {
    let plans = match &need {
        CopyUp::Nothing => return apply(cow),
        CopyUp::Entry(rel) => match cow.prepare_copies(std::slice::from_ref(rel)) {
            Ok(plans) if plans.is_empty() => return apply(cow),
            Ok(plans) => plans,
            Err(e) => return refuse(e),
        },
        // Walking the lower tree is I/O too.
        CopyUp::Tree(_) => Vec::new(),
    };
    copy_up_off_loop(
        cow_state,
        caller,
        Layers::of(cow),
        need,
        plans,
        refuse,
        apply,
    )
}

/// `after_copy_up` for a caller holding `plans` it already made for `need`.
pub(crate) fn copy_up_off_loop(
    cow_state: &Arc<Mutex<CowState>>,
    caller: Caller,
    layers: Layers,
    need: CopyUp,
    mut plans: Vec<(String, CowCopyPlan)>,
    refuse: impl Fn(BranchError) -> NotifAction + Send + 'static,
    apply: impl FnOnce(&mut SeccompCowBranch) -> NotifAction + Send + 'static,
) -> NotifAction {
    let cow_state = Arc::clone(cow_state);
    NotifAction::native(move || {
        let rels = match need {
            CopyUp::Nothing => Vec::new(),
            CopyUp::Entry(rel) => vec![rel],
            CopyUp::Tree(root) => match SeccompCowBranch::lower_tree(&layers.workdir, &root) {
                Ok(tree) => tree,
                Err(errno) => return NotifAction::Errno(errno),
            },
        };
        loop {
            if let Err(errno) = run_copies(&cow_state, &layers, plans) {
                return NotifAction::Errno(errno);
            }
            let mut st = cow_state.blocking_lock();
            let Some(cow) = st.branch.as_mut() else {
                return NotifAction::Errno(libc::EIO);
            };
            plans = match cow.prepare_copies(&rels) {
                Ok(plans) => plans,
                Err(e) => return refuse(e),
            };
            // A caller interrupted meanwhile (a signal, or an exec freeze
            // without a killable wait) restarts its syscall, which must not
            // find the write already done.
            if plans.is_empty() {
                return match caller.waiting() {
                    true => apply(cow),
                    false => NotifAction::Errno(libc::EINTR),
                };
            }
        }
    })
}

/// Blocks. Copies first, waits after: a caller that waits holds no ticket,
/// so two of them never wait on each other. A failed copy fails the syscall,
/// since continuing would reach the lower file.
fn run_copies(
    cow_state: &Mutex<CowState>,
    layers: &Layers,
    plans: Vec<(String, CowCopyPlan)>,
) -> Result<(), i32> {
    let (copies, waits): (Vec<_>, Vec<_>) = plans
        .into_iter()
        .partition(|(_, plan)| matches!(plan, CowCopyPlan::NeedsCopy { .. }));
    let mut copies = copies.into_iter();
    while let Some((rel, plan)) = copies.next() {
        let CowCopyPlan::NeedsCopy {
            file_size, ticket, ..
        } = plan
        else {
            continue;
        };
        let staged = SeccompCowBranch::stage_copy(&layers.workdir, &layers.staging, &rel);
        let mut st = cow_state.blocking_lock();
        let cow = st.branch.as_mut().ok_or(libc::EIO)?;
        if let Err(e) = cow.finish_copy(&rel, file_size, ticket, staged) {
            cow.abandon_copies(copies);
            return Err(e.raw_os_error().unwrap_or(libc::EIO));
        }
    }
    for (_, plan) in waits {
        if let CowCopyPlan::InFlight(done) = plan {
            done.wait();
        }
    }
    Ok(())
}

/// Where an open plan leads.
pub(crate) enum OpenStep {
    /// Outside the branch's say: the caller opens it the way it would anyway.
    Skip,
    Open(PathBuf),
    Copy(String, CowCopyPlan),
    Answer(NotifAction),
}

impl OpenStep {
    pub(crate) fn of(plan: Result<CowOpenPlan, BranchError>) -> Self {
        match plan {
            Ok(CowOpenPlan::Skip) | Err(BranchError::NotOwned) => OpenStep::Skip,
            // Deleted in this branch (whiteout): the lower file still exists, so
            // opening it would read its pre-delete content. Return ENOENT,
            // matching the stat/access handlers.
            Ok(CowOpenPlan::Deleted) => OpenStep::Answer(NotifAction::Errno(libc::ENOENT)),
            Ok(CowOpenPlan::Resolved(p)) | Ok(CowOpenPlan::UpperReady { upper: p }) => {
                OpenStep::Open(p)
            }
            Ok(CowOpenPlan::Copy { rel_path, plan }) => OpenStep::Copy(rel_path, plan),
            Err(e) => OpenStep::Answer(NotifAction::Errno(branch_errno(e))),
        }
    }
}

/// An open the branch may redirect.
pub(crate) struct CowOpen {
    pub(crate) caller: Caller,
    pub(crate) layers: Layers,
    pub(crate) path: String,
    pub(crate) flags: u64,
    pub(crate) open_flags: i32,
    pub(crate) mode: u32,
    /// Chroot mode has no kernel open to fall back to after a copy.
    pub(crate) may_continue: bool,
}

impl CowOpen {
    /// The answer for this open, or `None` when the branch leaves it alone.
    pub(crate) fn run(
        self,
        cow_state: &Arc<Mutex<CowState>>,
        cow: &mut SeccompCowBranch,
    ) -> Option<NotifAction> {
        Some(
            match OpenStep::of(cow.prepare_open(&self.path, self.flags)) {
                OpenStep::Skip => return None,
                OpenStep::Answer(action) => action,
                OpenStep::Open(p) => self.inject(&p),
                OpenStep::Copy(rel, plan) => copy_up_off_loop(
                    cow_state,
                    self.caller,
                    self.layers.clone(),
                    CopyUp::Entry(rel.clone()),
                    vec![(rel, plan)],
                    |e| NotifAction::Errno(branch_errno(e)),
                    move |cow| self.reopen(cow),
                ),
            },
        )
    }

    fn reopen(self, cow: &mut SeccompCowBranch) -> NotifAction {
        match OpenStep::of(cow.prepare_open(&self.path, self.flags)) {
            OpenStep::Open(p) => self.inject(&p),
            OpenStep::Answer(action) => action,
            OpenStep::Skip if self.may_continue => NotifAction::Continue,
            OpenStep::Skip => NotifAction::Errno(libc::EIO),
            OpenStep::Copy(rel, plan) => {
                cow.abandon_copies([(rel, plan)]);
                NotifAction::Errno(libc::EIO)
            }
        }
    }

    fn inject(&self, real_path: &Path) -> NotifAction {
        let fd = match open_confined(
            &self.layers.upper,
            &self.layers.workdir,
            real_path,
            self.open_flags,
            self.mode,
        ) {
            Ok(fd) => fd,
            // The kernel cannot see the upper layer, so its answer would be wrong.
            Err(errno) => return NotifAction::Errno(errno),
        };
        // Preserve O_CLOEXEC from the original openat flags.
        let newfd_flags = if self.flags & libc::O_CLOEXEC as u64 != 0 {
            libc::O_CLOEXEC as u32
        } else {
            0
        };
        NotifAction::InjectFdSend {
            srcfd: unsafe { OwnedFd::from_raw_fd(fd) },
            newfd_flags,
        }
    }
}

/// Handle open/openat/openat2 under workdir: redirect to COW upper/lower.
pub(crate) async fn handle_cow_open(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let (dirfd, path_ptr, flags, mode) = match decode_open_args(notif, notif_fd) {
        Some(a) => (a.dirfd, a.path_ptr, a.flags, a.mode),
        None => return NotifAction::Continue,
    };

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    let virtual_cwd = if (dirfd as i32) == libc::AT_FDCWD && !Path::new(&rel_path).is_absolute() {
        current_virtual_cwd(processes, notif.pid).await
    } else {
        None
    };
    let mut path = resolve_at_path_with_virtual(notif, dirfd, &rel_path, virtual_cwd.as_deref());

    let mut st = cow_state.lock().await;
    let cow = match st.branch.as_mut() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    path = map_cow_upper_path(cow, &path);
    if !cow.matches(&path) {
        return NotifAction::Continue;
    }

    // Read-only opens don't need interception unless the file was
    // modified or deleted in the COW layer.
    const WRITE_FLAGS: u64 =
        (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) as u64;
    let is_write = flags & WRITE_FLAGS != 0;
    if !is_write && !cow.needs_read_intercept(&path) {
        return NotifAction::Continue;
    }

    let open = CowOpen {
        caller: Caller::of(notif, notif_fd),
        layers: Layers::of(cow),
        path,
        flags,
        // Strip O_EXCL — the COW layer already verified exclusivity. Keeping it
        // would fail because we may have just copied the file into upper.
        open_flags: (flags & !(libc::O_EXCL as u64)) as i32,
        // Honor the child's requested creation mode (masked to permission bits).
        // Hardcoding 0o666 dropped the execute bits, so a binary copied into the
        // workdir (e.g. `cp /bin/echo m`) landed in upper non-executable and
        // `./m` failed with EACCES. The kernel ignores mode unless O_CREAT is set.
        mode: (mode & 0o7777) as u32,
        may_continue: true,
    };
    open.run(cow_state, cow).unwrap_or(NotifAction::Continue)
}

// ============================================================
// Write operation handlers
// ============================================================

/// Parsed COW write operation with resolved paths and extracted arguments.
enum CowWriteOp {
    Unlink {
        path: String,
        is_dir: bool,
    },
    Mkdir {
        path: String,
    },
    Mknod {
        path: String,
        mode: u32,
        dev: u64,
    },
    Rename {
        old_path: String,
        new_path: String,
    },
    Symlink {
        target: String,
        linkpath: String,
    },
    Link {
        old_path: String,
        new_path: String,
    },
    Chmod {
        path: String,
        mode: u32,
        nofollow: bool,
    },
    Chown {
        path: String,
        uid: u32,
        gid: u32,
    },
    Truncate {
        path: String,
        length: i64,
    },
}

impl CowWriteOp {
    fn remap_upper_paths(&mut self, cow: &SeccompCowBranch) {
        match self {
            CowWriteOp::Unlink { path, .. }
            | CowWriteOp::Mkdir { path }
            | CowWriteOp::Mknod { path, .. }
            | CowWriteOp::Chmod { path, .. }
            | CowWriteOp::Chown { path, .. }
            | CowWriteOp::Truncate { path, .. } => {
                *path = map_cow_upper_path(cow, path);
            }
            CowWriteOp::Rename { old_path, new_path } | CowWriteOp::Link { old_path, new_path } => {
                *old_path = map_cow_upper_path(cow, old_path);
                *new_path = map_cow_upper_path(cow, new_path);
            }
            CowWriteOp::Symlink { linkpath, .. } => {
                *linkpath = map_cow_upper_path(cow, linkpath);
            }
        }
    }
}

/// Read and resolve a path argument. For *at syscalls, pass the dirfd arg index;
/// for legacy syscalls, pass None to use the raw path.
fn read_resolved(
    notif: &SeccompNotif,
    path_arg: usize,
    dirfd_arg: Option<usize>,
    notif_fd: RawFd,
    virtual_cwd: Option<&str>,
) -> Option<String> {
    let raw = read_path(notif, notif.data.args[path_arg], notif_fd)?;
    match dirfd_arg {
        Some(i) => Some(resolve_at_path_with_virtual(
            notif,
            notif.data.args[i] as i64,
            &raw,
            virtual_cwd,
        )),
        None => Some(resolve_at_path_with_virtual(
            notif,
            libc::AT_FDCWD as i64,
            &raw,
            virtual_cwd,
        )),
    }
}

/// Parse the syscall into a CowWriteOp, reading and resolving paths from child memory.
fn parse_cow_write(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    virtual_cwd: Option<&str>,
) -> Option<CowWriteOp> {
    let nr = notif.data.nr as i64;

    // *at variants (dirfd in args[0], path in args[1])
    if nr == libc::SYS_unlinkat {
        let path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let is_dir = (notif.data.args[2] & libc::AT_REMOVEDIR as u64) != 0;
        return Some(CowWriteOp::Unlink { path, is_dir });
    }
    if nr == libc::SYS_mkdirat {
        return Some(CowWriteOp::Mkdir {
            path: read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?,
        });
    }
    if nr == libc::SYS_mknodat {
        // mknodat(dirfd, pathname, mode, dev)
        return Some(CowWriteOp::Mknod {
            path: read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?,
            mode: notif.data.args[2] as u32,
            dev: notif.data.args[3],
        });
    }
    if nr == libc::SYS_renameat2 || Some(nr) == arch::sys_renameat() {
        let old_path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 3, Some(2), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Rename { old_path, new_path });
    }
    if nr == libc::SYS_symlinkat {
        // symlinkat(target, newdirfd, linkpath): target is raw, linkpath is resolved
        let target = read_path(notif, notif.data.args[0], notif_fd)?;
        let linkpath = read_resolved(notif, 2, Some(1), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Symlink { target, linkpath });
    }
    if nr == libc::SYS_linkat {
        let old_path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 3, Some(2), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Link { old_path, new_path });
    }
    if nr == libc::SYS_fchmodat || nr == arch::SYS_FCHMODAT2 {
        let path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        // fchmodat(2) itself carries no flags; libc handles them by issuing
        // fchmodat2 instead, which is what mkfifo -m and chmod -h reach.
        let nofollow =
            nr == arch::SYS_FCHMODAT2 && notif.data.args[3] & libc::AT_SYMLINK_NOFOLLOW as u64 != 0;
        return Some(CowWriteOp::Chmod {
            path,
            mode: (notif.data.args[2] & 0o7777) as u32,
            nofollow,
        });
    }
    if nr == libc::SYS_fchownat {
        let path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Chown {
            path,
            uid: notif.data.args[2] as u32,
            gid: notif.data.args[3] as u32,
        });
    }

    // Legacy variants (path in args[0], no dirfd)
    if Some(nr) == arch::sys_unlink() {
        return Some(CowWriteOp::Unlink {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
            is_dir: false,
        });
    }
    if Some(nr) == arch::sys_rmdir() {
        return Some(CowWriteOp::Unlink {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
            is_dir: true,
        });
    }
    if Some(nr) == arch::sys_mkdir() {
        return Some(CowWriteOp::Mkdir {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
        });
    }
    if Some(nr) == arch::sys_mknod() {
        // mknod(pathname, mode, dev)
        return Some(CowWriteOp::Mknod {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
            mode: notif.data.args[1] as u32,
            dev: notif.data.args[2],
        });
    }
    if Some(nr) == arch::sys_rename() {
        let old_path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 1, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Rename { old_path, new_path });
    }
    if Some(nr) == arch::sys_symlink() {
        let target = read_path(notif, notif.data.args[0], notif_fd)?;
        let linkpath = read_resolved(notif, 1, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Symlink { target, linkpath });
    }
    if Some(nr) == arch::sys_link() {
        let old_path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 1, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Link { old_path, new_path });
    }
    if Some(nr) == arch::sys_chmod() {
        let path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Chmod {
            path,
            mode: (notif.data.args[1] & 0o7777) as u32,
            nofollow: false,
        });
    }
    if Some(nr) == arch::sys_chown() || Some(nr) == arch::sys_lchown() {
        let path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Chown {
            path,
            uid: notif.data.args[1] as u32,
            gid: notif.data.args[2] as u32,
        });
    }

    // truncate (legacy only, path in args[0])
    if nr == libc::SYS_truncate {
        let path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Truncate {
            path,
            length: notif.data.args[1] as i64,
        });
    }

    None
}

/// Map a BranchError result to a NotifAction.
fn cow_result(r: Result<bool, BranchError>) -> NotifAction {
    match r {
        Ok(true) => NotifAction::ReturnValue(0),
        Ok(false) | Err(BranchError::NotOwned) => NotifAction::Continue,
        // Continue would let the kernel act on the lower entry, which the
        // branch promised to leave alone.
        Err(e) => NotifAction::Errno(branch_errno(e)),
    }
}

/// Map an errno-style handler result (unlink, rename) to a NotifAction.
fn unlink_result(r: Result<bool, i32>) -> NotifAction {
    match r {
        Ok(true) => NotifAction::ReturnValue(0),
        Err(errno) => NotifAction::Errno(errno),
        _ => NotifAction::Continue,
    }
}

impl CowWriteOp {
    /// What the branch must copy up before this write can run.
    fn copy_up(&self, cow: &SeccompCowBranch) -> CopyUp {
        let entry = |path: &str| cow.matches(path).then(|| cow.safe_rel(path)).flatten();
        let need = match self {
            CowWriteOp::Chmod { path, .. }
            | CowWriteOp::Chown { path, .. }
            | CowWriteOp::Truncate { path, .. } => entry(path).map(CopyUp::Entry),
            CowWriteOp::Rename { old_path, .. } => entry(old_path).map(|r| cow.rename_copy_up(r)),
            CowWriteOp::Link { old_path, new_path } if cow.matches(new_path) => {
                entry(old_path).map(|r| cow.link_copy_up(r))
            }
            _ => None,
        };
        need.unwrap_or(CopyUp::Nothing)
    }
}

/// How a write answers a copy-up the branch refused.
fn refuse_write_copy(names_entry: bool, e: BranchError) -> NotifAction {
    match e {
        BranchError::QuotaExceeded => NotifAction::Errno(libc::ENOSPC),
        // A kernel object: its metadata is the kernel's to change, but it
        // cannot be staged under a new name.
        BranchError::NotOwned if names_entry => NotifAction::Errno(libc::EXDEV),
        BranchError::NotOwned => NotifAction::Continue,
        e => NotifAction::Errno(branch_errno(e)),
    }
}

/// Handle all write-type syscalls: both *at variants (unlinkat, mkdirat, etc.)
/// and legacy variants (unlink, rmdir, mkdir, etc.).
pub(crate) async fn handle_cow_write(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let mut op = match parse_cow_write(notif, notif_fd, virtual_cwd.as_deref()) {
        Some(op) => op,
        None => return NotifAction::Continue,
    };

    let mut st = cow_state.lock().await;
    let cow = match st.branch.as_mut() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };
    op.remap_upper_paths(cow);
    if let CowWriteOp::Rename { old_path, new_path } = &op {
        // Refused before the copy, so a refused rename stages nothing.
        if cow.matches(old_path) {
            if let Err(errno) = cow.check_rename(old_path, new_path) {
                return NotifAction::Errno(errno);
            }
        }
    }
    let need = op.copy_up(cow);
    let names_entry = matches!(op, CowWriteOp::Rename { .. } | CowWriteOp::Link { .. });
    after_copy_up(
        cow_state,
        Caller::of(notif, notif_fd),
        cow,
        need,
        move |e| refuse_write_copy(names_entry, e),
        move |cow| apply_write(cow, &op),
    )
}

/// Run a write operation once any file it changes is in the upper.
fn apply_write(cow: &mut SeccompCowBranch, op: &CowWriteOp) -> NotifAction {
    match *op {
        CowWriteOp::Unlink { ref path, is_dir } => {
            if !cow.matches(path) {
                return NotifAction::Continue;
            }
            unlink_result(cow.handle_unlink(path, is_dir))
        }
        CowWriteOp::Mkdir { ref path } => {
            if !cow.matches(path) {
                return NotifAction::Continue;
            }
            cow_result(cow.handle_mkdir(path))
        }
        CowWriteOp::Mknod {
            ref path,
            mode,
            dev,
        } => {
            if !cow.matches(path) {
                return NotifAction::Continue;
            }
            cow_result(cow.handle_mknod(path, mode, dev))
        }
        CowWriteOp::Rename {
            ref old_path,
            ref new_path,
        } => {
            if !cow.matches(old_path) {
                return NotifAction::Continue;
            }
            unlink_result(cow.handle_rename(old_path, new_path))
        }
        CowWriteOp::Symlink {
            ref target,
            ref linkpath,
        } => {
            if !cow.matches(linkpath) {
                return NotifAction::Continue;
            }
            cow_result(cow.handle_symlink(target, linkpath))
        }
        CowWriteOp::Link {
            ref old_path,
            ref new_path,
        } => {
            // A hard link cannot be half staged. With one name inside the
            // branch and the other below it there is nothing to stage: linking
            // in would create the name in the workdir the branch promised to
            // leave untouched, and linking out would hand the child an alias
            // for the lower inode that survives an abort. EXDEV is what the
            // kernel says about a link that cannot span the two sides.
            if cow.matches(old_path) != cow.matches(new_path) {
                return NotifAction::Errno(libc::EXDEV);
            }
            if !cow.matches(new_path) {
                return NotifAction::Continue;
            }
            link_result(cow.handle_link(old_path, new_path))
        }
        CowWriteOp::Chmod {
            ref path,
            mode,
            nofollow,
        } => {
            if !cow.matches(path) {
                return NotifAction::Continue;
            }
            // Linux has no symlink modes: the kernel's answer for
            // AT_SYMLINK_NOFOLLOW on a symlink, given before the target is touched.
            if nofollow && cow.handle_stat(path).is_some_and(|p| p.is_symlink()) {
                return NotifAction::Errno(libc::EOPNOTSUPP);
            }
            cow_result(cow.handle_chmod(path, mode))
        }
        CowWriteOp::Chown { ref path, uid, gid } => {
            if !cow.matches(path) {
                return NotifAction::Continue;
            }
            cow_result(cow.handle_chown(path, uid, gid))
        }
        CowWriteOp::Truncate { ref path, length } => {
            if !cow.matches(path) {
                return NotifAction::Continue;
            }
            cow_result(cow.handle_truncate(path, length))
        }
    }
}

// ============================================================
// access() handler — fake W_OK for COW-managed paths
// ============================================================

/// Handle faccessat/faccessat2/access — return success for W_OK checks on
/// COW-managed paths so programs that pre-check write permissions (like dpkg)
/// don't fail before the COW layer can redirect their writes.
pub(crate) async fn handle_cow_access(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;

    // access(pathname, mode): args[0]=path, args[1]=mode
    // faccessat(dirfd, pathname, mode, flags): args[0]=dirfd, args[1]=path, args[2]=mode
    let (path, mode) = if Some(nr) == arch::sys_access() {
        let p = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => resolve_at_path_with_virtual(
                notif,
                libc::AT_FDCWD as i64,
                &p,
                virtual_cwd.as_deref(),
            ),
            None => return NotifAction::Continue,
        };
        (p, notif.data.args[1] as i32)
    } else {
        let dirfd = notif.data.args[0] as i64;
        let p = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref()),
            None => return NotifAction::Continue,
        };
        (p, notif.data.args[2] as i32)
    };

    // Only intercept W_OK checks
    if mode & libc::W_OK == 0 {
        return NotifAction::Continue;
    }

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    let path = map_cow_upper_path(cow, &path);
    if !cow.matches(&path) {
        return NotifAction::Continue;
    }

    // Path is under workdir and W_OK was requested — writes will be
    // redirected to the COW upper layer, so report success.
    // Check the path actually exists on the real filesystem.
    if std::path::Path::new(&path).exists() || cow.handle_stat(&path).is_some() {
        return NotifAction::ReturnValue(0);
    }

    NotifAction::Continue
}

// ============================================================
// utimensat handler
// ============================================================

/// Handle utimensat — resolve path to COW upper then set timestamps.
/// utimensat(dirfd, pathname, times, flags)
pub(crate) async fn handle_cow_utimensat(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let dirfd = notif.data.args[0] as i64;
    let path_ptr = notif.data.args[1];
    let times_ptr = notif.data.args[2];
    let flags = notif.data.args[3] as i32;

    if path_ptr == 0 {
        return NotifAction::Continue;
    }

    // The kernel faults on the times before it looks at the path, and a plan
    // given up afterwards would leave its copy reserved in the quota.
    let times = if times_ptr != 0 {
        match read_child_mem(notif_fd, notif.id, notif.pid, times_ptr, 32) {
            Ok(data) => {
                let mut ts: [libc::timespec; 2] = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), &mut ts as *mut _ as *mut u8, 32);
                }
                Some(ts)
            }
            Err(_) => return NotifAction::Errno(libc::EFAULT),
        }
    } else {
        None
    };
    let follow = (flags & libc::AT_SYMLINK_NOFOLLOW) == 0;

    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref()),
        None => return NotifAction::Continue,
    };

    let mut st = cow_state.lock().await;
    let cow = match st.branch.as_mut() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };
    let path = map_cow_upper_path(cow, &path);
    if !cow.matches(&path) {
        return NotifAction::Continue;
    }
    let Some(rel) = cow.safe_rel(&path) else {
        return NotifAction::Continue;
    };
    let layers = Layers::of(cow);
    let upper = layers.upper.join(&rel);
    after_copy_up(
        cow_state,
        Caller::of(notif, notif_fd),
        cow,
        CopyUp::Entry(rel),
        refuse_times_copy,
        move |_| set_times(&layers, &upper, times, follow),
    )
}

fn refuse_times_copy(e: BranchError) -> NotifAction {
    refuse_write_copy(false, e)
}

fn set_times(
    layers: &Layers,
    upper_path: &Path,
    times: Option<[libc::timespec; 2]>,
    follow: bool,
) -> NotifAction {
    let (root, rel) = match pick_root_rel(&layers.upper, &layers.workdir, upper_path) {
        Ok(v) => v,
        Err(e) => return NotifAction::Errno(e),
    };
    let times_raw = times
        .as_ref()
        .map(|t| t.as_ptr())
        .unwrap_or(std::ptr::null());
    if let Err(e) = crate::sys::fs::utimensat_in_root(root, &rel, times_raw, follow) {
        return NotifAction::Errno(e);
    }
    NotifAction::ReturnValue(0)
}

// ============================================================
// Read operation handlers (stat, readlink, getdents)
// ============================================================

/// Handle newfstatat / faccessat — resolve path then Continue to let kernel stat.
/// The trick: we rewrite the path pointer in child memory to point to the resolved path.
/// Actually, simpler: for stat, we do the stat ourselves and write the result.
pub(crate) async fn handle_cow_stat(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    // newfstatat(dirfd, pathname, statbuf, flags)
    // faccessat(dirfd, pathname, mode, flags)
    // stat/lstat(pathname, statbuf), access(pathname, mode)
    //
    // The legacy x86_64 variants carry the path in args[0] and have no
    // dirfd or flags. Parsing them with the at-variant layout reads the
    // statbuf pointer as the path, never matches the workdir, and falls
    // through to the kernel, which leaks whiteouted lower entries to any
    // static-libc child that emits legacy stat (same register-layout bug
    // handle_cow_open fixed for legacy open).
    let legacy = [arch::sys_stat(), arch::sys_lstat(), arch::sys_access()]
        .into_iter()
        .flatten()
        .any(|l| l == nr);
    let (dirfd, path_ptr) = if legacy {
        (libc::AT_FDCWD as i64, notif.data.args[0])
    } else {
        (notif.data.args[0] as i64, notif.data.args[1])
    };
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref()),
        None => return NotifAction::Continue,
    };

    let (real_path, upper_root, workdir_root) = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();
        let path = map_cow_upper_path(cow, &path);
        if !cow.has_changes() || !cow.matches(&path) || !cow.needs_read_intercept(&path) {
            return NotifAction::Continue;
        }
        let real = match cow.handle_stat(&path) {
            Some(p) => p,
            None => return NotifAction::Errno(libc::ENOENT),
        };
        (real, upper_root, workdir_root)
    };

    if nr == libc::SYS_faccessat
        || nr == crate::arch::SYS_FACCESSAT2
        || arch::sys_access() == Some(nr)
    {
        // Existence check, confined: lstat succeeds for any present entry
        // (including a dangling symlink), matching the prior semantics.
        let (root, rel) = match pick_root_rel(&upper_root, &workdir_root, &real_path) {
            Ok(v) => v,
            Err(_) => return NotifAction::Errno(libc::ENOENT),
        };
        if crate::sys::fs::statat_in_root(root, &rel, false).is_ok() {
            return NotifAction::ReturnValue(0);
        }
        return NotifAction::Errno(libc::ENOENT);
    }

    // newfstatat/stat/lstat — stat the resolved path (confined to its layer
    // root) and write the native libc layout back to the child. Do not
    // hand-pack struct stat; its layout is architecture-specific.
    let statbuf_addr = if legacy {
        notif.data.args[1]
    } else {
        notif.data.args[2]
    };
    let follow = if legacy {
        arch::sys_lstat() != Some(nr)
    } else {
        let flags = (notif.data.args[3] & 0xFFFF_FFFF) as i32;
        (flags & libc::AT_SYMLINK_NOFOLLOW) == 0
    };
    let (root, rel) = match pick_root_rel(&upper_root, &workdir_root, &real_path) {
        Ok(v) => v,
        Err(e) => return NotifAction::Errno(e),
    };
    let statbuf = match crate::sys::fs::statat_in_root(root, &rel, follow) {
        Ok(s) => s,
        Err(e) => return NotifAction::Errno(e),
    };
    let buf = unsafe {
        std::slice::from_raw_parts(
            &statbuf as *const libc::stat as *const u8,
            std::mem::size_of::<libc::stat>(),
        )
    };

    if write_child_mem(notif_fd, notif.id, notif.pid, statbuf_addr, buf).is_err() {
        return NotifAction::Continue;
    }

    NotifAction::ReturnValue(0)
}

/// Handle statx — resolve the path to upper/lower and run statx ourselves.
///
/// We cannot return Continue when the file exists: on Continue the kernel
/// re-runs statx against the original (un-redirected) path, which for a
/// COW-only file lives only in the upper layer and is invisible to the
/// kernel under the lower workdir → ENOENT. So mirror `handle_cow_stat`:
/// statx the resolved path in the supervisor and write the buffer back.
pub(crate) async fn handle_cow_statx(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    // statx(dirfd, pathname, flags, mask, statxbuf)
    let dirfd = notif.data.args[0] as i64;
    let flags = notif.data.args[2] as i32;
    let mask = notif.data.args[3] as u32;
    let statxbuf_addr = notif.data.args[4];

    // AT_EMPTY_PATH stats the dirfd itself, no path resolution needed.
    // The fd was already redirected at open time, so let the kernel handle it.
    if (flags & libc::AT_EMPTY_PATH) != 0 {
        return NotifAction::Continue;
    }

    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(p) if !p.is_empty() => {
            resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref())
        }
        _ => return NotifAction::Continue,
    };

    let (real_path, upper_root, workdir_root) = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();
        let path = map_cow_upper_path(cow, &path);
        if !cow.has_changes() || !cow.matches(&path) || !cow.needs_read_intercept(&path) {
            return NotifAction::Continue;
        }
        let real = match cow.handle_stat(&path) {
            Some(p) => p,
            None => return NotifAction::Errno(libc::ENOENT), // deleted or absent
        };
        (real, upper_root, workdir_root)
    };

    let (root, rel) = match pick_root_rel(&upper_root, &workdir_root, &real_path) {
        Ok(v) => v,
        Err(e) => return NotifAction::Errno(e),
    };
    let mut stx_buf = vec![0u8; 256]; // sizeof(struct statx)
    if let Err(e) = crate::sys::fs::statx_in_root(root, &rel, flags, mask, &mut stx_buf) {
        return NotifAction::Errno(e);
    }

    if write_child_mem(notif_fd, notif.id, notif.pid, statxbuf_addr, &stx_buf).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(0)
}

// ============================================================
// execve / execveat handler
// ============================================================

/// Handle execve/execveat under COW: when the binary resolves into the
/// upper layer (created or modified inside the workdir), open the upper
/// file and inject it as an fd, rewriting the path to /proc/self/fd/N so
/// the kernel execs the COW version.
///
/// Without this, execve resolves the original (un-redirected) path, which
/// for a COW-only binary lives only in upper and is invisible under the
/// lower workdir → ENOENT. Files resolving to the lower layer are
/// unmodified, so the kernel finds them at the original path and we leave
/// them alone.
pub(crate) async fn handle_cow_exec(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    // execve(path, argv, envp):              args[0]=path,  args[1]=argv, args[2]=envp
    // execveat(dirfd, path, argv, envp, ..): args[1]=path, args[2]=argv, args[3]=envp
    let (dirfd, path_ptr, argv_ptr, envp_ptr) = if nr == libc::SYS_execveat {
        (
            notif.data.args[0] as i64,
            notif.data.args[1],
            notif.data.args[2],
            notif.data.args[3],
        )
    } else {
        (
            libc::AT_FDCWD as i64,
            notif.data.args[0],
            notif.data.args[1],
            notif.data.args[2],
        )
    };

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };

    let virtual_cwd = if (dirfd as i32) == libc::AT_FDCWD && !Path::new(&rel_path).is_absolute() {
        current_virtual_cwd(processes, notif.pid).await
    } else {
        None
    };
    let resolved = resolve_at_path_with_virtual(notif, dirfd, &rel_path, virtual_cwd.as_deref());

    let (upper_path, upper_root, workdir_root) = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();
        let path = map_cow_upper_path(cow, &resolved);
        if !cow.has_changes() || !cow.matches(&path) || !cow.needs_read_intercept(&path) {
            return NotifAction::Continue;
        }
        let real = match cow.handle_stat(&path) {
            // Only redirect when the binary lives in the upper layer.
            Some(real) if real.starts_with(cow.upper_dir()) => real,
            // Lower-layer (unmodified) binary — kernel resolves it fine.
            Some(_) => return NotifAction::Continue,
            // Deleted in the COW layer (or absent) — must not exec the lower file.
            None => return NotifAction::Errno(libc::ENOENT),
        };
        (real, upper_root, workdir_root)
    };

    // Open the upper binary and inject the fd into the child.
    let src_fd = match open_confined(
        &upper_root,
        &workdir_root,
        &upper_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => fd,
        Err(_) => return NotifAction::Errno(libc::ENOENT),
    };

    let addfd = crate::sys::structs::SeccompNotifAddfd {
        id: notif.id,
        flags: 0,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags: 0, // no O_CLOEXEC — the kernel must read it at exec time
    };
    let child_fd = unsafe {
        libc::ioctl(
            notif_fd,
            crate::sys::structs::SECCOMP_IOCTL_NOTIF_ADDFD as libc::Ioctl,
            &addfd as *const _,
        )
    };
    unsafe { libc::close(src_fd) };

    if child_fd < 0 {
        return NotifAction::Errno(libc::EIO);
    }

    // Rewrite the path argument to /proc/self/fd/N so the kernel execs the
    // injected fd, relocating argv[0] when it aliases the path buffer (see
    // rewrite_exec_path_to_fd). Force-writes past read-only protections (a
    // .rodata exec path literal). No length guard: execve replaces the
    // address space on success, so a write past the original buffer is
    // harmless.
    if crate::seccomp::notif::rewrite_exec_path_to_fd(
        notif_fd, notif.id, notif.pid, path_ptr, argv_ptr, envp_ptr, child_fd,
    )
    .is_err()
    {
        return NotifAction::Errno(libc::EFAULT);
    }

    NotifAction::Continue
}

/// Handle readlinkat — read symlink from upper/lower, write to child buffer.
pub(crate) async fn handle_cow_readlink(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    // readlinkat(dirfd, pathname, buf, bufsiz), and legacy
    // readlink(pathname, buf, bufsiz), which shifts every argument by one.
    let a = notif.data.args;
    let (dirfd, path_ptr, buf_addr, bufsiz) = if arch::sys_readlink() == Some(notif.data.nr as i64)
    {
        (libc::AT_FDCWD as i64, a[0], a[1], a[2])
    } else {
        (a[0] as i64, a[1], a[2], a[3])
    };
    let bufsiz = (bufsiz & 0xFFFFFFFF) as usize;
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref()),
        None => return NotifAction::Continue,
    };

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    let path = map_cow_upper_path(cow, &path);
    if !cow.has_changes() || !cow.matches(&path) || !cow.needs_read_intercept(&path) {
        return NotifAction::Continue;
    }

    let target = match cow.handle_readlink(&path) {
        Some(t) => t,
        None => return NotifAction::Errno(libc::ENOENT),
    };
    drop(st);

    let target_bytes = target.as_bytes();
    let write_len = target_bytes.len().min(bufsiz);

    if write_child_mem(
        notif_fd,
        notif.id,
        notif.pid,
        buf_addr,
        &target_bytes[..write_len],
    )
    .is_err()
    {
        return NotifAction::Continue;
    }

    NotifAction::ReturnValue(write_len as i64)
}

/// Handle getdents64 for COW directories — merge upper + lower entries.
pub(crate) async fn handle_cow_getdents(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let pid = notif.pid;
    let child_fd = (notif.data.args[0] & 0xFFFFFFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFFFFFF) as usize;

    // Check if fd points to a COW-managed directory.
    let link_path = format!("/proc/{}/fd/{}", pid, child_fd);
    let target = match std::fs::read_link(&link_path) {
        Ok(t) => t.to_string_lossy().into_owned(),
        Err(_) => return NotifAction::Continue,
    };

    if crate::procfs::net::lookup(&crate::procfs::canon_proc_namespace(&target))
        != crate::procfs::net::NetEntry::Outside
    {
        return NotifAction::Continue;
    }

    // Compute rel_path under the global COW lock, but do not hold it
    // across the per-process lock acquired below.
    let rel_path = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        if !cow.has_changes() {
            return NotifAction::Continue;
        }
        let target_path = Path::new(&target);
        if cow.matches(&target) {
            cow.safe_rel(&target).unwrap_or_else(|| ".".to_string())
        } else if let Ok(rel) = target_path.strip_prefix(cow.upper_dir()) {
            let rel = rel.to_string_lossy();
            if rel.is_empty() {
                ".".to_string()
            } else {
                rel.into_owned()
            }
        } else {
            return NotifAction::Continue;
        }
    };

    // Per-process dir cache lookup.
    let pp = match pp_handle(processes, pid) {
        Some(h) => h,
        None => return NotifAction::Continue,
    };
    let mut perproc = pp.lock().await;

    // Invalidate stale cache (fd reused for a different directory),
    // and short-circuit EOF on a previously fully-drained entry.
    if let Some((cached_target, entries)) = perproc.cow_dir_cache.get(&child_fd) {
        if *cached_target != target {
            perproc.cow_dir_cache.remove(&child_fd);
        } else if entries.is_empty() {
            perproc.cow_dir_cache.remove(&child_fd);
            return NotifAction::ReturnValue(0);
        }
    }

    // Build cache on first call.
    if !perproc.cow_dir_cache.contains_key(&child_fd) {
        let entries = {
            let st = cow_state.lock().await;
            let cow = match st.branch.as_ref() {
                Some(c) => c,
                None => return NotifAction::Continue,
            };
            let merged = cow.list_merged_dir(&rel_path);
            let upper_dir = cow.upper_dir().join(&rel_path);
            let lower_dir = cow.workdir().join(&rel_path);

            let mut out = Vec::new();
            let mut d_off: i64 = 0;
            for name in &merged {
                d_off += 1;
                let upper_p = upper_dir.join(name);
                let lower_p = lower_dir.join(name);
                let check = if upper_p.exists() || upper_p.is_symlink() {
                    &upper_p
                } else {
                    &lower_p
                };
                let d_type = if check.is_dir() {
                    DT_DIR
                } else if check.is_symlink() {
                    DT_LNK
                } else {
                    DT_REG
                };
                use std::os::unix::fs::MetadataExt;
                let d_ino = std::fs::symlink_metadata(check)
                    .map(|m| m.ino())
                    .unwrap_or(0);
                if let Some(rec) = build_dirent64(d_ino, d_off, d_type, name) {
                    out.push(rec);
                }
            }
            out
        };
        perproc
            .cow_dir_cache
            .insert(child_fd, (target.clone(), entries));
    }

    let entries = match perproc.cow_dir_cache.get_mut(&child_fd) {
        Some((_, e)) => e,
        None => return NotifAction::Continue,
    };

    let mut result = Vec::new();
    let mut consumed = 0;
    for entry in entries.iter() {
        if result.len() + entry.len() > buf_size {
            break;
        }
        result.extend_from_slice(entry);
        consumed += 1;
    }

    if consumed > 0 {
        entries.drain(..consumed);
    }
    drop(perproc);

    if !result.is_empty() {
        if write_child_mem(notif_fd, notif.id, pid, buf_addr, &result).is_err() {
            return NotifAction::Continue;
        }
    }

    NotifAction::ReturnValue(result.len() as i64)
}

/// Handle chdir — redirect to COW upper directory if the target was created
/// by COW and doesn't exist on the real filesystem.
///
/// Opens the upper directory, injects the fd into the child, and rewrites
/// the path arg to /proc/self/fd/N so the kernel chdir succeeds.
pub(crate) async fn handle_cow_chdir(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let path_ptr = notif.data.args[0];
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    let orig_path_buf_len = path.len() + 1; // NUL-terminated size in child memory

    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let resolved =
        resolve_at_path_with_virtual(notif, libc::AT_FDCWD as i64, &path, virtual_cwd.as_deref());

    let (abs_path, upper_path, upper_root, workdir_root) = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();
        let abs_path = map_cow_upper_path(cow, &resolved);
        if !cow.matches(&abs_path) {
            return NotifAction::Continue;
        }
        let rel = match cow.safe_rel(&abs_path) {
            Some(r) => r,
            None => return NotifAction::Continue,
        };
        let upper_path = cow.upper_dir().join(&rel);
        (abs_path, upper_path, upper_root, workdir_root)
    };

    // If the directory exists on the real filesystem, let the kernel handle it.
    if std::path::Path::new(&abs_path).is_dir() {
        return NotifAction::Continue;
    }

    // Only intervene if the directory exists in the COW upper layer.
    if !upper_path.is_dir() {
        return NotifAction::Continue;
    }

    // Open the upper directory and inject fd into the child.
    let src_fd = match open_confined(
        &upper_root,
        &workdir_root,
        &upper_path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    ) {
        Ok(fd) => fd,
        Err(_) => return NotifAction::Errno(libc::ENOENT),
    };

    let addfd = crate::sys::structs::SeccompNotifAddfd {
        id: notif.id,
        flags: 0,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags: libc::O_CLOEXEC as u32,
    };
    let child_fd = unsafe {
        libc::ioctl(
            notif_fd,
            crate::sys::structs::SECCOMP_IOCTL_NOTIF_ADDFD as libc::Ioctl,
            &addfd as *const _,
        )
    };
    unsafe { libc::close(src_fd) };

    if child_fd < 0 {
        return NotifAction::Errno(libc::EIO);
    }

    // Rewrite the path argument to /proc/self/fd/N so the kernel chdir
    // follows the injected fd.  The original buffer at path_ptr must be
    // large enough — otherwise we'd corrupt adjacent child memory.
    let fd_path = format!("/proc/self/fd/{}\0", child_fd);
    if orig_path_buf_len < fd_path.len() {
        // Original path buffer too small for the rewrite.  The injected
        // fd has O_CLOEXEC so it will be cleaned up on exit/exec.
        return NotifAction::Errno(libc::ENOENT);
    }
    // Force-write past read-only protections (a .rodata chdir path literal).
    // The fit guard above keeps the redirect from overflowing the buffer.
    if write_child_mem_force(notif_fd, notif.id, notif.pid, path_ptr, fd_path.as_bytes()).is_err() {
        return NotifAction::Errno(libc::EFAULT);
    }

    // We insert the virtual cwd here, before returning Continue and
    // letting the kernel run the rewritten chdir. We can't observe
    // the kernel's verdict without polling, but at this point we've
    // verified upper_path is a directory, the addfd ioctl succeeded,
    // and write_child_mem rewrote the path argument — so a kernel
    // chdir to /proc/self/fd/N is essentially guaranteed. If it does
    // somehow fail, the per-child pidfd watcher will drop this entry
    // when the process exits, so the inconsistency is bounded by
    // process lifetime.
    if let Some(pp) = pp_handle(processes, notif.pid) {
        pp.lock().await.virtual_cwd = Some(abs_path);
    }

    NotifAction::Continue
}

/// Handle getcwd after chdir into a COW-only directory.
pub(crate) async fn handle_cow_getcwd(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    let buf_size = (notif.data.args[1] & 0xFFFF_FFFF) as usize;

    let cached_virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let virtual_cwd = if let Some(cwd) = cached_virtual_cwd {
        cwd
    } else {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let cwd = match std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
            Ok(c) => c,
            Err(_) => return NotifAction::Continue,
        };
        match cwd.strip_prefix(cow.upper_dir()) {
            Ok(rel) => cow.workdir().join(rel).to_string_lossy().into_owned(),
            Err(_) => return NotifAction::Continue,
        }
    };

    let cwd_bytes = virtual_cwd.as_bytes();
    if cwd_bytes.len() + 1 > buf_size {
        return NotifAction::Errno(libc::ERANGE);
    }

    let mut write_buf = cwd_bytes.to_vec();
    write_buf.push(0);

    if write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, &write_buf).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(write_buf.len() as i64)
}

#[cfg(test)]
mod confine_tests {
    use super::open_confined;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use tempfile::TempDir;

    fn read_fd_path(fd: i32) -> std::path::PathBuf {
        std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap()
    }

    #[test]
    fn serves_in_tree_file() {
        let upper = TempDir::new().unwrap();
        let lower = TempDir::new().unwrap();
        std::fs::write(lower.path().join("ok.txt"), "data").unwrap();
        let real = lower.path().join("ok.txt");
        match open_confined(upper.path(), lower.path(), &real, libc::O_RDONLY, 0) {
            Ok(fd) => {
                assert_eq!(
                    std::fs::read_to_string(format!("/proc/self/fd/{}", fd)).unwrap(),
                    "data"
                );
                unsafe { libc::close(fd) };
            }
            Err(libc::ENOSYS) => {}
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn blocks_final_component_symlink_escape() {
        let upper = TempDir::new().unwrap();
        let lower = TempDir::new().unwrap();
        // workdir/link -> /etc/passwd
        symlink("/etc/passwd", lower.path().join("link")).unwrap();
        let real = lower.path().join("link");
        match open_confined(upper.path(), lower.path(), &real, libc::O_RDONLY, 0) {
            // Confined: /etc/passwd resolves under <lower>/etc/passwd, absent.
            Err(libc::ENOENT) | Err(libc::ENOSYS) => {}
            Ok(fd) => {
                let resolved = read_fd_path(fd);
                unsafe { libc::close(fd) };
                assert!(
                    resolved.starts_with(lower.path()),
                    "escaped: {:?}",
                    resolved
                );
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn blocks_intermediate_component_symlink_escape() {
        let upper = TempDir::new().unwrap();
        let lower = TempDir::new().unwrap();
        // workdir/evil -> /etc, child opens evil/passwd
        symlink("/etc", lower.path().join("evil")).unwrap();
        let real = lower.path().join("evil/passwd");
        match open_confined(upper.path(), lower.path(), &real, libc::O_RDONLY, 0) {
            Err(libc::ENOENT) | Err(libc::ENOSYS) => {}
            Ok(fd) => {
                let resolved = read_fd_path(fd);
                unsafe { libc::close(fd) };
                assert!(
                    resolved.starts_with(lower.path()),
                    "escaped: {:?}",
                    resolved
                );
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn refuses_path_under_neither_root() {
        let upper = TempDir::new().unwrap();
        let lower = TempDir::new().unwrap();
        let real = Path::new("/etc/passwd");
        assert_eq!(
            open_confined(upper.path(), lower.path(), real, libc::O_RDONLY, 0),
            Err(libc::EACCES)
        );
    }
}

//! Exec relay: argv safety for policy-checked execs without stopping any task.
//!
//! The supervisor reads argv from the child, judges it, and continues the
//! execve; the kernel then copies argv from the same memory, which sibling
//! threads and CLONE_VM peers can rewrite in between. Instead of freezing
//! those tasks, an approved execve is redirected to `relay.c`: the kernel runs
//! it from a sealed memfd, and it execs the target with the argv the policy
//! saw, read from a trailer on its own image. See `relay.c` for the child side.
//!
//! The memfd is installed at a free fd K just below the child's soft
//! RLIMIT_NOFILE and the soft limit is then set to K until the relay runs:
//! no dup2, open, F_DUPFD, SCM_RIGHTS or pidfd_getfd in the sandbox can
//! place a different file at K, so the sibling that could rewrite argv
//! cannot swap the program either. The child's path is rewritten in place
//! to `/dev/fd/K`, kept short because the bytes after a short path are
//! often the argv pointer array, which cannot move.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_mem, read_exec_cstr, read_exec_ptr_array, rewrite_exec_path};
use crate::seccomp::state::read_tgid_of_tid;
use crate::sys::structs::{SeccompNotif, SeccompNotifAddfd, SECCOMP_ADDFD_FLAG_SETFD, SECCOMP_IOCTL_NOTIF_ADDFD};
use std::os::unix::io::RawFd;

/// The relay program, built by build.rs for the target and embedded so a
/// deployed library never depends on a file beside it.
pub(crate) const RELAY_ELF: &[u8] = include_bytes!(env!("EXEC_RELAY_PATH"));

/// Marks the config block in `RELAY_ELF`; the same bytes as relay.c's magic.
const CONFIG_MAGIC: u64 = 0x5359_414c_4552_4c53;
const CONFIG_LEN: usize = 32;

const TRAILER_MAGIC: u32 = 0x5245_4c41;
const TRAILER_VERSION: u32 = 1;
const HEADER_LEN: usize = 40;
pub(crate) const ARGS_MAX: usize = 2 << 20;
pub(crate) const ENTRIES_MAX: usize = 65536;

/// How the relay reaches the target once it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArgsMode {
    /// `execveat(dirfd, base)` after checking the directory's identity, so
    /// swapping a path component after the policy looked has no effect.
    Pinned = 0,
    /// `execve(full_path)`: scripts, whose interpreter re-opens the path
    /// anyway, and COW/chroot modes, whose exec handlers pin the target
    /// themselves against the single-threaded relay.
    ByPath = 1,
}

/// Everything the relay needs, serialized as the trailer on its image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExecArgs {
    pub mode: ArgsMode,
    pub dir_dev: u64,
    pub dir_ino: u64,
    pub dir: Vec<u8>,
    pub base: Vec<u8>,
    pub full_path: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
    pub envp: Vec<Vec<u8>>,
}

impl ExecArgs {
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        if self.argv.len() > ENTRIES_MAX || self.envp.len() > ENTRIES_MAX {
            return Err(io::Error::from_raw_os_error(libc::E2BIG));
        }
        let mut out = Vec::with_capacity(HEADER_LEN + 256);
        for v in [TRAILER_MAGIC, TRAILER_VERSION, self.mode as u32,
                  self.argv.len() as u32, self.envp.len() as u32, 0] {
            out.extend_from_slice(&v.to_ne_bytes());
        }
        out.extend_from_slice(&self.dir_dev.to_ne_bytes());
        out.extend_from_slice(&self.dir_ino.to_ne_bytes());
        let strings = [&self.dir, &self.base, &self.full_path]
            .into_iter()
            .chain(self.argv.iter())
            .chain(self.envp.iter());
        for s in strings {
            if s.contains(&0) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            out.extend_from_slice(s);
            out.push(0);
        }
        if out.len() > ARGS_MAX {
            return Err(io::Error::from_raw_os_error(libc::E2BIG));
        }
        Ok(out)
    }

    /// Mirror of relay.c's reader, kept so the tests pin the wire format.
    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        let u32_at = |i: usize| u32::from_ne_bytes(bytes[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
        if u32_at(0) != TRAILER_MAGIC || u32_at(4) != TRAILER_VERSION {
            return None;
        }
        let mode = match u32_at(8) {
            0 => ArgsMode::Pinned,
            1 => ArgsMode::ByPath,
            _ => return None,
        };
        let (argc, envc) = (u32_at(12) as usize, u32_at(16) as usize);
        let mut pos = HEADER_LEN;
        let mut next = || {
            let end = bytes[pos..].iter().position(|&b| b == 0)? + pos;
            let s = bytes[pos..end].to_vec();
            pos = end + 1;
            Some(s)
        };
        let dir = next()?;
        let base = next()?;
        let full_path = next()?;
        let argv = (0..argc).map(|_| next()).collect::<Option<Vec<_>>>()?;
        let envp = (0..envc).map(|_| next()).collect::<Option<Vec<_>>>()?;
        Some(Self { mode, dir_dev: u64_at(24), dir_ino: u64_at(32), dir, base, full_path, argv, envp })
    }
}

/// The relay image for one exec: `RELAY_ELF` with the config block pointing
/// at the trailer appended after it, to be read back through `fd`.
pub(crate) fn build_image(args: &ExecArgs, fd: i32) -> io::Result<Vec<u8>> {
    let trailer = args.encode()?;
    let mut image = RELAY_ELF.to_vec();
    let at = image
        .windows(8)
        .position(|w| w == CONFIG_MAGIC.to_ne_bytes())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "exec-relay image has no config block"))?;
    let trailer_off = image.len() as u64;
    let trailer_len = trailer.len() as u64;
    let block = &mut image[at..at + CONFIG_LEN];
    block[8..12].copy_from_slice(&(fd as u32).to_ne_bytes());
    block[16..24].copy_from_slice(&trailer_off.to_ne_bytes());
    block[24..32].copy_from_slice(&trailer_len.to_ne_bytes());
    image.extend_from_slice(&trailer);
    Ok(image)
}

// ============================================================
// Supervisor side
// ============================================================

/// One execve/execveat as the child issued it, read once from its memory.
/// This copy is what the policy judges and what the relay runs.
pub(crate) struct ExecRequest {
    pub path: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
    pub envp: Vec<Vec<u8>>,
    pub path_ptr: u64,
    pub argv_ptr: u64,
    pub envp_ptr: u64,
    /// The target as the policy event reports it: host path, or the virtual
    /// path under chroot.
    pub resolved: PathBuf,
}

impl ExecRequest {
    pub(crate) fn argv_strings(&self) -> Vec<String> {
        self.argv.iter().map(|a| String::from_utf8_lossy(a).into_owned()).collect()
    }
}

struct Hold {
    memfd_ident: (u64, u64),
    old_soft: u64,
}

/// Per-tgid record of a relay exec in flight, from commit until the relay's
/// own execve arrives (or the process shows up again without it).
#[derive(Default)]
pub struct RelayState {
    holds: Mutex<HashMap<i32, Hold>>,
}

impl RelayState {
    /// Whether `pid` is a running relay: a hold exists for its process and its
    /// exe is the memfd. Syscalls the relay makes between its two execs are
    /// mechanism, not application behaviour, and must not reach policy_fn.
    pub(crate) fn is_relay_task(&self, pid: i32) -> bool {
        let holds = self.holds.lock().unwrap();
        if holds.is_empty() {
            return false;
        }
        let tgid = read_tgid_of_tid(pid).unwrap_or(pid);
        match holds.get(&tgid) {
            Some(hold) => ident_of(Path::new(&format!("/proc/{pid}/exe"))) == Some(hold.memfd_ident),
            None => false,
        }
    }
}

pub(crate) enum Prepared {
    /// The relay's own execve: already judged, let the exec handlers run it.
    SecondExec,
    /// A fresh application exec, judged next and relayed on allow.
    First(PendingExec),
}

pub(crate) struct PendingExec {
    pub request: ExecRequest,
    args: ExecArgs,
    tgid: i32,
}

fn errno_of(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn ident_of(path: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

fn nofile_limits(pid: i32) -> io::Result<(u64, u64)> {
    let mut old = libc::rlimit64 { rlim_cur: 0, rlim_max: 0 };
    let r = unsafe { libc::prlimit64(pid, libc::RLIMIT_NOFILE, std::ptr::null(), &mut old) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((old.rlim_cur, old.rlim_max))
}

fn set_soft_nofile(pid: i32, soft: u64, hard: u64) -> io::Result<()> {
    let new = libc::rlimit64 { rlim_cur: soft, rlim_max: hard };
    let r = unsafe { libc::prlimit64(pid, libc::RLIMIT_NOFILE, &new, std::ptr::null_mut()) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Step one of a policy-checked exec: recognise the relay's own execve, or
/// read the request and resolve the target the way the kernel would, so a
/// target that cannot run fails the caller's execve with the kernel's errno
/// (execvp's PATH walk depends on ENOENT arriving here).
pub(crate) async fn prepare(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    ctx: &Arc<SupervisorCtx>,
) -> Result<Prepared, i32> {
    let pid = notif.pid as i32;
    let tgid = read_tgid_of_tid(pid).unwrap_or(pid);

    let hold = ctx.exec_relay.holds.lock().unwrap().remove(&tgid);
    if let Some(hold) = hold {
        let ours = ident_of(Path::new(&format!("/proc/{pid}/exe"))) == Some(hold.memfd_ident);
        if let Ok((_, hard)) = nofile_limits(tgid) {
            let _ = set_soft_nofile(tgid, hold.old_soft.min(hard), hard);
        }
        if ours {
            return Ok(Prepared::SecondExec);
        }
    }

    let request = read_request(notif, notif_fd)?;
    let (request, args) = resolve_target(notif, request, ctx).await?;
    Ok(Prepared::First(PendingExec { request, args, tgid }))
}

fn read_request(notif: &SeccompNotif, notif_fd: RawFd) -> Result<ExecRequest, i32> {
    let nr = notif.data.nr as i64;
    let a = &notif.data.args;
    let (path_ptr, argv_ptr, envp_ptr) = if nr == libc::SYS_execveat {
        (a[1], a[2], a[3])
    } else {
        (a[0], a[1], a[2])
    };
    let mut read = |addr: u64, len: usize| read_child_mem(notif_fd, notif.id, notif.pid, addr, len);
    let path = read_exec_cstr(&mut read, path_ptr).map_err(|_| libc::EFAULT)?;
    let mut strings = |base: u64| -> Result<Vec<Vec<u8>>, i32> {
        let ptrs = read_exec_ptr_array(&mut read, base).map_err(|_| libc::EFAULT)?;
        if ptrs.len() > ENTRIES_MAX {
            return Err(libc::E2BIG);
        }
        ptrs.iter()
            .map(|&p| read_exec_cstr(&mut read, p).map_err(|_| libc::E2BIG))
            .collect()
    };
    let argv = strings(argv_ptr)?;
    let envp = strings(envp_ptr)?;
    Ok(ExecRequest { path, argv, envp, path_ptr, argv_ptr, envp_ptr, resolved: PathBuf::new() })
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in path.components() {
        match c {
            std::path::Component::ParentDir => { out.pop(); }
            std::path::Component::Normal(n) => out.push(n),
            _ => {}
        }
    }
    out
}

/// The target as an absolute path in the child's view, from its cwd or the
/// execveat dirfd.
fn absolute_target(notif: &SeccompNotif, request: &ExecRequest, ctx: &SupervisorCtx) -> Result<PathBuf, i32> {
    let nr = notif.data.nr as i64;
    let (dirfd, flags) = if nr == libc::SYS_execveat {
        (notif.data.args[0] as i64 as i32, notif.data.args[4] as i32)
    } else {
        (libc::AT_FDCWD, 0)
    };
    let pid = notif.pid;
    let rel = Path::new(OsStr::from_bytes(&request.path));
    if request.path.is_empty() {
        if flags & libc::AT_EMPTY_PATH == 0 {
            return Err(libc::ENOENT);
        }
        let target = std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).map_err(|_| libc::EBADF)?;
        if !target.is_absolute() {
            return Err(libc::ENOENT);
        }
        return Ok(target);
    }
    if rel.is_absolute() {
        return Ok(normalize(rel));
    }
    let base = if dirfd == libc::AT_FDCWD {
        ctx.processes
            .virtual_cwd(pid as i32)
            .or_else(|| std::fs::read_link(format!("/proc/{pid}/cwd")).ok())
            .ok_or(libc::ENOENT)?
    } else {
        std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).map_err(|_| libc::EBADF)?
    };
    Ok(normalize(&base.join(rel)))
}

fn stat_errno(e: io::Error) -> i32 {
    match e.raw_os_error() {
        Some(n) if n == libc::ENOENT || n == libc::ENOTDIR || n == libc::ELOOP || n == libc::ENAMETOOLONG => n,
        _ => libc::EACCES,
    }
}

/// Check the target exists and may run, and decide how the relay reaches it.
async fn resolve_target(
    notif: &SeccompNotif,
    mut request: ExecRequest,
    ctx: &Arc<SupervisorCtx>,
) -> Result<(ExecRequest, ExecArgs), i32> {
    let target = absolute_target(notif, &request, ctx)?;
    let policy = &ctx.policy;
    let bytes = |p: &Path| p.as_os_str().as_bytes().to_vec();
    let by_path = |host: &Path, reported: PathBuf, request: &mut ExecRequest| {
        request.resolved = reported;
        ExecArgs {
            mode: ArgsMode::ByPath,
            dir_dev: 0,
            dir_ino: 0,
            dir: Vec::new(),
            base: Vec::new(),
            full_path: bytes(host),
            argv: request.argv.clone(),
            envp: request.envp.clone(),
        }
    };

    if let Some(root) = policy.chroot_root.as_deref() {
        let host = crate::sandbox::resolve_sandbox_path_to_host(&target, Some(root), &policy.chroot_mounts);
        std::fs::metadata(&host).map_err(stat_errno)?;
        // The chroot exec handler resolves the virtual path itself when the
        // relay execs it, so the relay hands it the path the child used.
        let args = by_path(&target, target.clone(), &mut request);
        return Ok((request, args));
    }

    let host = {
        let st = ctx.cow.lock().await;
        match st.branch.as_ref() {
            Some(cow) if cow.has_changes() => {
                let upper = crate::cow::dispatch::map_cow_upper_path(cow, &target.to_string_lossy());
                if cow.matches(&upper) {
                    match cow.handle_stat(&upper) {
                        Some(real) => Some(real),
                        None => return Err(libc::ENOENT),
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    };
    if let Some(real) = host {
        std::fs::metadata(&real).map_err(stat_errno)?;
        let args = by_path(&target, target.clone(), &mut request);
        return Ok((request, args));
    }

    let meta = std::fs::metadata(&target).map_err(stat_errno)?;
    if !meta.is_file() {
        return Err(libc::EACCES);
    }
    let c_target = std::ffi::CString::new(bytes(&target)).map_err(|_| libc::EINVAL)?;
    let executable = unsafe { libc::faccessat(libc::AT_FDCWD, c_target.as_ptr(), libc::X_OK, libc::AT_EACCESS) } == 0;
    if !executable {
        return Err(libc::EACCES);
    }
    let mut head = [0u8; 2];
    let is_script = std::fs::File::open(&target)
        .and_then(|mut f| { use std::io::Read; f.read(&mut head) })
        .map(|n| n == 2 && &head == b"#!")
        .unwrap_or(false);
    if is_script {
        let args = by_path(&target, target.clone(), &mut request);
        return Ok((request, args));
    }
    let dir = target.parent().ok_or(libc::ENOENT)?;
    let (dir_dev, dir_ino) = ident_of(dir).ok_or(libc::ENOENT)?;
    request.resolved = target.clone();
    let args = ExecArgs {
        mode: ArgsMode::Pinned,
        dir_dev,
        dir_ino,
        dir: bytes(dir),
        base: bytes(Path::new(target.file_name().ok_or(libc::ENOENT)?)),
        full_path: bytes(&target),
        argv: request.argv.clone(),
        envp: request.envp.clone(),
    };
    Ok((request, args))
}

/// `/dev/fd` when the host has it (a symlink to /proc/self/fd), for the
/// shorter rewrite; else the procfs path.
fn fd_dir() -> &'static str {
    static DIR: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        if std::fs::read_link("/dev/fd").is_ok() { "/dev/fd" } else { "/proc/self/fd" }
    })
}

fn sealed_memfd(image: &[u8]) -> io::Result<OwnedFd> {
    let fd = crate::sys::syscall::memfd_create(
        "sandlock-exec-relay",
        (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as u32,
    )?;
    {
        use std::io::Write;
        let mut file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) });
        file.write_all(image)?;
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Step two, after the policy allowed: install the relay at a pinned fd and
/// point the child's execve at it.
pub(crate) fn commit(pending: PendingExec, notif: &SeccompNotif, notif_fd: RawFd, ctx: &Arc<SupervisorCtx>) -> Result<(), i32> {
    let pid = notif.pid as i32;
    let PendingExec { request, args, tgid } = pending;
    let (soft, hard) = nofile_limits(tgid).map_err(|e| errno_of(&e))?;
    // Seven digits keep "/dev/fd/K" within 16 bytes; a free slot just below
    // the soft limit is almost never in use.
    let top = soft.min(hard).min(10_000_000);
    if top < 32 {
        return Err(libc::EAGAIN);
    }
    let k = (top - 16..top)
        .rev()
        .find(|k| std::fs::symlink_metadata(format!("/proc/{pid}/fd/{k}")).is_err())
        .ok_or(libc::EAGAIN)?;
    let k_link = format!("/proc/{pid}/fd/{k}");
    let image = build_image(&args, k as i32).map_err(|e| errno_of(&e))?;
    let memfd = sealed_memfd(&image).map_err(|e| errno_of(&e))?;
    let ident = std::fs::metadata(format!("/proc/self/fd/{}", memfd.as_raw_fd()))
        .map(|m| (m.dev(), m.ino()))
        .map_err(|e| errno_of(&e))?;

    let restore = || { let _ = set_soft_nofile(tgid, soft, hard); };
    let addfd = SeccompNotifAddfd {
        id: notif.id,
        flags: SECCOMP_ADDFD_FLAG_SETFD,
        srcfd: memfd.as_raw_fd() as u32,
        newfd: k as u32,
        newfd_flags: 0,
    };
    let installed = unsafe { libc::ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ADDFD as libc::Ioctl, &addfd as *const _) };
    if installed < 0 {
        restore();
        return Err(libc::EAGAIN);
    }
    if let Err(e) = set_soft_nofile(tgid, k, hard) {
        restore();
        return Err(errno_of(&e));
    }
    // Nothing in the sandbox can change fd K from here on, so this check
    // settles what the kernel will open.
    if ident_of(Path::new(&k_link)) != Some(ident) {
        restore();
        return Err(libc::EAGAIN);
    }
    let new_path = format!("{}/{k}\0", fd_dir());
    if rewrite_exec_path(
        notif_fd, notif.id, notif.pid, request.path_ptr, request.argv_ptr, request.envp_ptr, new_path.as_bytes(),
    ).is_err() {
        restore();
        return Err(libc::EFAULT);
    }
    ctx.exec_relay.holds.lock().unwrap().insert(tgid, Hold { memfd_ident: ident, old_soft: soft });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(mode: ArgsMode) -> ExecArgs {
        ExecArgs {
            mode,
            dir_dev: 0x1234,
            dir_ino: 0x5678,
            dir: b"/usr/bin".to_vec(),
            base: b"echo".to_vec(),
            full_path: b"/usr/bin/echo".to_vec(),
            argv: vec![b"echo".to_vec(), b"hello world".to_vec(), Vec::new()],
            envp: vec![b"PATH=/usr/bin".to_vec()],
        }
    }

    #[test]
    fn trailer_roundtrips_both_modes() {
        for mode in [ArgsMode::Pinned, ArgsMode::ByPath] {
            let args = sample(mode);
            assert_eq!(ExecArgs::decode(&args.encode().unwrap()), Some(args));
        }
    }

    #[test]
    fn decode_rejects_bad_magic_and_truncation() {
        let mut bytes = sample(ArgsMode::Pinned).encode().unwrap();
        assert!(ExecArgs::decode(&bytes[..bytes.len() - 1]).is_none());
        bytes[0] ^= 1;
        assert!(ExecArgs::decode(&bytes).is_none());
    }

    #[test]
    fn encode_rejects_embedded_nul_and_too_many_entries() {
        let mut args = sample(ArgsMode::Pinned);
        args.argv.push(b"a\0b".to_vec());
        assert_eq!(args.encode().unwrap_err().raw_os_error(), Some(libc::EINVAL));
        let mut args = sample(ArgsMode::Pinned);
        args.envp = vec![Vec::new(); ENTRIES_MAX + 1];
        assert_eq!(args.encode().unwrap_err().raw_os_error(), Some(libc::E2BIG));
    }

    #[test]
    fn build_image_patches_the_config_block_and_appends_the_trailer() {
        let args = sample(ArgsMode::ByPath);
        let image = build_image(&args, 1023).unwrap();
        assert_eq!(&image[..4], b"\x7fELF");
        let at = image.windows(8).position(|w| w == CONFIG_MAGIC.to_ne_bytes()).unwrap();
        let block = &image[at..at + CONFIG_LEN];
        assert_eq!(u32::from_ne_bytes(block[8..12].try_into().unwrap()), 1023);
        let off = u64::from_ne_bytes(block[16..24].try_into().unwrap()) as usize;
        let len = u64::from_ne_bytes(block[24..32].try_into().unwrap()) as usize;
        assert_eq!(off, RELAY_ELF.len());
        assert_eq!(ExecArgs::decode(&image[off..off + len]), Some(args));
        assert_eq!(RELAY_ELF.windows(8).filter(|w| *w == CONFIG_MAGIC.to_ne_bytes()).count(), 1);
    }

    #[test]
    fn normalize_collapses_dots_and_parents() {
        assert_eq!(normalize(Path::new("/usr/./bin/../bin/echo")), PathBuf::from("/usr/bin/echo"));
        assert_eq!(normalize(Path::new("/../x")), PathBuf::from("/x"));
    }
}

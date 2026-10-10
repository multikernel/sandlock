//! Path metadata calls are answered from an object pinned on the caller's
//! behalf, so no alias or racing swap reaches what the open handlers hide.

use std::ffi::CString;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;

use super::{net_metadata, resolve_to_normalized_absolute};
use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_cstr, write_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Stat,
    Statx,
    Access,
    Readlink,
}

pub(super) struct Request {
    pub(super) operation: Operation,
    pub(super) dirfd: i64,
    pub(super) path: u64,
    pub(super) output: u64,
    pub(super) flags: u32,
    pub(super) mode: u32,
    pub(super) size: u64,
}

impl Request {
    pub(super) fn decode(notif: &SeccompNotif) -> Option<Self> {
        let nr = notif.data.nr as i64;
        let a = notif.data.args;
        let mut request = Self {
            operation: Operation::Stat,
            dirfd: a[0] as i64,
            path: a[1],
            output: a[2],
            flags: 0,
            mode: 0,
            size: 0,
        };
        if nr == libc::SYS_fstat {
            request.path = 0;
            request.output = a[1];
            request.flags = libc::AT_EMPTY_PATH as u32;
        } else if nr == libc::SYS_newfstatat {
            request.flags = a[3] as u32;
        } else if nr == libc::SYS_statx {
            request.operation = Operation::Statx;
            request.flags = a[2] as u32;
            request.mode = a[3] as u32;
            request.output = a[4];
        } else if nr == libc::SYS_faccessat || nr == crate::arch::SYS_FACCESSAT2 {
            request.operation = Operation::Access;
            request.mode = a[2] as u32;
            if nr == crate::arch::SYS_FACCESSAT2 {
                request.flags = a[3] as u32;
            }
        } else if nr == libc::SYS_readlinkat {
            request.operation = Operation::Readlink;
            request.flags = libc::AT_SYMLINK_NOFOLLOW as u32;
            request.size = a[3];
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                request.dirfd = libc::AT_FDCWD as i64;
                request.path = a[0];
                request.output = a[1];
                if nr == libc::SYS_lstat {
                    request.flags = libc::AT_SYMLINK_NOFOLLOW as u32;
                } else if nr == libc::SYS_access {
                    request.operation = Operation::Access;
                    request.mode = a[1] as u32;
                } else if nr == libc::SYS_readlink {
                    request.operation = Operation::Readlink;
                    request.flags = libc::AT_SYMLINK_NOFOLLOW as u32;
                    request.size = a[2];
                } else if nr != libc::SYS_stat {
                    return None;
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            return None;
        }
        Some(request)
    }
}

pub(super) fn write_result<T>(
    value: &T,
    output: u64,
    notif: &SeccompNotif,
    notif_fd: RawFd,
) -> NotifAction {
    let bytes = unsafe {
        std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
    };
    match write_child_mem(notif_fd, notif.id, notif.pid, output, bytes) {
        Ok(_) => NotifAction::ReturnValue(0),
        Err(_) => NotifAction::Errno(libc::EFAULT),
    }
}

pub(super) fn errno_action() -> NotifAction {
    NotifAction::Errno(
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

pub(super) fn probe_metadata(
    path: &str,
    dirfd: i64,
    pid: u32,
    follow: bool,
) -> Result<OwnedFd, i32> {
    let base = if Path::new(path).is_absolute() {
        None
    } else {
        Some(crate::seccomp::notif::open_base_dir(pid, dirfd)?)
    };
    let path = CString::new(path).map_err(|_| libc::EINVAL)?;
    crate::seccomp::notif::openat2_at(
        base.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd),
        &path,
        (libc::O_PATH | libc::O_CLOEXEC | if follow { 0 } else { libc::O_NOFOLLOW }) as u64,
        0,
        crate::seccomp::notif::RESOLVE_NO_MAGICLINKS,
    )
}

fn task_link(entry: &str) -> Option<(&str, &str)> {
    let (link, tail) = entry.split_once('/').unwrap_or((entry, ""));
    matches!(link, "cwd" | "exe" | "root").then_some((link, tail.trim_start_matches('/')))
}

// The task's own link is followed as the kernel would; the rest of the path
// still may not cross another magic link.
fn probe_through_task_link(pid: i32, link: &str, tail: &str, follow: bool) -> Result<OwnedFd, i32> {
    let nofollow = |last: bool| if last && !follow { libc::O_NOFOLLOW } else { 0 };
    let target = CString::new(format!("/proc/{pid}/{link}")).unwrap();
    let base = crate::seccomp::notif::openat2_at(
        libc::AT_FDCWD,
        &target,
        (libc::O_PATH | libc::O_CLOEXEC | nofollow(tail.is_empty())) as u64,
        0,
        0,
    )?;
    if tail.is_empty() {
        return Ok(base);
    }
    let tail = CString::new(tail).map_err(|_| libc::EINVAL)?;
    crate::seccomp::notif::openat2_at(
        base.as_raw_fd(),
        &tail,
        (libc::O_PATH | libc::O_CLOEXEC | nofollow(true)) as u64,
        0,
        crate::seccomp::notif::RESOLVE_NO_MAGICLINKS,
    )
}

// Walks the /proc/<task>/ prefix as the kernel would and leaves the entry,
// and everything after it, as spelled.
fn proc_task_entry(path: &str, caller_tid: i32, caller_tgid: i32) -> Option<(i32, i32, &str)> {
    let mut prefix = Vec::new();
    let mut rest = path.strip_prefix('/')?;
    let (task, thread, entry) = loop {
        let (component, tail) = rest.split_once('/').unwrap_or((rest, ""));
        match (prefix.as_slice(), component) {
            (_, "" | ".") => {}
            (_, "..") => {
                prefix.pop();
            }
            (["proc", task], entry) if entry != "task" => break (*task, None, rest),
            (["proc", task, "task", tid], _) => break (*task, Some(*tid), rest),
            _ => prefix.push(component),
        }
        if tail.is_empty() {
            return None;
        }
        rest = tail;
    };
    let positive = |id: &str| id.parse::<i32>().ok().filter(|id| *id > 0);
    let parent = match task {
        "self" | "thread-self" => caller_tgid,
        _ => positive(task)?,
    };
    let pid = match thread {
        Some(tid) => positive(tid)?,
        None if task == "thread-self" => caller_tid,
        None => parent,
    };
    Some((parent, pid, entry))
}

pub(crate) async fn handle_pinned_metadata(
    notif: &SeccompNotif,
    ctx: &SupervisorCtx,
    notif_fd: RawFd,
) -> NotifAction {
    let Some(request) = Request::decode(notif) else {
        return NotifAction::Continue;
    };
    if notif.data.nr as i64 == libc::SYS_fstat && (request.dirfd as i32) < 0 {
        return NotifAction::Errno(libc::EBADF);
    }
    let path = match read_child_cstr(notif_fd, notif.id, notif.pid, request.path, 4096) {
        Some(path) => path,
        None if request.path == 0
            && request.flags & libc::AT_EMPTY_PATH as u32 != 0
            && matches!(request.operation, Operation::Stat | Operation::Statx) =>
        {
            String::new()
        }
        None => return NotifAction::Errno(libc::EFAULT),
    };
    if ctx.policy.chroot_root.is_some()
        && (!path.is_empty() || request.flags & libc::AT_EMPTY_PATH as u32 == 0)
    {
        return NotifAction::Continue;
    }
    let requires_directory = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    let follow = request.flags & libc::AT_SYMLINK_NOFOLLOW as u32 == 0 || requires_directory;
    let absolute =
        resolve_to_normalized_absolute(notif.pid, request.dirfd, &path, None, &[], &ctx.processes);
    let tgid = ctx
        .processes
        .tgid_of(notif.pid as i32)
        .unwrap_or(notif.pid as i32);
    let joined = super::joined_absolute(notif.pid, request.dirfd, &path, None, &[], &ctx.processes);
    let task_entry = joined
        .as_deref()
        .and_then(Path::to_str)
        .and_then(|joined| proc_task_entry(joined, notif.pid as i32, tgid))
        .filter(|(parent, pid, _)| {
            ctx.processes.contains(*parent)
                && ctx.processes.contains(*pid)
                && (*parent == *pid || ctx.processes.tgid_of(*pid) == Some(*parent))
        });
    let held_fd = if path.is_empty() {
        if request.flags & libc::AT_EMPTY_PATH as u32 == 0
            && !matches!(request.operation, Operation::Readlink)
        {
            return NotifAction::Errno(libc::ENOENT);
        }
        Some((notif.pid, request.dirfd as i32))
    } else if follow {
        absolute
            .as_deref()
            .and_then(Path::to_str)
            .and_then(|p| super::own_fd_request(p, notif.pid as i32, tgid))
            .map(|fd| (notif.pid, fd))
            .or_else(|| {
                let (_, pid, entry) = task_entry?;
                let fd = entry.strip_prefix("fd/")?;
                if !fd.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                Some((pid as u32, fd.parse::<i32>().ok()?))
            })
    } else {
        None
    };
    let mut translated = path.clone();
    for (prefix, target) in [
        ("/proc/self/", format!("/proc/{tgid}/")),
        (
            "/proc/thread-self/",
            format!("/proc/{tgid}/task/{}/", notif.pid),
        ),
    ] {
        if let Some(rest) = path.strip_prefix(prefix) {
            translated = format!("{target}{rest}");
            break;
        }
    }
    let probe = match held_fd {
        Some((pid, fd)) => crate::seccomp::notif::open_base_dir(pid, fd as i64),
        None => match task_entry.and_then(|(_, pid, entry)| Some((pid, task_link(entry)?))) {
            Some((pid, (link, tail))) => probe_through_task_link(pid, link, tail, follow),
            None => probe_metadata(&translated, request.dirfd, notif.pid, follow),
        },
    };
    let mut fd = match probe {
        Ok(fd) => fd,
        Err(errno) => return NotifAction::Errno(errno),
    };
    let mut real = match std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
        Ok(real) => real,
        Err(_) => return errno_action(),
    };
    if held_fd.is_none() {
        if let Some(reprobe) = crate::seccomp::notif::reprobe_in_callers_proc(
            &real,
            notif.pid,
            !follow,
            &ctx.processes,
        ) {
            match reprobe {
                Ok((callers, path)) => {
                    fd = callers;
                    real = path;
                }
                Err(errno) => return NotifAction::Errno(errno),
            }
        }
    }
    let resolved = real.to_string_lossy();
    if let Some(action) = net_metadata::serve_pinned(
        &request,
        &fd,
        &resolved,
        absolute.as_deref().and_then(Path::to_str).unwrap_or(&path),
        !path.is_empty(),
        requires_directory,
        follow,
        notif,
        ctx,
        notif_fd,
    )
    .await
    {
        return action;
    }
    let empty = c"";
    match request.operation {
        Operation::Stat => {
            if request.flags
                & !(libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT) as u32
                != 0
            {
                return NotifAction::Errno(libc::EINVAL);
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
                return errno_action();
            }
            write_result(&st, request.output, notif, notif_fd)
        }
        Operation::Statx => {
            let mut st: libc::statx = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::statx(
                    fd.as_raw_fd(),
                    empty.as_ptr(),
                    request.flags as i32 | libc::AT_EMPTY_PATH,
                    request.mode,
                    &mut st,
                )
            } < 0
            {
                return errno_action();
            }
            write_result(&st, request.output, notif, notif_fd)
        }
        Operation::Access => {
            if unsafe {
                libc::syscall(
                    crate::arch::SYS_FACCESSAT2,
                    fd.as_raw_fd(),
                    empty.as_ptr(),
                    request.mode,
                    request.flags as i32 | libc::AT_EMPTY_PATH,
                )
            } < 0
            {
                return errno_action();
            }
            NotifAction::ReturnValue(0)
        }
        Operation::Readlink => {
            if request.size == 0 || request.size > i32::MAX as u64 {
                return NotifAction::Errno(libc::EINVAL);
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
                return errno_action();
            }
            if !path.is_empty() && st.st_mode & libc::S_IFMT != libc::S_IFLNK {
                return NotifAction::Errno(libc::EINVAL);
            }
            let mut target = vec![0u8; (request.size as usize).min(4096)];
            let count = unsafe {
                libc::readlinkat(
                    fd.as_raw_fd(),
                    empty.as_ptr(),
                    target.as_mut_ptr().cast(),
                    target.len(),
                )
            };
            if count < 0 {
                return errno_action();
            }
            if resolved == "/proc/self" {
                target = tgid.to_string().into_bytes();
            } else if resolved == "/proc/thread-self" {
                target = format!("{tgid}/task/{}", notif.pid).into_bytes();
            } else {
                target.truncate(count as usize);
            }
            target.truncate(request.size as usize);
            if write_child_mem(notif_fd, notif.id, notif.pid, request.output, &target).is_err() {
                return NotifAction::Errno(libc::EFAULT);
            }
            NotifAction::ReturnValue(target.len() as i64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_task_entries_keep_peer_identity() {
        assert_eq!(
            proc_task_entry("/proc/42/fd/1", 9, 8),
            Some((42, 42, "fd/1"))
        );
        assert_eq!(
            proc_task_entry("/proc/42/task/43/fd/1", 9, 8),
            Some((42, 43, "fd/1"))
        );
        assert_eq!(
            proc_task_entry("/proc/thread-self/cwd", 9, 8),
            Some((8, 9, "cwd"))
        );
        assert_eq!(
            proc_task_entry("/proc/self/task/9/exe", 9, 8),
            Some((8, 9, "exe"))
        );
        assert_eq!(proc_task_entry("/proc/-1/fd/1", 9, 8), None);
        assert_eq!(
            proc_task_entry("/proc//self/./exe", 9, 8),
            Some((8, 8, "exe"))
        );
        assert_eq!(
            proc_task_entry("/proc/42/task/43/../../fd/1", 9, 8),
            Some((42, 42, "fd/1"))
        );
        assert_eq!(
            proc_task_entry("/proc/self/cwd/a/../b/", 9, 8),
            Some((8, 8, "cwd/a/../b/"))
        );
        assert_eq!(proc_task_entry("/proc/self/", 9, 8), None);
    }
}

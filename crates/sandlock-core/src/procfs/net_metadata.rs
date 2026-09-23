use std::ffi::CString;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use super::{canon_proc_namespace, net, resolve_to_normalized_absolute};
use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_cstr, write_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;

#[derive(Clone, Copy)]
enum Operation {
    Stat,
    Statx,
    Access,
    Readlink,
}

struct Request {
    operation: Operation,
    dirfd: i64,
    path: u64,
    output: u64,
    flags: u32,
    mode: u32,
    size: u64,
}

impl Request {
    fn decode(notif: &SeccompNotif) -> Option<Self> {
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

fn host_path(path: &Path, ctx: &SupervisorCtx) -> PathBuf {
    if let Some((virtual_path, host)) = ctx
        .policy
        .chroot_mounts
        .iter()
        .filter(|(virtual_path, _)| path.starts_with(virtual_path))
        .max_by_key(|(virtual_path, _)| virtual_path.components().count())
    {
        return host.join(path.strip_prefix(virtual_path).unwrap());
    }
    match &ctx.policy.chroot_root {
        Some(root) => root.join(path.strip_prefix("/").unwrap_or(path)),
        None => path.to_path_buf(),
    }
}

pub(super) fn net_path(
    mut path: PathBuf,
    follow: bool,
    notif: &SeccompNotif,
    ctx: &SupervisorCtx,
) -> Option<PathBuf> {
    for _ in 0..40 {
        if net::lookup(&canon_proc_namespace(path.to_str()?)) != net::NetEntry::Outside {
            return Some(path);
        }
        let mapped = host_path(&path, ctx);
        let canonical = canon_proc_namespace(mapped.to_str()?);
        if net::lookup(&canonical) != net::NetEntry::Outside {
            return Some(PathBuf::from(canonical.as_ref()));
        }
        let components: Vec<_> = path.components().collect();
        let mut prefix = PathBuf::new();
        let mut replaced = false;
        for (index, component) in components.iter().enumerate() {
            prefix.push(component.as_os_str());
            if !follow && index + 1 == components.len() {
                break;
            }
            let Ok(target) = std::fs::read_link(host_path(&prefix, ctx)) else {
                continue;
            };
            let mut replacement = if target.is_absolute() {
                target
            } else {
                prefix.parent()?.join(target)
            };
            for tail in &components[index + 1..] {
                replacement.push(tail.as_os_str());
            }
            path = resolve_to_normalized_absolute(
                notif.pid,
                libc::AT_FDCWD as i64,
                replacement.to_str()?,
                ctx.policy.chroot_root.as_deref(),
                &ctx.policy.chroot_mounts,
                &ctx.processes,
            )?;
            replaced = true;
            break;
        }
        if !replaced {
            return None;
        }
    }
    None
}

fn metadata(entry: net::NetEntry, symlink: bool, created_at: std::time::Duration) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    st.st_mode = if symlink {
        libc::S_IFLNK | 0o777
    } else if entry == net::NetEntry::Directory {
        libc::S_IFDIR | 0o555
    } else {
        libc::S_IFREG | 0o444
    };
    st.st_nlink = if entry == net::NetEntry::Directory && !symlink {
        2
    } else {
        1
    };
    st.st_size = if symlink { 8 } else { 0 };
    st.st_blksize = 1024;
    st.st_atime = created_at.as_secs() as libc::time_t;
    st.st_atime_nsec = created_at.subsec_nanos() as libc::c_long;
    st.st_mtime = st.st_atime;
    st.st_mtime_nsec = st.st_atime_nsec;
    st.st_ctime = st.st_atime;
    st.st_ctime_nsec = st.st_atime_nsec;
    st.st_ino = match entry {
        net::NetEntry::File(file) => {
            3 + net::FILES.iter().position(|(_, f)| *f == file).unwrap() as u64
        }
        _ => {
            if symlink {
                1
            } else {
                2
            }
        }
    };
    st
}

fn write_result<T>(value: &T, output: u64, notif: &SeccompNotif, notif_fd: RawFd) -> NotifAction {
    let bytes = unsafe {
        std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
    };
    match write_child_mem(notif_fd, notif.id, notif.pid, output, bytes) {
        Ok(_) => NotifAction::ReturnValue(0),
        Err(_) => NotifAction::Errno(libc::EFAULT),
    }
}

pub(crate) async fn handle_net_metadata(
    notif: &SeccompNotif,
    ctx: &SupervisorCtx,
    notif_fd: RawFd,
) -> NotifAction {
    let Some(request) = Request::decode(notif) else {
        return NotifAction::Continue;
    };
    let Some(path) = read_child_cstr(notif_fd, notif.id, notif.pid, request.path, 4096) else {
        return NotifAction::Continue;
    };
    if path.is_empty() {
        return NotifAction::Continue;
    }
    let requires_directory = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    let follow = request.flags & libc::AT_SYMLINK_NOFOLLOW as u32 == 0 || requires_directory;
    let Some(absolute) = resolve_to_normalized_absolute(
        notif.pid,
        request.dirfd,
        &path,
        ctx.policy.chroot_root.as_deref(),
        &ctx.policy.chroot_mounts,
        &ctx.processes,
    ) else {
        return NotifAction::Continue;
    };
    let Some(resolved) = net_path(absolute.clone(), follow, notif, ctx) else {
        return NotifAction::Continue;
    };
    serve_metadata(
        &request,
        absolute.to_str().unwrap(),
        resolved.to_str().unwrap(),
        requires_directory,
        follow,
        true,
        notif,
        ctx,
        notif_fd,
    )
    .await
}

async fn serve_metadata(
    request: &Request,
    original: &str,
    resolved: &str,
    requires_directory: bool,
    follow: bool,
    check_access: bool,
    notif: &SeccompNotif,
    ctx: &SupervisorCtx,
    notif_fd: RawFd,
) -> NotifAction {
    if check_access {
        if let Some(errno) = super::net_dispatch::access_alias_errno(
            original,
            resolved,
            libc::O_RDONLY as u64,
            notif,
            ctx,
        )
        .await
        {
            return NotifAction::Errno(errno);
        }
    }
    let entry = net::lookup(&canon_proc_namespace(resolved));
    if entry == net::NetEntry::Missing {
        return NotifAction::Errno(libc::ENOENT);
    }
    if requires_directory && matches!(entry, net::NetEntry::File(_)) {
        return NotifAction::Errno(libc::ENOTDIR);
    }
    let mounted = ctx.policy.chroot_root.is_some()
        && ctx
            .policy
            .chroot_mounts
            .iter()
            .any(|(mount, _)| Path::new(original) == mount);
    let symlink = !follow && resolved == "/proc/net" && !mounted;
    let allowed_flags = match request.operation {
        Operation::Stat => libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT,
        Operation::Statx => {
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT | 0x6000
        }
        Operation::Access => libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH | libc::AT_EACCESS,
        Operation::Readlink => libc::AT_SYMLINK_NOFOLLOW,
    } as u32;
    if request.flags & !allowed_flags != 0 {
        return NotifAction::Errno(libc::EINVAL);
    }
    match request.operation {
        Operation::Access => {
            if request.mode & !7 != 0 {
                return NotifAction::Errno(libc::EINVAL);
            }
            if request.mode & libc::W_OK as u32 != 0
                || (request.mode & libc::X_OK as u32 != 0
                    && matches!(entry, net::NetEntry::File(_)))
            {
                return NotifAction::Errno(libc::EACCES);
            }
            NotifAction::ReturnValue(0)
        }
        Operation::Readlink => {
            if request.size == 0 || request.size > i32::MAX as u64 {
                return NotifAction::Errno(libc::EINVAL);
            }
            if !symlink {
                return NotifAction::Errno(libc::EINVAL);
            }
            let target = b"self/net";
            let length = target.len().min(request.size as usize);
            if write_child_mem(
                notif_fd,
                notif.id,
                notif.pid,
                request.output,
                &target[..length],
            )
            .is_err()
            {
                return NotifAction::Errno(libc::EFAULT);
            }
            NotifAction::ReturnValue(length as i64)
        }
        Operation::Stat => {
            let st = metadata(entry, symlink, ctx.procfs.lock().await.created_at);
            write_result(&st, request.output, notif, notif_fd)
        }
        Operation::Statx => {
            if request.flags & 0x6000 == 0x6000 || request.mode & 0x80000000 != 0 {
                return NotifAction::Errno(libc::EINVAL);
            }
            let st = metadata(entry, symlink, ctx.procfs.lock().await.created_at);
            let mut stx: libc::statx = unsafe { std::mem::zeroed() };
            stx.stx_mask = libc::STATX_BASIC_STATS;
            stx.stx_blksize = st.st_blksize as u32;
            stx.stx_nlink = st.st_nlink as u32;
            stx.stx_mode = st.st_mode as u16;
            stx.stx_ino = st.st_ino;
            stx.stx_size = st.st_size as u64;
            stx.stx_atime.tv_sec = st.st_atime;
            stx.stx_atime.tv_nsec = st.st_atime_nsec as u32;
            stx.stx_mtime = stx.stx_atime;
            stx.stx_ctime = stx.stx_atime;
            write_result(&stx, request.output, notif, notif_fd)
        }
    }
}

fn errno_action() -> NotifAction {
    NotifAction::Errno(
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

fn probe_metadata(path: &str, dirfd: i64, pid: u32, follow: bool) -> Result<OwnedFd, i32> {
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
        0x02,
    )
}

fn proc_task_entry(path: &str, caller_tid: i32, caller_tgid: i32) -> Option<(i32, i32, &str)> {
    let (task, mut rest) = path.strip_prefix("/proc/")?.split_once('/')?;
    let parent = match task {
        "self" | "thread-self" => caller_tgid,
        _ => task.parse::<i32>().ok().filter(|pid| *pid > 0)?,
    };
    let mut pid = if task == "thread-self" {
        caller_tid
    } else {
        parent
    };
    if let Some(thread) = rest.strip_prefix("task/") {
        let (tid, tail) = thread.split_once('/')?;
        pid = tid.parse::<i32>().ok().filter(|pid| *pid > 0)?;
        rest = tail;
    }
    Some((parent, pid, rest))
}

// The sealed snapshot name selects cosmetic metadata only, never access rights.
fn named_net_file(path: &str) -> Option<net::NetFile> {
    let name = path
        .strip_prefix("/memfd:sandlock-proc-net-")?
        .strip_suffix(" (deleted)")?;
    net::FILES
        .iter()
        .find_map(|(entry, file)| (*entry == name).then_some(*file))
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
    let tracked_proc = absolute
        .as_deref()
        .and_then(Path::to_str)
        .and_then(|path| proc_task_entry(path, notif.pid as i32, tgid))
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
                let (_, pid, entry) = tracked_proc?;
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
        None if tracked_proc
            .is_some_and(|(_, _, entry)| matches!(entry, "cwd" | "exe" | "root")) =>
        {
            let (_, pid, entry) = tracked_proc.unwrap();
            let target = CString::new(format!("/proc/{pid}/{entry}")).unwrap();
            crate::seccomp::notif::openat2_at(
                libc::AT_FDCWD,
                &target,
                (libc::O_PATH | libc::O_CLOEXEC | if follow { 0 } else { libc::O_NOFOLLOW }) as u64,
                0,
                0,
            )
        }
        None => probe_metadata(&translated, request.dirfd, notif.pid, follow),
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
    if matches!(request.operation, Operation::Stat | Operation::Statx) {
        if let Some(file) = named_net_file(&resolved) {
            let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
            let required =
                libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
            if seals >= 0 && seals & required == required {
                let name = net::FILES
                    .iter()
                    .find(|(_, entry)| *entry == file)
                    .unwrap()
                    .0;
                return serve_metadata(
                    &request,
                    "",
                    &format!("/proc/net/{name}"),
                    requires_directory,
                    follow,
                    false,
                    notif,
                    ctx,
                    notif_fd,
                )
                .await;
            }
        }
    }
    if net::lookup(&canon_proc_namespace(&resolved)) != net::NetEntry::Outside {
        return serve_metadata(
            &request,
            absolute.as_deref().and_then(Path::to_str).unwrap_or(&path),
            &resolved,
            requires_directory,
            follow,
            !path.is_empty(),
            notif,
            ctx,
            notif_fd,
        )
        .await;
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
    fn named_network_descriptors_require_exact_catalog_names() {
        for &(name, file) in net::FILES {
            assert_eq!(
                named_net_file(&format!("/memfd:sandlock-proc-net-{name} (deleted)")),
                Some(file)
            );
        }
        assert_eq!(
            named_net_file("/memfd:sandlock-proc-net-snmp (deleted)"),
            None
        );
        assert_eq!(named_net_file("/tmp/sandlock-proc-net-tcp (deleted)"), None);
    }

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
    }

    #[test]
    fn pinned_outside_alias_stays_in_closed_network_catalog() {
        let directory =
            std::env::temp_dir().join(format!("sandlock-net-metadata-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let alias = directory.join("alias");
        let _ = std::fs::remove_file(&alias);
        std::os::unix::fs::symlink("/proc/net/snmp", &alias).unwrap();
        let fd = probe_metadata(
            alias.to_str().unwrap(),
            libc::AT_FDCWD as i64,
            std::process::id(),
            true,
        )
        .unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink("/dev/null", &alias).unwrap();
        let real = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        assert_eq!(
            net::lookup(&canon_proc_namespace(real.to_str().unwrap())),
            net::NetEntry::Missing
        );
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn network_metadata_has_proc_modes_and_zero_file_sizes() {
        let created_at = std::time::Duration::new(123, 456);
        let directory = metadata(net::NetEntry::Directory, false, created_at);
        assert_eq!(directory.st_mode, libc::S_IFDIR | 0o555);
        assert_eq!(directory.st_nlink, 2);
        for &(_, file) in net::FILES {
            let st = metadata(net::NetEntry::File(file), false, created_at);
            assert_eq!(st.st_mode, libc::S_IFREG | 0o444);
            assert_eq!(st.st_size, 0);
            assert_eq!(st.st_mtime, 123);
            assert_eq!(st.st_mtime_nsec, 456);
        }
        let link = metadata(net::NetEntry::Directory, true, created_at);
        assert_eq!(link.st_mode, libc::S_IFLNK | 0o777);
        assert_eq!(link.st_size, b"self/net".len() as i64);
    }
}

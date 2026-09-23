use std::ffi::CString;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::path::Path;

use super::net::{self, NetEntry};
use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{
    dup_fd_from_pid, inject_open_result, named_content_memfd, openat2_at, write_child_mem,
    NotifAction, OpenRequest,
};
use crate::sys::structs::SeccompNotif;

pub(crate) async fn access_errno(
    path: &str,
    flags: u64,
    notif: &SeccompNotif,
    ctx: &SupervisorCtx,
) -> Option<i32> {
    let policy = &ctx.policy;
    let canonical = super::canon_proc_namespace(path);
    let forms = super::own_proc_self_forms(
        path,
        notif.pid as i32,
        ctx.processes
            .tgid_of(notif.pid as i32)
            .unwrap_or(notif.pid as i32),
    );
    let denied = ctx.policy_fn.lock().await;
    if super::is_hidden_proc_path(path, &ctx.processes)
        || std::iter::once(path)
            .chain(std::iter::once(canonical.as_ref()))
            .chain(forms.iter().map(String::as_str))
            .any(|p| {
                denied.is_path_denied(p)
                    || policy
                        .chroot_denied
                        .iter()
                        .any(|d| Path::new(p).starts_with(d))
            })
    {
        return Some(libc::EACCES);
    }
    let granted = |p: &str| {
        policy
            .chroot_readable
            .iter()
            .chain(&policy.chroot_writable)
            .any(|g| super::own_grant_covers(p, g))
    };
    let mounted = policy.chroot_root.is_some()
        && policy
            .chroot_mounts
            .iter()
            .any(|(p, _)| Path::new(path).starts_with(p));
    if !mounted && !granted(path) && !granted(&canonical) && !forms.iter().any(|p| granted(p)) {
        return Some(libc::EACCES);
    }
    if flags as i32 & (libc::O_ACCMODE | libc::O_TRUNC | libc::O_CREAT) != 0 {
        return Some(libc::EACCES);
    }
    None
}

pub(crate) async fn access_alias_errno(
    path: &str,
    resolved: &str,
    flags: u64,
    notif: &SeccompNotif,
    ctx: &SupervisorCtx,
) -> Option<i32> {
    if let Some(errno) = access_errno(path, flags, notif, ctx).await {
        return Some(errno);
    }
    if path == resolved {
        return None;
    }
    let mounted = ctx.policy.chroot_root.is_some()
        && ctx.policy.chroot_mounts.iter().any(|(v, h)| {
            Path::new(path).strip_prefix(v).ok().is_some_and(|rest| {
                super::canon_proc_namespace(&h.join(rest).to_string_lossy())
                    == super::canon_proc_namespace(resolved)
            })
        });
    if !mounted {
        return access_errno(resolved, flags, notif, ctx).await;
    }
    let canonical = super::canon_proc_namespace(resolved);
    let denied = ctx.policy_fn.lock().await;
    if denied.is_path_denied(&canonical)
        || ctx
            .policy
            .chroot_denied
            .iter()
            .any(|p| Path::new(canonical.as_ref()).starts_with(p))
    {
        Some(libc::EACCES)
    } else {
        None
    }
}

pub(crate) async fn serve_entry(
    entry: NetEntry,
    flags: u64,
    notif: &SeccompNotif,
    ctx: &SupervisorCtx,
) -> NotifAction {
    let flags_i = flags as i32;
    if entry == NetEntry::Missing {
        return NotifAction::Errno(libc::ENOENT);
    }
    if flags_i & (libc::O_ACCMODE | libc::O_TRUNC | libc::O_CREAT) != 0 {
        return NotifAction::Errno(libc::EACCES);
    }
    // SECCOMP_ADDFD uses fget(), which rejects O_PATH descriptors.
    if flags_i & libc::O_PATH != 0 {
        return NotifAction::Errno(libc::EOPNOTSUPP);
    }
    let fd = match entry {
        NetEntry::Directory => {
            let path = CString::new(format!("/proc/{}/net", notif.pid)).unwrap();
            openat2_at(
                libc::AT_FDCWD,
                &path,
                (flags_i | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                0,
                0,
            )
        }
        NetEntry::File(file) => {
            if flags_i & libc::O_DIRECTORY != 0 {
                return NotifAction::Errno(libc::ENOTDIR);
            }
            let ports = ctx.network.lock().await.port_map.real_to_virtual.clone();
            let content = match net::render(file, &ctx.processes, &ports, &ctx.netlink, &ctx.policy)
            {
                Ok(content) => content,
                Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EIO)),
            };
            let name = format!(
                "sandlock-proc-net-{}",
                net::FILES.iter().find(|(_, f)| *f == file).unwrap().0
            );
            match named_content_memfd(&content, true, &name) {
                Ok(fd) => {
                    if unsafe { libc::fchmod(fd.as_raw_fd(), 0o444) } < 0 {
                        return NotifAction::Errno(last_errno());
                    }
                    let path = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
                    openat2_at(
                        libc::AT_FDCWD,
                        &path,
                        ((flags_i & !libc::O_NOFOLLOW) | libc::O_CLOEXEC) as u64,
                        0,
                        0,
                    )
                }
                Err(e) => Err(e.raw_os_error().unwrap_or(libc::EIO)),
            }
        }
        NetEntry::Outside | NetEntry::Missing => return NotifAction::Errno(libc::ENOENT),
    };
    match fd {
        Ok(fd) => inject_open_result(fd.into_raw_fd(), flags),
        Err(e) => NotifAction::Errno(e),
    }
}

pub(crate) async fn handle_net_open(
    notif: &SeccompNotif,
    open: &OpenRequest,
    ctx: &SupervisorCtx,
) -> NotifAction {
    let Some(path) = open.target_str() else {
        return NotifAction::Continue;
    };
    if open.args.resolve != 0 && ctx.policy.chroot_root.is_none() {
        return NotifAction::Continue;
    }
    let resolved = if ctx.policy.chroot_root.is_some() {
        super::net_metadata::net_path(
            Path::new(path).to_path_buf(),
            open.args.flags & libc::O_NOFOLLOW as u64 == 0,
            notif,
            ctx,
        )
    } else {
        Some(Path::new(path).to_path_buf())
    };
    let Some(resolved) = resolved else {
        return NotifAction::Continue;
    };
    let resolved = resolved.to_str().unwrap();
    let entry = net::lookup(&super::canon_proc_namespace(resolved));
    if entry == NetEntry::Outside {
        return NotifAction::Continue;
    }
    if let Some(errno) = access_alias_errno(path, resolved, open.args.flags, notif, ctx).await {
        return NotifAction::Errno(errno);
    }
    if open.args.resolve != 0 {
        let chroot = crate::chroot::dispatch::ChrootCtx::new(&ctx.policy, &ctx.processes);
        if let Some(action) = crate::chroot::dispatch::enforce_resolve_flags(
            notif,
            open.args.dirfd,
            &open.path,
            &chroot,
            crate::chroot::dispatch::honorable_resolve_flags(open.args.resolve),
        ) {
            return action;
        }
    }
    if open.args.flags & libc::O_NOFOLLOW as u64 != 0 && resolved == "/proc/net" {
        return NotifAction::Errno(if open.args.flags & libc::O_PATH as u64 != 0 {
            libc::EOPNOTSUPP
        } else {
            libc::ELOOP
        });
    }
    if matches!(entry, NetEntry::File(_)) && open.path.ends_with('/') {
        return NotifAction::Errno(libc::ENOTDIR);
    }
    serve_entry(entry, open.args.flags, notif, ctx).await
}

fn net_directory(fd: &OwnedFd) -> Result<bool, i32> {
    let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    Ok(path
        .to_str()
        .map(|s| net::lookup(&super::canon_proc_namespace(s)))
        == Some(NetEntry::Directory))
}

fn directory_records(offset: usize, count: usize, legacy: bool) -> Result<(Vec<u8>, usize), i32> {
    let names = [".", ".."]
        .into_iter()
        .chain(net::FILES.iter().map(|(name, _)| *name));
    let mut data = Vec::new();
    let mut next = offset;
    for (index, name) in names.enumerate().skip(offset) {
        let kind = if index < 2 {
            super::DT_DIR
        } else {
            super::DT_REG
        };
        let inode = match index {
            0 => 2,
            1 => 1,
            _ => (index + 1) as u64,
        };
        let mut record =
            super::build_dirent64(inode, (index + 1) as i64, kind, name).ok_or(libc::EIO)?;
        if legacy {
            record[18..].fill(0);
            record[18..18 + name.len()].copy_from_slice(name.as_bytes());
            let last = record.len() - 1;
            record[last] = kind;
        }
        if data.len() + record.len() > count {
            if data.is_empty() {
                return Err(libc::EINVAL);
            }
            break;
        }
        data.extend(record);
        next = index + 1;
    }
    Ok((data, next))
}

pub(crate) async fn handle_net_directory(
    notif: &SeccompNotif,
    ctx: &SupervisorCtx,
    notif_fd: i32,
    fallback: bool,
) -> NotifAction {
    let fd = match dup_fd_from_pid(notif.pid, notif.data.args[0] as i32) {
        Ok(fd) => fd,
        Err(e) => return NotifAction::Errno(e.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let is_net = match net_directory(&fd) {
        Ok(is_net) => is_net,
        Err(e) => return NotifAction::Errno(e),
    };
    if !is_net && !fallback {
        return NotifAction::Continue;
    }
    let _guard = ctx.procfs.lock().await;
    if notif.data.nr as i64 == libc::SYS_lseek {
        let result = unsafe {
            libc::lseek(
                fd.as_raw_fd(),
                notif.data.args[1] as i64,
                notif.data.args[2] as i32,
            )
        };
        return if result < 0 {
            NotifAction::Errno(last_errno())
        } else {
            NotifAction::ReturnValue(result)
        };
    }
    let count = (notif.data.args[2] as u32 as usize).min(1024 * 1024);
    let initial_offset = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_CUR) };
    let (data, next) = if is_net {
        let offset = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_CUR) };
        if offset < 0 {
            return NotifAction::Errno(last_errno());
        }
        match directory_records(
            offset as usize,
            count,
            Some(notif.data.nr as i64) == crate::arch::sys_getdents(),
        ) {
            Ok((data, next)) => (data, Some(next)),
            Err(e) => return NotifAction::Errno(e),
        }
    } else {
        // Pin every final getdents target so dup2 cannot swap in a host net directory.
        let mut data = vec![0; count];
        let n = unsafe {
            libc::syscall(
                notif.data.nr as libc::c_long,
                fd.as_raw_fd(),
                data.as_mut_ptr(),
                count,
            )
        };
        if n < 0 {
            return NotifAction::Errno(last_errno());
        }
        data.truncate(n as usize);
        (data, None)
    };
    if !data.is_empty()
        && write_child_mem(notif_fd, notif.id, notif.pid, notif.data.args[1], &data).is_err()
    {
        if !is_net && initial_offset >= 0 {
            unsafe {
                libc::lseek(fd.as_raw_fd(), initial_offset, libc::SEEK_SET);
            }
        }
        return NotifAction::Errno(libc::EFAULT);
    }
    if let Some(next) = next {
        if unsafe { libc::lseek(fd.as_raw_fd(), next as i64, libc::SEEK_SET) } < 0 {
            return NotifAction::Errno(last_errno());
        }
    }
    NotifAction::ReturnValue(data.len() as i64)
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

pub(crate) fn metadata_syscalls() -> Vec<i64> {
    let mut nrs = vec![
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_faccessat,
        crate::arch::SYS_FACCESSAT2,
        libc::SYS_readlinkat,
    ];
    nrs.extend(
        [
            crate::arch::sys_stat(),
            crate::arch::sys_lstat(),
            crate::arch::sys_access(),
            crate::arch::sys_readlink(),
        ]
        .into_iter()
        .flatten(),
    );
    nrs
}

// Check the injected object because mounts and racing symlinks can bypass lexical dispatch.
pub(crate) async fn guard_injection(
    action: NotifAction,
    notif: &SeccompNotif,
    open: &OpenRequest,
    ctx: &SupervisorCtx,
) -> NotifAction {
    if ctx.policy.chroot_root.is_none() {
        return action;
    }
    let NotifAction::InjectFdSend { ref srcfd, .. } = action else {
        return action;
    };
    let real = match std::fs::read_link(format!("/proc/self/fd/{}", srcfd.as_raw_fd())) {
        Ok(real) => real,
        Err(_) => return NotifAction::Errno(libc::EIO),
    };
    let canonical = super::canon_proc_namespace(&real.to_string_lossy()).into_owned();
    let entry = net::lookup(&canonical);
    if entry == NetEntry::Outside {
        return action;
    }
    let denied = ctx.policy_fn.lock().await.is_path_denied(&canonical)
        || ctx
            .policy
            .chroot_denied
            .iter()
            .any(|p| Path::new(&canonical).starts_with(p));
    if denied {
        return NotifAction::Errno(libc::EACCES);
    }
    serve_entry(entry, open.args.flags, notif, ctx).await
}

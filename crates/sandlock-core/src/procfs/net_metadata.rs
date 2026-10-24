use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use super::metadata::{write_result, Operation, Request};
use super::{canon_proc_namespace, net, resolve_to_normalized_absolute};
use crate::seccomp::ctx::SupervisorCtx;
use crate::seccomp::notif::{read_child_cstr, write_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;

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
    st.st_atime = created_at.as_secs() as _;
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

// The sealed snapshot name selects cosmetic metadata only, never access rights.
fn named_net_file(path: &str) -> Option<net::NetFile> {
    let name = path
        .strip_prefix("/memfd:sandlock-proc-net-")?
        .strip_suffix(" (deleted)")?;
    net::FILES
        .iter()
        .find_map(|(entry, file)| (*entry == name).then_some(*file))
}

pub(super) async fn serve_pinned(
    request: &Request,
    fd: &OwnedFd,
    resolved: &str,
    original: &str,
    check_access: bool,
    requires_directory: bool,
    follow: bool,
    notif: &SeccompNotif,
    ctx: &SupervisorCtx,
    notif_fd: RawFd,
) -> Option<NotifAction> {
    if matches!(request.operation, Operation::Stat | Operation::Statx) {
        if let Some(file) = named_net_file(resolved) {
            let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
            let required =
                libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
            if seals >= 0 && seals & required == required {
                let name = net::FILES
                    .iter()
                    .find(|(_, entry)| *entry == file)
                    .unwrap()
                    .0;
                return Some(
                    serve_metadata(
                        request,
                        "",
                        &format!("/proc/net/{name}"),
                        requires_directory,
                        follow,
                        false,
                        notif,
                        ctx,
                        notif_fd,
                    )
                    .await,
                );
            }
        }
    }
    if net::lookup(&canon_proc_namespace(resolved)) != net::NetEntry::Outside {
        return Some(
            serve_metadata(
                request,
                original,
                resolved,
                requires_directory,
                follow,
                check_access,
                notif,
                ctx,
                notif_fd,
            )
            .await,
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::metadata::probe_metadata;
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

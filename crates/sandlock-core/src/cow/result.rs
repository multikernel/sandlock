use crate::error::BranchError;
use crate::seccomp::notif::NotifAction;

/// Map a `SeccompCowBranch::handle_link` result to a `NotifAction`.
///
/// Unlike the generic COW result mapping in the dispatcher, this never falls
/// through. A hard link whose destination the branch owns has to be answered by
/// the branch: letting the original syscall run would give the child a second
/// name for the lower inode, so a write through it would edit the file the
/// branch promised to leave alone, and the name itself would outlive an aborted
/// branch.
pub(crate) fn link_result(r: Result<bool, BranchError>) -> NotifAction {
    match r {
        Ok(true) => NotifAction::ReturnValue(0),
        // The branch declined: the source is a directory (EPERM is the
        // kernel's own answer for that) or the upper-layer link failed.
        Ok(false) => NotifAction::Errno(libc::EPERM),
        Err(BranchError::QuotaExceeded) => NotifAction::Errno(libc::ENOSPC),
        Err(BranchError::Deleted) => NotifAction::Errno(libc::ENOENT),
        Err(BranchError::Denied) => NotifAction::Errno(libc::EPERM),
        Err(BranchError::Exists) => NotifAction::Errno(libc::EEXIST),
        Err(BranchError::NotOwned) => NotifAction::Errno(libc::EXDEV),
        Err(_) => NotifAction::Errno(libc::EIO),
    }
}

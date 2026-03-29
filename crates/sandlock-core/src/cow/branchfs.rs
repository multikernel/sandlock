use super::CowBranch;
use crate::error::BranchError;
use std::ffi::CStr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

// ioctl constants
const FS_IOC_BRANCH_CREATE: libc::c_ulong = 0x80806200;
const FS_IOC_BRANCH_COMMIT: libc::c_ulong = 0x00006201;
const FS_IOC_BRANCH_ABORT: libc::c_ulong = 0x00006202;

pub(crate) struct BranchFsBranch {
    ctl_path: PathBuf,
    branch_path: PathBuf,
}

impl BranchFsBranch {
    /// Create a new branch via ioctl on .branchfs_ctl.
    pub fn create(mount_root: &Path) -> Result<Self, BranchError> {
        let ctl_path = mount_root.join(".branchfs_ctl");
        let file = std::fs::OpenOptions::new()
            .read(true).write(true)
            .open(&ctl_path)
            .map_err(|e| BranchError::Operation(format!("open {}: {}", ctl_path.display(), e)))?;

        let mut buf = [0u8; 128];
        let ret = unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_BRANCH_CREATE, buf.as_mut_ptr()) };
        if ret < 0 {
            return Err(BranchError::Operation(format!(
                "ioctl CREATE: {}", std::io::Error::last_os_error()
            )));
        }

        let uuid = CStr::from_bytes_until_nul(&buf)
            .map_err(|_| BranchError::Operation("invalid UUID from ioctl".into()))?
            .to_str()
            .map_err(|_| BranchError::Operation("non-UTF8 UUID".into()))?
            .to_string();

        let branch_path = mount_root.join(format!("@{}", uuid));
        let branch_ctl = branch_path.join(".branchfs_ctl");

        Ok(Self {
            ctl_path: branch_ctl,
            branch_path,
        })
    }

    fn ctl_ioctl(&self, cmd: libc::c_ulong) -> Result<(), BranchError> {
        let file = std::fs::OpenOptions::new()
            .read(true).write(true)
            .open(&self.ctl_path)
            .map_err(|e| BranchError::Operation(format!("open ctl: {}", e)))?;
        let ret = unsafe { libc::ioctl(file.as_raw_fd(), cmd, 0) };
        if ret < 0 {
            Err(BranchError::Operation(format!(
                "ioctl: {}", std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }
}

impl CowBranch for BranchFsBranch {
    fn branch_path(&self) -> &Path {
        &self.branch_path
    }

    fn commit(&self) -> Result<(), BranchError> {
        self.ctl_ioctl(FS_IOC_BRANCH_COMMIT)
    }

    fn abort(&self) -> Result<(), BranchError> {
        self.ctl_ioctl(FS_IOC_BRANCH_ABORT)
    }

    fn cleanup(&self) -> Result<(), BranchError> {
        // BranchFS cleanup happens via abort ioctl
        self.abort()
    }
}

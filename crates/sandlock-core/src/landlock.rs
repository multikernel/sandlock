use std::os::fd::OwnedFd;
use std::path::Path;

use crate::error::{ConfinementError, SandlockError};
use crate::policy::Policy;
use crate::sys::structs::{
    LandlockNetPortAttr, LandlockPathBeneathAttr, LandlockRulesetAttr,
    LANDLOCK_ACCESS_FS_EXECUTE, LANDLOCK_ACCESS_FS_IOCTL_DEV, LANDLOCK_ACCESS_FS_MAKE_BLOCK,
    LANDLOCK_ACCESS_FS_MAKE_CHAR, LANDLOCK_ACCESS_FS_MAKE_DIR, LANDLOCK_ACCESS_FS_MAKE_FIFO,
    LANDLOCK_ACCESS_FS_MAKE_REG, LANDLOCK_ACCESS_FS_MAKE_SOCK, LANDLOCK_ACCESS_FS_MAKE_SYM,
    LANDLOCK_ACCESS_FS_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE, LANDLOCK_ACCESS_FS_REFER,
    LANDLOCK_ACCESS_FS_REMOVE_DIR, LANDLOCK_ACCESS_FS_REMOVE_FILE, LANDLOCK_ACCESS_FS_TRUNCATE,
    LANDLOCK_ACCESS_FS_WRITE_FILE, LANDLOCK_ACCESS_NET_BIND_TCP, LANDLOCK_ACCESS_NET_CONNECT_TCP,
    LANDLOCK_CREATE_RULESET_VERSION, LANDLOCK_RULE_NET_PORT, LANDLOCK_RULE_PATH_BENEATH,
    LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET, LANDLOCK_SCOPE_SIGNAL, SYS_LANDLOCK_CREATE_RULESET,
};
use crate::sys::syscall;

// ============================================================
// Access flag helpers
// ============================================================

/// All FS read access flags.
const READ_ACCESS: u64 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

/// Build the full FS access bitmask for the given ABI version.
fn base_fs_access(abi: u32) -> u64 {
    // ABI v1 base: bits 0-12 (EXECUTE through MAKE_SYM)
    let mut mask: u64 = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    if abi >= 2 {
        mask |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    mask
}

/// Build the write access bitmask: READ_ACCESS + all write/create/delete flags.
fn write_access(abi: u32) -> u64 {
    let mut mask: u64 = READ_ACCESS
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    if abi >= 2 {
        mask |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    mask
}

// ============================================================
// ABI version detection
// ============================================================

/// Query the Landlock ABI version supported by the running kernel.
///
/// Returns `ConfinementError::LandlockUnavailable` when the kernel has no
/// Landlock support (ENOSYS / EOPNOTSUPP).
pub fn abi_version() -> Result<u32, ConfinementError> {
    // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
    let ret = unsafe {
        syscall::syscall3(
            SYS_LANDLOCK_CREATE_RULESET,
            0, // NULL attr pointer
            0, // size 0
            LANDLOCK_CREATE_RULESET_VERSION as u64,
        )
    };

    match ret {
        Ok(v) => Ok(v as u32),
        Err(e) => {
            let raw = e.raw_os_error().unwrap_or(0);
            // ENOSYS (38) = syscall not available; EOPNOTSUPP (95) = disabled
            if raw == libc::ENOSYS || raw == libc::EOPNOTSUPP {
                Err(ConfinementError::LandlockUnavailable(e.to_string()))
            } else {
                Err(ConfinementError::Landlock(format!(
                    "abi_version query failed: {}",
                    e
                )))
            }
        }
    }
}

// ============================================================
// Rule helpers
// ============================================================

/// Open `path` and add a Landlock path-beneath rule to `ruleset_fd`.
fn add_path_rule(ruleset_fd: &OwnedFd, path: &Path, access: u64) -> Result<(), ConfinementError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| {
            ConfinementError::Landlock(format!("open path {:?} failed: {}", path, e))
        })?;

    use std::os::unix::io::AsRawFd;
    let attr = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: file.as_raw_fd(),
    };

    syscall::landlock_add_rule(
        ruleset_fd,
        LANDLOCK_RULE_PATH_BENEATH,
        &attr as *const _ as *const std::ffi::c_void,
        0,
    )
    .map_err(|e| ConfinementError::Landlock(format!("add path rule for {:?}: {}", path, e)))?;

    Ok(())
}

/// Add a Landlock network port rule to `ruleset_fd`.
fn add_net_rule(ruleset_fd: &OwnedFd, port: u16, access: u64) -> Result<(), ConfinementError> {
    let attr = LandlockNetPortAttr {
        allowed_access: access,
        port: port as u64,
    };

    syscall::landlock_add_rule(
        ruleset_fd,
        LANDLOCK_RULE_NET_PORT,
        &attr as *const _ as *const std::ffi::c_void,
        0,
    )
    .map_err(|e| ConfinementError::Landlock(format!("add net rule for port {}: {}", port, e)))?;

    Ok(())
}

// ============================================================
// Main entry point
// ============================================================

/// Minimum Landlock ABI version required by sandlock.
pub const MIN_ABI: u32 = 6;

/// Apply Landlock confinement based on the given `Policy`.
///
/// Requires Landlock ABI v6 or later. Returns an error if the kernel does
/// not meet this requirement.
pub fn confine(policy: &Policy) -> Result<(), SandlockError> {
    // Step 1 -- detect and validate ABI version.
    let abi = abi_version().map_err(|e| {
        SandlockError::Sandbox(crate::error::SandboxError::Confinement(e))
    })?;

    if abi < MIN_ABI {
        return Err(SandlockError::Sandbox(
            crate::error::SandboxError::Confinement(
                ConfinementError::InsufficientAbi {
                    required: MIN_ABI,
                    actual: abi,
                    feature: "full sandlock support".into(),
                },
            ),
        ));
    }

    // Step 2 -- build handled_access_fs / handled_access_net / scoped.
    let handled_access_fs = base_fs_access(abi);

    let has_net = !policy.net_bind.is_empty() || !policy.net_connect.is_empty();
    let handled_access_net = if has_net {
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    } else {
        0
    };

    let scoped = {
        let mut s: u64 = 0;
        if policy.isolate_ipc {
            s |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
        }
        if policy.isolate_signals {
            s |= LANDLOCK_SCOPE_SIGNAL;
        }
        s
    };

    // Step 3 — create ruleset.
    let attr = LandlockRulesetAttr {
        handled_access_fs,
        handled_access_net,
        scoped,
    };

    let ruleset_fd = syscall::landlock_create_ruleset(&attr, std::mem::size_of::<LandlockRulesetAttr>(), 0)
        .map_err(|e| {
            SandlockError::Sandbox(crate::error::SandboxError::Confinement(
                ConfinementError::Landlock(format!("create ruleset: {}", e)),
            ))
        })?;

    // Step 4 — add filesystem path rules.
    // When chroot is active, translate virtual paths (inside chroot) to host
    // paths by prepending the chroot root.  Skip paths that don't exist in
    // the rootfs.
    let chroot_root = policy.chroot.as_deref();
    let fs_write_mask = write_access(abi);
    for path in &policy.fs_writable {
        let host;
        let rule_path = if let Some(root) = chroot_root {
            host = root.join(path.strip_prefix("/").unwrap_or(path));
            if !host.exists() { continue; }
            host.as_path()
        } else {
            path.as_path()
        };
        add_path_rule(&ruleset_fd, rule_path, fs_write_mask).map_err(|e| {
            SandlockError::Sandbox(crate::error::SandboxError::Confinement(e))
        })?;
    }

    for path in &policy.fs_readable {
        let host;
        let rule_path = if let Some(root) = chroot_root {
            host = root.join(path.strip_prefix("/").unwrap_or(path));
            if !host.exists() { continue; }
            host.as_path()
        } else {
            path.as_path()
        };
        add_path_rule(&ruleset_fd, rule_path, READ_ACCESS).map_err(|e| {
            SandlockError::Sandbox(crate::error::SandboxError::Confinement(e))
        })?;
    }

    // GPU device paths (when gpu_devices is set)
    if policy.gpu_devices.is_some() {
        // Read-write access to GPU device nodes
        for path in &[
            "/dev/nvidia0", "/dev/nvidia1", "/dev/nvidia2", "/dev/nvidia3",
            "/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools",
            "/dev/dri",
        ] {
            let _ = add_path_rule(&ruleset_fd, std::path::Path::new(path), fs_write_mask);
            // Ignore errors — devices may not exist
        }
        // Read-only access to GPU sysfs/procfs
        for path in &[
            "/proc/driver/nvidia",
            "/sys/bus/pci/devices",
            "/sys/module/nvidia",
        ] {
            let _ = add_path_rule(&ruleset_fd, std::path::Path::new(path), READ_ACCESS);
        }
    }

    // Step 5 -- add network port rules.
    for &port in &policy.net_bind {
        add_net_rule(&ruleset_fd, port, LANDLOCK_ACCESS_NET_BIND_TCP).map_err(|e| {
            SandlockError::Sandbox(crate::error::SandboxError::Confinement(e))
        })?;
    }
    for &port in &policy.net_connect {
        add_net_rule(&ruleset_fd, port, LANDLOCK_ACCESS_NET_CONNECT_TCP).map_err(|e| {
            SandlockError::Sandbox(crate::error::SandboxError::Confinement(e))
        })?;
    }

    // Step 6 — enforce (irreversible).
    syscall::landlock_restrict_self(&ruleset_fd, 0).map_err(|e| {
        SandlockError::Sandbox(crate::error::SandboxError::Confinement(
            ConfinementError::Landlock(format!("restrict_self: {}", e)),
        ))
    })?;

    Ok(())
}

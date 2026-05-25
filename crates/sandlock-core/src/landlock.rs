use std::os::fd::OwnedFd;
use std::path::Path;

use crate::error::{ConfinementError, SandlockError};
use crate::protection::{Protection, ProtectionPolicy, ProtectionState};
use crate::sandbox::Sandbox;
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

/// Access rights that apply to non-directory files. The kernel rejects a
/// path-beneath rule on a non-directory whose `allowed_access` carries any
/// directory-only right (READ_DIR, MAKE_*, REMOVE_*, REFER) with EINVAL, so the
/// requested access is masked down to this set for files and device nodes.
const ACCESS_FILE: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_TRUNCATE
    | LANDLOCK_ACCESS_FS_IOCTL_DEV;

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
    use std::os::unix::fs::OpenOptionsExt;
    // Reference the path with O_PATH rather than opening it for I/O: O_PATH does
    // not block on FIFOs and needs no read permission on the target, so a rule
    // on a FIFO or a write-only/no-read path neither hangs nor fails here. An
    // O_PATH fd still supports fstat (the file-type check below) and serves as a
    // valid parent_fd for landlock_add_rule.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            ConfinementError::Landlock(format!("open path {:?} failed: {}", path, e))
        })?;

    // Directory-only access rights (READ_DIR, MAKE_*, REMOVE_*, REFER) make
    // landlock_add_rule fail with EINVAL on a non-directory path. Mask the
    // requested access down to the file-applicable set for files and devices.
    let allowed_access = match file.metadata() {
        Ok(m) if m.is_dir() => access,
        _ => access & ACCESS_FILE,
    };

    use std::os::unix::io::AsRawFd;
    let attr = LandlockPathBeneathAttr {
        allowed_access,
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
// Per-protection availability resolution
// ============================================================

/// Resolution for a single `Protection` against the host's Landlock
/// ABI and the policy's state for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum Resolved {
    /// Enforce: protection is available on the host and the policy
    /// requires (or allows) it.
    Active,
    /// Enforce-not: protection is unavailable on the host but the
    /// policy named it `Degradable`, so we skip it silently.
    Degraded,
    /// Off: the policy disabled this protection (regardless of host
    /// support).
    Disabled,
    /// Error: the policy is `Strict` but the host kernel cannot
    /// provide this protection.
    StrictlyUnavailable,
}

/// Resolve a single `Protection` against the host ABI and a
/// `ProtectionPolicy` into one of four states.
#[doc(hidden)]
pub fn resolve(p: Protection, host_abi: u32, policy: &ProtectionPolicy) -> Resolved {
    let available = host_abi >= p.min_abi();
    match (policy.state(p), available) {
        (ProtectionState::Disabled, _) => Resolved::Disabled,
        (ProtectionState::Strict, true) => Resolved::Active,
        (ProtectionState::Strict, false) => Resolved::StrictlyUnavailable,
        (ProtectionState::Degradable, true) => Resolved::Active,
        (ProtectionState::Degradable, false) => Resolved::Degraded,
    }
}

/// Compute the `scoped` mask from the per-protection resolutions of
/// the two scope protections.
pub(crate) fn compute_scope_mask(abi: u32, pol: &ProtectionPolicy) -> u64 {
    let mut mask: u64 = 0;
    if resolve(Protection::AbstractUnixScope, abi, pol) == Resolved::Active {
        mask |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
    }
    if resolve(Protection::SignalScope, abi, pol) == Resolved::Active {
        mask |= LANDLOCK_SCOPE_SIGNAL;
    }
    mask
}

/// Compute the `handled_access_fs` mask. Starts from the ABI-cumulative
/// base set and masks off bits whose corresponding `Protection` is
/// `Disabled` in the policy.
pub(crate) fn compute_fs_mask(abi: u32, pol: &ProtectionPolicy) -> u64 {
    let mut mask = base_fs_access(abi);
    if resolve(Protection::FsRefer, abi, pol) == Resolved::Disabled {
        mask &= !LANDLOCK_ACCESS_FS_REFER;
    }
    if resolve(Protection::FsTruncate, abi, pol) == Resolved::Disabled {
        mask &= !LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if resolve(Protection::FsIoctlDev, abi, pol) == Resolved::Disabled {
        mask &= !LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    mask
}

/// Compute the `handled_access_net` mask, preserving the wildcard
/// behaviour: when any TCP `--net-allow` rule covers every port we
/// drop `CONNECT_TCP` from the handled set (the on-behalf path is then
/// the sole enforcer). Returns `0` when `Protection::NetTcp` is not
/// `Active` (either disabled by policy or degraded on a kernel that
/// does not provide TCP network hooks).
pub(crate) fn compute_net_mask(
    abi: u32,
    pol: &ProtectionPolicy,
    sandbox: &Sandbox,
    handle_net: bool,
) -> u64 {
    if !handle_net {
        return 0;
    }
    if resolve(Protection::NetTcp, abi, pol) != Resolved::Active {
        return 0;
    }
    use crate::sandbox::Protocol;
    let net_wildcard = sandbox
        .net_allow
        .iter()
        .any(|r| r.protocol == Protocol::Tcp && r.all_ports);
    if net_wildcard {
        LANDLOCK_ACCESS_NET_BIND_TCP
    } else {
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    }
}

// ============================================================
// Main entry point
// ============================================================

/// Minimum Landlock ABI version required by sandlock when every
/// protection is in the default `ProtectionState::Strict`. The
/// authoritative per-protection floors live in
/// `Protection::min_abi()`; this constant is kept for backward
/// compatibility with downstream code that re-exports it.
pub const MIN_ABI: u32 = 6;

/// Apply Landlock confinement based on the given `Sandbox`.
///
/// Requires Landlock ABI v6 or later. Returns an error if the kernel does
/// not meet this requirement.
pub fn confine(policy: &Sandbox) -> Result<(), SandlockError> {
    confine_inner(policy, true)
}

/// Apply Landlock filesystem confinement without TCP bind/connect rules.
pub fn confine_filesystem(policy: &Sandbox) -> Result<(), SandlockError> {
    confine_inner(policy, false)
}

fn confine_inner(policy: &Sandbox, handle_net: bool) -> Result<(), SandlockError> {
    // Step 1 — detect host ABI version.
    let abi = abi_version().map_err(|e| {
        SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(e))
    })?;

    // Step 2 — per-protection availability resolution. Any protection
    // in `ProtectionState::Strict` that the host kernel cannot provide
    // is a hard error here; `Degradable` becomes a silent skip and
    // `Disabled` is honoured regardless of host support. With the
    // default `ProtectionPolicy::strict_all()` on a v6+ host this
    // produces `Resolved::Active` for every protection — preserving
    // the historical `MIN_ABI = 6` floor exactly.
    let pol = &policy.protection_policy;
    for protection in Protection::all() {
        if resolve(protection, abi, pol) == Resolved::StrictlyUnavailable {
            return Err(SandlockError::Runtime(
                crate::error::SandboxRuntimeError::Confinement(
                    ConfinementError::ProtectionUnavailable {
                        protection,
                        required_abi: protection.min_abi(),
                        host_abi: abi,
                    },
                ),
            ));
        }
    }

    // Step 3 — build handled_access_fs / handled_access_net / scoped.
    //
    // FS: cumulative ABI base set, with `Disabled` protections masked
    // off (FsRefer/FsTruncate/FsIoctlDev).
    let handled_access_fs = compute_fs_mask(abi, pol);

    // Net: TCP bind/connect via Landlock by default. When any
    // `--net-allow` rule has the all-ports wildcard (`host:*` or
    // `:*`), Landlock cannot express "every port" without enumerating
    // 65535 rules, so we drop CONNECT_TCP from the handled set —
    // unhandled access is unrestricted by Landlock. The on-behalf
    // path (seccomp notif on connect/sendto/sendmsg) still enforces
    // the per-rule IP allowlist when the rule is `host:*`. For `:*`
    // the on-behalf path becomes `NetworkPolicy::Unrestricted` (no
    // additional check). Bind enforcement is unaffected.
    // Landlock's net hooks only cover TCP (CONNECT_TCP / BIND_TCP).
    // UDP and ICMP rules are enforced elsewhere (BPF gates plus the
    // on-behalf path), so they're filtered out here — feeding them to
    // Landlock would either be a no-op (for unhandled protocols) or
    // wrongly install TCP rules from a UDP wildcard.
    use crate::sandbox::Protocol;
    let net_wildcard = policy
        .net_allow
        .iter()
        .any(|r| r.protocol == Protocol::Tcp && r.all_ports);
    let handled_access_net = compute_net_mask(abi, pol, policy, handle_net);

    // Scope: IPC + signal isolation, each gated on its protection's
    // resolved state.
    let scoped = compute_scope_mask(abi, pol);

    // Step 3 — create ruleset.
    let attr = LandlockRulesetAttr {
        handled_access_fs,
        handled_access_net,
        scoped,
    };

    let ruleset_fd = syscall::landlock_create_ruleset(&attr, std::mem::size_of::<LandlockRulesetAttr>(), 0)
        .map_err(|e| {
            SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(
                ConfinementError::Landlock(format!("create ruleset: {}", e)),
            ))
        })?;

    // Step 4 — add filesystem path rules.
    // When chroot is active, translate virtual paths (inside chroot) to host
    // paths by prepending the chroot root.  Skip paths that don't exist in
    // the rootfs.  Only chroot-translated paths are added — host paths are
    // NOT added, so any seccomp fallthrough is blocked by Landlock (fail-closed).
    // The PT_INTERP patching in handle_chroot_exec ensures the kernel loads
    // the image's ELF interpreter via an injected fd, not a host path.
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
            SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(e))
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
            SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(e))
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

    // Step 5 -- add network port rules. Skip entirely when
    // `Protection::NetTcp` is not `Active` (either policy-disabled or
    // degraded on a host without TCP network hooks) — `handled_access_net`
    // is 0 in that case and the kernel would reject any rule with EINVAL.
    let net_tcp_active = resolve(Protection::NetTcp, abi, pol) == Resolved::Active;
    if handle_net && net_tcp_active {
        for &port in &policy.net_bind {
            add_net_rule(&ruleset_fd, port, LANDLOCK_ACCESS_NET_BIND_TCP).map_err(|e| {
                SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(e))
            })?;
        }
    }
    // For TCP connect, Landlock is the only enforcer on the direct path.
    // The on-behalf path (when enabled) re-checks (ip, port) against the
    // resolved allowlist, but Landlock must already permit the port or
    // the kernel rejects before seccomp gets a chance to dispatch. Allow
    // every port that any --net-allow rule mentions, plus every HTTP
    // intercept port; the on-behalf check ensures the IP also matches.
    //
    // When `net_wildcard` is set we already excluded CONNECT_TCP from
    // `handled_access_net`, so adding rules here would fail with EINVAL.
    // Skip — the on-behalf path is the sole enforcer.
    if handle_net && net_tcp_active && !net_wildcard {
        let mut connect_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
        for rule in &policy.net_allow {
            // TCP-only — see net_wildcard comment above.
            if rule.protocol != Protocol::Tcp {
                continue;
            }
            for &p in &rule.ports {
                connect_ports.insert(p);
            }
        }
        for &p in &policy.http_ports {
            connect_ports.insert(p);
        }
        for port in connect_ports {
            add_net_rule(&ruleset_fd, port, LANDLOCK_ACCESS_NET_CONNECT_TCP).map_err(|e| {
                SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(e))
            })?;
        }
    }

    // Step 6 — enforce (irreversible).
    syscall::landlock_restrict_self(&ruleset_fd, 0).map_err(|e| {
        SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(
            ConfinementError::Landlock(format!("restrict_self: {}", e)),
        ))
    })?;

    Ok(())
}

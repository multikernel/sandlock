use std::os::fd::OwnedFd;
use std::path::Path;

use crate::error::{ConfinementError, SandlockError};
use crate::protection::{Protection, ProtectionPolicy, ProtectionStatus};
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

/// Indices N for which `/dev/nvidiaN` exists. Used for the "all GPUs"
/// (`gpu_devices == []`) case. Matches `nvidia<digits>` exactly, so the
/// control/capability nodes (`nvidiactl`, `nvidia-uvm`, `nvidia-caps`,
/// `nvidia-modeset`) are excluded.
fn present_gpu_indices() -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/dev") else {
        return Vec::new();
    };
    // `parse::<u32>` accepts only "nvidia<digits>", rejecting nvidiactl,
    // nvidia-uvm, nvidia-caps, nvidia-modeset, etc.
    let mut out: Vec<u32> = entries
        .flatten()
        .filter_map(|ent| ent.file_name().to_str()?.strip_prefix("nvidia")?.parse().ok())
        .collect();
    out.sort_unstable();
    out
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

/// Compute the `scoped` mask from the per-protection resolutions of
/// the two scope protections.
///
/// # Precondition
///
/// The caller must have already rejected any `Protection` whose
/// `ProtectionStatus::resolve()` is `ProtectionStatus::Unavailable` —
/// otherwise this function silently produces a mask that omits the bit,
/// which is the right answer for `Disabled` / `Degraded` but the *wrong*
/// answer for `Unavailable` (where the call should never have reached
/// the mask-compute stage). `confine_inner` enforces this by walking
/// `Protection::all()` and returning `ProtectionUnavailable` for any
/// strict-unavailable protection before this function is called.
///
/// In test builds a `debug_assert!` pins the invariant so a future
/// caller that forgets the upstream guard fails loudly.
pub(crate) fn compute_scope_mask(abi: u32, pol: &ProtectionPolicy) -> u64 {
    debug_assert!(
        !matches!(
            ProtectionStatus::resolve(Protection::SignalScope, abi, pol),
            ProtectionStatus::Unavailable,
        ),
        "compute_scope_mask called with SignalScope Unavailable; \
         caller must filter via confine_inner's Protection::all() walk first"
    );
    debug_assert!(
        !matches!(
            ProtectionStatus::resolve(Protection::AbstractUnixSocketScope, abi, pol),
            ProtectionStatus::Unavailable,
        ),
        "compute_scope_mask called with AbstractUnixSocketScope Unavailable; \
         caller must filter via confine_inner's Protection::all() walk first"
    );

    let mut mask: u64 = 0;
    if ProtectionStatus::resolve(Protection::AbstractUnixSocketScope, abi, pol)
        == ProtectionStatus::Active
    {
        mask |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
    }
    if ProtectionStatus::resolve(Protection::SignalScope, abi, pol) == ProtectionStatus::Active {
        mask |= LANDLOCK_SCOPE_SIGNAL;
    }
    mask
}

/// Compute the `handled_access_fs` mask. Starts from the ABI-cumulative
/// base set and masks off bits whose corresponding `Protection` is
/// `Disabled` or `Degraded` in the policy.
///
/// `Degraded` means a `Degradable` protection on a host that does not
/// provide the underlying kernel hook — declaring the bit anyway would
/// fail `landlock_create_ruleset` with EINVAL and break the silent-skip
/// contract. `base_fs_access(abi)` already gates each extension bit on
/// the host ABI, so on a real host the `Degraded` bit is not in the
/// base mask in the first place. Masking it off here is defence in
/// depth: the contract is uniformly expressed regardless of how
/// `base_fs_access` evolves, and the synthetic-ABI integration tests
/// can exercise this code path directly.
pub fn compute_fs_mask(abi: u32, pol: &ProtectionPolicy) -> u64 {
    let mut mask = base_fs_access(abi);
    if matches!(
        ProtectionStatus::resolve(Protection::FsRefer, abi, pol),
        ProtectionStatus::Disabled | ProtectionStatus::Degraded
    ) {
        mask &= !LANDLOCK_ACCESS_FS_REFER;
    }
    if matches!(
        ProtectionStatus::resolve(Protection::FsTruncate, abi, pol),
        ProtectionStatus::Disabled | ProtectionStatus::Degraded
    ) {
        mask &= !LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if matches!(
        ProtectionStatus::resolve(Protection::FsIoctlDev, abi, pol),
        ProtectionStatus::Disabled | ProtectionStatus::Degraded
    ) {
        mask &= !LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    mask
}

/// Compute the `handled_access_net` mask AND the TCP wildcard flag,
/// preserving the wildcard behaviour: when any TCP `--net-allow` rule
/// covers every port we drop `CONNECT_TCP` from the handled set (the
/// on-behalf path is then the sole enforcer).
///
/// `--net-deny` is default-allow: every TCP connect must reach the
/// on-behalf seccomp path (the DenyList enforcer), so Landlock must not
/// gate `CONNECT_TCP` at all. A non-empty `net_deny` therefore forces the
/// wildcard treatment, exactly like an all-ports `--net-allow` rule.
///
/// Returns `(0, false)` when `Protection::NetTcp` is not `Active`
/// (either disabled by policy or degraded on a kernel that does not
/// provide TCP network hooks).
///
/// Returning both the mask and the wildcard flag keeps the rule-
/// installation site in `confine_inner` in sync with the mask: the
/// caller no longer recomputes the wildcard from `sandbox.net_allow`,
/// so divergence between the two derivations is impossible by
/// construction.
pub fn compute_net_mask(
    abi: u32,
    pol: &ProtectionPolicy,
    sandbox: &Sandbox,
    handle_net: bool,
) -> (u64, bool) {
    if !handle_net {
        return (0, false);
    }
    if ProtectionStatus::resolve(Protection::NetTcp, abi, pol) != ProtectionStatus::Active {
        return (0, false);
    }
    use crate::sandbox::Protocol;
    let net_wildcard = !sandbox.net_deny.is_empty()
        || sandbox
            .net_allow
            .iter()
            .any(|r| r.protocol == Protocol::Tcp && r.all_ports);
    let mut mask = if net_wildcard {
        LANDLOCK_ACCESS_NET_BIND_TCP
    } else {
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    };
    // `--net-deny-bind` is default-allow: every TCP bind must reach the
    // on-behalf seccomp handler (the bind denylist enforcer), so Landlock
    // must not gate BIND_TCP. Drop it from the handled set; the on-behalf
    // path becomes the sole bind enforcer. (Mutually exclusive with
    // `--net-allow-bind`, so no kernel bind rules are installed either.)
    // `--net-allow-bind '*'` likewise leaves BIND_TCP unhandled: every
    // port is allowed and nothing enforces on the on-behalf path.
    if !sandbox.net_deny_bind.is_empty() || sandbox.net_allow_bind.is_all() {
        mask &= !LANDLOCK_ACCESS_NET_BIND_TCP;
    }
    (mask, net_wildcard)
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
    // produces `ProtectionStatus::Active` for every protection —
    // preserving the historical `MIN_ABI = 6` floor exactly.
    let pol = &policy.protection_policy;
    for protection in Protection::all() {
        if ProtectionStatus::resolve(protection, abi, pol) == ProtectionStatus::Unavailable {
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
    //
    // `compute_net_mask` is the single source of truth for both the
    // handled-net mask and the TCP wildcard flag: the rule-installation
    // block below uses the same `net_wildcard` value the mask was
    // derived from, so the two cannot diverge.
    use crate::sandbox::Protocol;
    let (handled_access_net, net_wildcard) = compute_net_mask(abi, pol, policy, handle_net);

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
    // Intersect the per-path write mask with the resolved handled set so
    // every installed rule is a subset of `handled_access_fs` by
    // construction. `compute_fs_mask` drops the REFER/TRUNCATE/IOCTL_DEV
    // bit for any FS protection that is Disabled or Degraded; without this
    // intersection the writable-path rule would still request the dropped
    // bit and `landlock_add_rule` would reject it with EINVAL. (The file
    // path inside `add_path_rule` further narrows this with `& ACCESS_FILE`,
    // which preserves the subset property.)
    let fs_write_mask = write_access(abi) & handled_access_fs;
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
    if let Some(ref devices) = policy.gpu_devices {
        // Shared control nodes: required for ANY GPU use, not per-GPU.
        // (nvidiactl = RM control channel; uvm = unified memory.)
        for path in &["/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools"] {
            let _ = add_path_rule(&ruleset_fd, Path::new(path), fs_write_mask);
            // Ignore errors — nodes may not exist (e.g. uvm before first use)
        }

        // Per-GPU render nodes. Each physical GPU N is a distinct node
        // /dev/nvidiaN; opening it O_RDWR is REQUIRED to map that GPU. Granting
        // only the requested indices makes selection a hard kernel boundary
        // instead of the soft CUDA_VISIBLE_DEVICES hint set in context.rs.
        // Empty list = all present GPUs.
        let indices = if devices.is_empty() {
            present_gpu_indices()
        } else {
            devices.clone()
        };
        for idx in indices {
            let node = format!("/dev/nvidia{idx}");
            let _ = add_path_rule(&ruleset_fd, Path::new(&node), fs_write_mask);
        }

        // DRM render nodes. /dev/dri is a directory of per-GPU card*/renderD*
        // nodes; a single rule exposes ALL of them, which would reopen the
        // sharing hole this selection closes. CUDA compute does not need
        // /dev/dri, so only grant it for the all-GPUs case; per-index DRM
        // mapping would need a PCI-BDF -> renderD* lookup (future work).
        if devices.is_empty() {
            let _ = add_path_rule(&ruleset_fd, Path::new("/dev/dri"), fs_write_mask);
        }

        // Read-only access to GPU sysfs/procfs
        for path in &[
            "/proc/driver/nvidia",
            "/sys/bus/pci/devices",
            "/sys/module/nvidia",
        ] {
            let _ = add_path_rule(&ruleset_fd, Path::new(path), READ_ACCESS);
        }
    }

    // Step 5 -- add network port rules. Skip entirely when
    // `Protection::NetTcp` is not `Active` (either policy-disabled or
    // degraded on a host without TCP network hooks) — `handled_access_net`
    // is 0 in that case and the kernel would reject any rule with EINVAL.
    let net_tcp_active =
        ProtectionStatus::resolve(Protection::NetTcp, abi, pol) == ProtectionStatus::Active;
    // `BindPorts::All` installs no rules: BIND_TCP was dropped from the
    // handled set, so every bind is already allowed.
    if handle_net && net_tcp_active {
        if let crate::sandbox::BindPorts::Ports(ports) = &policy.net_allow_bind {
            for &port in ports {
                add_net_rule(&ruleset_fd, port, LANDLOCK_ACCESS_NET_BIND_TCP).map_err(|e| {
                    SandlockError::Runtime(crate::error::SandboxRuntimeError::Confinement(e))
                })?;
            }
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

// ============================================================
// Security-contract tests for the mask-compute helpers
// ============================================================
//
// These tests check the *observable* output bits of
// `compute_scope_mask` / `compute_fs_mask` / `compute_net_mask` against
// the Landlock kernel constants, not just that the policy-state
// HashMap was mutated. Each `ProtectionState` combined with each host
// ABI produces a specific bit pattern — these tests are the contract
// pin for the Landlock attrs that exit `confine_inner`. Drift here is
// a security bug, not a refactor cleanup.

#[cfg(test)]
mod mask_contract_tests {
    use super::*;
    use crate::protection::ProtectionState;
    use crate::Sandbox;

    // ---------- compute_scope_mask ----------

    #[test]
    fn scope_mask_strict_v6_sets_both_scope_bits() {
        let pol = ProtectionPolicy::strict_all();
        let mask = compute_scope_mask(6, &pol);
        assert_eq!(
            mask,
            LANDLOCK_SCOPE_SIGNAL | LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
            "strict_all on v6 host must request both v6 IPC scopes"
        );
    }

    #[test]
    fn scope_mask_disable_signal_clears_only_signal_bit() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::SignalScope, ProtectionState::Disabled);
        let mask = compute_scope_mask(6, &pol);
        assert_eq!(mask & LANDLOCK_SCOPE_SIGNAL, 0, "SIGNAL must be cleared");
        assert_eq!(
            mask & LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
            LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
            "ABSTRACT_UNIX_SOCKET must remain set"
        );
    }

    #[test]
    fn scope_mask_disable_abstract_unix_clears_only_abstract_bit() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::AbstractUnixSocketScope, ProtectionState::Disabled);
        let mask = compute_scope_mask(6, &pol);
        assert_eq!(
            mask & LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
            0,
            "ABSTRACT_UNIX_SOCKET must be cleared",
        );
        assert_eq!(
            mask & LANDLOCK_SCOPE_SIGNAL,
            LANDLOCK_SCOPE_SIGNAL,
            "SIGNAL must remain set",
        );
    }

    #[test]
    fn scope_mask_disable_both_returns_zero() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::SignalScope, ProtectionState::Disabled);
        pol.set(Protection::AbstractUnixSocketScope, ProtectionState::Disabled);
        assert_eq!(
            compute_scope_mask(6, &pol),
            0,
            "both scopes disabled on a capable host must produce mask=0"
        );
    }

    #[test]
    fn scope_mask_allow_degraded_on_v5_host_returns_zero() {
        // v5 does not provide either v6 scope; Degradable must skip
        // silently — observable as both bits absent.
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::SignalScope, ProtectionState::Degradable);
        pol.set(Protection::AbstractUnixSocketScope, ProtectionState::Degradable);
        assert_eq!(
            compute_scope_mask(5, &pol),
            0,
            "Degradable scopes on a v5 host must contribute no bits"
        );
    }

    // ---------- compute_fs_mask ----------

    #[test]
    fn fs_mask_strict_v6_includes_all_fs_protection_bits() {
        let pol = ProtectionPolicy::strict_all();
        let mask = compute_fs_mask(6, &pol);
        for (bit, name) in [
            (LANDLOCK_ACCESS_FS_REFER, "REFER"),
            (LANDLOCK_ACCESS_FS_TRUNCATE, "TRUNCATE"),
            (LANDLOCK_ACCESS_FS_IOCTL_DEV, "IOCTL_DEV"),
        ] {
            assert_eq!(
                mask & bit,
                bit,
                "{} bit must be set in the strict v6 fs mask",
                name,
            );
        }
    }

    #[test]
    fn fs_mask_disable_fs_refer_clears_only_refer_bit() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::FsRefer, ProtectionState::Disabled);
        let mask = compute_fs_mask(6, &pol);
        assert_eq!(mask & LANDLOCK_ACCESS_FS_REFER, 0);
        assert_eq!(mask & LANDLOCK_ACCESS_FS_TRUNCATE, LANDLOCK_ACCESS_FS_TRUNCATE);
        assert_eq!(mask & LANDLOCK_ACCESS_FS_IOCTL_DEV, LANDLOCK_ACCESS_FS_IOCTL_DEV);
    }

    #[test]
    fn fs_mask_disable_fs_truncate_clears_only_truncate_bit() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::FsTruncate, ProtectionState::Disabled);
        let mask = compute_fs_mask(6, &pol);
        assert_eq!(mask & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
        assert_eq!(mask & LANDLOCK_ACCESS_FS_REFER, LANDLOCK_ACCESS_FS_REFER);
        assert_eq!(mask & LANDLOCK_ACCESS_FS_IOCTL_DEV, LANDLOCK_ACCESS_FS_IOCTL_DEV);
    }

    #[test]
    fn fs_mask_disable_fs_ioctl_dev_clears_only_ioctl_dev_bit() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::FsIoctlDev, ProtectionState::Disabled);
        let mask = compute_fs_mask(6, &pol);
        assert_eq!(mask & LANDLOCK_ACCESS_FS_IOCTL_DEV, 0);
        assert_eq!(mask & LANDLOCK_ACCESS_FS_REFER, LANDLOCK_ACCESS_FS_REFER);
        assert_eq!(mask & LANDLOCK_ACCESS_FS_TRUNCATE, LANDLOCK_ACCESS_FS_TRUNCATE);
    }

    #[test]
    fn fs_mask_degraded_protections_get_masked_off_on_low_abi_host() {
        // FsIoctlDev requires v5; on a v4 host it is Degraded. The bit
        // must NOT appear in the mask — declaring a bit the kernel
        // doesn't know would fail landlock_create_ruleset with EINVAL.
        // This is the bug class commit bf9490d fixed; pin it here.
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::FsIoctlDev, ProtectionState::Degradable);
        let mask = compute_fs_mask(4, &pol);
        assert_eq!(
            mask & LANDLOCK_ACCESS_FS_IOCTL_DEV,
            0,
            "Degraded FsIoctlDev on a v4 host must NOT contribute the IOCTL_DEV bit",
        );
    }

    // ---------- compute_net_mask ----------

    fn empty_sandbox() -> Sandbox {
        Sandbox::builder()
            .build_unchecked()
            .expect("minimal builder must produce a sandbox in unit tests")
    }

    #[test]
    fn net_mask_handle_net_false_returns_zero_no_wildcard() {
        let pol = ProtectionPolicy::strict_all();
        let sb = empty_sandbox();
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, false);
        assert_eq!(mask, 0, "handle_net=false → mask is zero");
        assert!(!wildcard, "handle_net=false → wildcard is false");
    }

    #[test]
    fn net_mask_strict_no_wildcard_sets_bind_and_connect_bits() {
        let pol = ProtectionPolicy::strict_all();
        let sb = empty_sandbox();
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        assert_eq!(
            mask,
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
            "strict NetTcp with no wildcard rule → both BIND_TCP and CONNECT_TCP",
        );
        assert!(!wildcard);
    }

    #[test]
    fn net_mask_disable_net_tcp_returns_zero() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::NetTcp, ProtectionState::Disabled);
        let sb = empty_sandbox();
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        assert_eq!(
            mask, 0,
            "disabled NetTcp must produce mask=0 regardless of handle_net",
        );
        assert!(!wildcard);
    }

    #[test]
    fn net_mask_degraded_net_tcp_on_v3_host_returns_zero() {
        // NetTcp requires v4. On a v3 host Degradable resolves to
        // Degraded, contributing no bits.
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::NetTcp, ProtectionState::Degradable);
        let sb = empty_sandbox();
        let (mask, wildcard) = compute_net_mask(3, &pol, &sb, true);
        assert_eq!(mask, 0);
        assert!(!wildcard);
    }

    #[test]
    fn net_mask_net_deny_forces_wildcard_dropping_connect_tcp() {
        // `--net-deny` is default-allow and enforced on the on-behalf
        // seccomp path, so Landlock must not gate CONNECT_TCP: a non-empty
        // net_deny forces the wildcard treatment (BIND_TCP only), exactly
        // like an all-ports --net-allow rule. This pins the reconciliation
        // of the net-deny runtime relaxation with compute_net_mask.
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_deny("10.0.0.0/8")
            .build()
            .expect("net_deny sandbox builds");
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        assert_eq!(
            mask,
            LANDLOCK_ACCESS_NET_BIND_TCP,
            "net_deny must drop CONNECT_TCP so all TCP connects reach the on-behalf path",
        );
        assert!(wildcard, "net_deny must set the wildcard flag");
    }

    #[test]
    fn net_mask_net_deny_bind_drops_bind_tcp() {
        // `--net-deny-bind` is default-allow and enforced on the on-behalf
        // bind() path, so Landlock must NOT gate BIND_TCP: every TCP bind has
        // to reach the supervisor's denylist check. The mask keeps CONNECT_TCP
        // (no connect rules here) but drops BIND_TCP.
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_deny_bind("8080")
            .build()
            .expect("net_deny_bind sandbox builds");
        let (mask, _wildcard) = compute_net_mask(6, &pol, &sb, true);
        assert_eq!(
            mask & LANDLOCK_ACCESS_NET_BIND_TCP,
            0,
            "net_deny_bind must drop BIND_TCP so all TCP binds reach the on-behalf path",
        );
        assert_ne!(
            mask & LANDLOCK_ACCESS_NET_CONNECT_TCP,
            0,
            "net_deny_bind must not affect CONNECT_TCP handling",
        );
    }

    #[test]
    fn net_mask_bind_all_drops_bind_tcp() {
        // `--net-allow-bind '*'` allows every TCP bind: Landlock must not
        // handle BIND_TCP at all (no rules needed, no on-behalf enforcement).
        // CONNECT_TCP handling is unaffected.
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_allow_bind("*")
            .build()
            .expect("wildcard allow-bind sandbox builds");
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        assert_eq!(
            mask,
            LANDLOCK_ACCESS_NET_CONNECT_TCP,
            "bind-all must drop BIND_TCP from the handled set and keep CONNECT_TCP",
        );
        assert!(!wildcard, "bind-all must not force the connect wildcard");
    }

    #[test]
    fn net_mask_bind_all_with_net_deny_yields_zero_mask() {
        // net_deny drops CONNECT_TCP (on-behalf enforces connects) and
        // bind-all drops BIND_TCP: nothing is left for Landlock to handle.
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_deny("10.0.0.0/8")
            .net_allow_bind("*")
            .build()
            .expect("net_deny + wildcard allow-bind sandbox builds");
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        assert_eq!(mask, 0, "net_deny + bind-all leaves no handled net access");
        assert!(wildcard, "net_deny must still set the wildcard flag");
    }
}

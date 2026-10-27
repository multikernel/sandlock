use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use landlock::{
    make_bitflags, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
};

use crate::error::{ConfinementError, SandlockError};
use crate::grant::Grant;
use crate::protection::{Protection, ProtectionPolicy, ProtectionStatus};
use crate::sandbox::Sandbox;
use crate::sys::structs::{LANDLOCK_CREATE_RULESET_VERSION, SYS_LANDLOCK_CREATE_RULESET};
use crate::sys::syscall;

const READ_ACCESS: BitFlags<AccessFs> = make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir});

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
        .filter_map(|ent| {
            ent.file_name()
                .to_str()?
                .strip_prefix("nvidia")?
                .parse()
                .ok()
        })
        .collect();
    out.sort_unstable();
    out
}

/// First ABI whose Landlock gates connect() and addressed sends to named unix
/// sockets (`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`).
const RESOLVE_UNIX_ABI: u32 = 9;

/// Whether the host's Landlock gates named unix sockets itself. When it does,
/// the caller connects in its own name, so peers see its credentials instead
/// of the supervisor's.
pub(crate) fn gates_named_unix() -> bool {
    abi_version().is_ok_and(|abi| abi >= RESOLVE_UNIX_ABI)
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

/// Files the supervisor answers for with generated content. Their real
/// inode must not be granted, or any other spelling of them reads the host's.
fn shadowed_files() -> impl Iterator<Item = &'static Path> {
    crate::procfs::SHADOWED_ETC_FILES.iter().map(Path::new)
}

/// How confinement treats a grant under /proc. Only `Landlock` installs the
/// grant as given, which follows a magic link to its target; the others turn
/// a grant on such a link into one that grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcGrants {
    Landlock,
    /// The supervisor serves procfs and the files it generates.
    Served,
    /// The grant names the jail's copy of the path.
    Jailed,
}

impl ProcGrants {
    pub(crate) fn of(supervised: bool, jailed: bool) -> Self {
        match (supervised, jailed) {
            (_, true) => ProcGrants::Jailed,
            (true, false) => ProcGrants::Served,
            (false, false) => ProcGrants::Landlock,
        }
    }
}

/// Install a read grant on `dir` as rules on its entries, leaving out the
/// shadowed files beneath it. Landlock cannot deny a file inside a granted
/// tree, so this is the only way to grant the rest. A file created directly
/// in `dir` after this is not covered; the grants this applies to are
/// read-only host trees such as /etc. Entries are opened beneath `dir`'s
/// descriptor so a pinned grant stays on the tree it was pinned to.
fn add_read_rules_around_shadowed(
    mut ruleset: RulesetCreated,
    dir: File,
    path: &Path,
) -> Result<RulesetCreated, ConfinementError> {
    use nix::fcntl::OFlag;
    let fail = |e| ConfinementError::Landlock(format!("read dir {:?}: {}", path, e));
    let mut entries = nix::dir::Dir::openat(
        Some(dir.as_raw_fd()),
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(fail)?;
    for entry in entries.iter().flatten() {
        let name = Path::new(std::ffi::OsStr::from_bytes(entry.file_name().to_bytes()));
        if name == Path::new(".") || name == Path::new("..") {
            continue;
        }
        let child = path.join(name);
        if shadowed_files().any(|f| f == child) || crate::procfs::is_supervised_proc_grant(&child) {
            continue;
        }
        // An entry that vanished or cannot be referenced costs only itself.
        let Ok(file) = open_at(dir.as_raw_fd(), name, libc::O_NOFOLLOW) else {
            continue;
        };
        // A link is never the object of an access; its target has its own rule.
        if file.metadata().is_ok_and(|m| m.is_symlink()) {
            continue;
        }
        if shadowed_files().any(|f| f.starts_with(&child)) {
            ruleset = add_read_rules_around_shadowed(ruleset, file, &child)?;
        } else {
            let _ = add_file_beneath_rule(&mut ruleset, file, &child, READ_ACCESS);
        }
    }
    add_file_beneath_rule(ruleset, dir, path, AccessFs::ReadDir)
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
pub(crate) fn compute_scope_mask(abi: u32, pol: &ProtectionPolicy) -> BitFlags<Scope> {
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

    let mut mask: BitFlags<Scope> = Default::default();
    // This scope is also what keeps the confined child, which shares the
    // supervisor's uid, off the supervisor's abstract control socket.
    if ProtectionStatus::resolve(Protection::AbstractUnixSocketScope, abi, pol)
        == ProtectionStatus::Active
    {
        mask |= Scope::AbstractUnixSocket;
    }
    if ProtectionStatus::resolve(Protection::SignalScope, abi, pol) == ProtectionStatus::Active {
        mask |= Scope::Signal;
    }
    mask
}

/// Compute the raw `handled_access_fs` mask, excluding disabled or degraded
/// protections. Returns kernel access bits without exposing crate-specific types.
pub fn compute_fs_mask(abi: u32, pol: &ProtectionPolicy) -> u64 {
    if abi == 0 {
        return 0;
    }
    // Only explicitly supported rights are handled so that `landlock` dependency updates
    // do not silently widen the ruleset.
    let mut mask = AccessFs::Execute
        | AccessFs::WriteFile
        | AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::RemoveDir
        | AccessFs::RemoveFile
        | AccessFs::MakeChar
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeBlock
        | AccessFs::MakeSym;
    if abi >= 2 {
        mask |= AccessFs::Refer;
    }
    if abi >= 3 {
        mask |= AccessFs::Truncate;
    }
    if abi >= 5 {
        mask |= AccessFs::IoctlDev;
    }
    if abi >= RESOLVE_UNIX_ABI {
        mask |= AccessFs::ResolveUnix;
    }
    if matches!(
        ProtectionStatus::resolve(Protection::FsRefer, abi, pol),
        ProtectionStatus::Disabled | ProtectionStatus::Degraded
    ) {
        mask &= !AccessFs::Refer;
    }
    if matches!(
        ProtectionStatus::resolve(Protection::FsTruncate, abi, pol),
        ProtectionStatus::Disabled | ProtectionStatus::Degraded
    ) {
        mask &= !AccessFs::Truncate;
    }
    if matches!(
        ProtectionStatus::resolve(Protection::FsIoctlDev, abi, pol),
        ProtectionStatus::Disabled | ProtectionStatus::Degraded
    ) {
        mask &= !AccessFs::IoctlDev;
    }
    mask.bits()
}

/// Compute the `handled_access_net` mask AND the TCP wildcard flag,
/// preserving the wildcard behaviour: when any TCP `--net-allow` rule
/// covers every port we drop `CONNECT_TCP` from the handled set (the
/// on-behalf path is then the sole enforcer).
///
/// Outbound modes, derived from the separated configuration:
/// deny-only (`net_deny` present, no explicit `net_allow` and no
/// HTTP-only allow layer) forces the wildcard treatment because every TCP
/// connect must reach the on-behalf DenyList enforcer. A combined policy
/// with a finite allowlist keeps `CONNECT_TCP` handled so Landlock still
/// gates ports; a combined policy whose allowlist covers every TCP port
/// drops it like an allow-only wildcard. HTTP-derived reachability never
/// uses the all-ports form, so it never forces the wildcard by itself.
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
        return (Default::default(), false);
    }
    if ProtectionStatus::resolve(Protection::NetTcp, abi, pol) != ProtectionStatus::Active {
        return (Default::default(), false);
    }
    use crate::sandbox::Protocol;
    let allow_all_ports = sandbox
        .launch_and_approvable_net_allow()
        .iter()
        .any(|r| r.protocol == Protocol::Tcp && r.all_ports);
    let deny_only = !sandbox.net_deny.is_empty() && !sandbox.net_allow_is_active();
    let net_wildcard = deny_only || allow_all_ports;
    let mut mask = AccessNet::BindTcp | AccessNet::ConnectTcp;

    if net_wildcard {
        mask &= !AccessNet::ConnectTcp;
    }
    // `--net-deny-bind` is default-allow: every TCP bind must reach the
    // on-behalf seccomp handler (the bind denylist enforcer), so Landlock
    // must not gate BIND_TCP. Drop it from the handled set; the on-behalf
    // path becomes the sole bind enforcer. When an allowlist is also present,
    // the same supervisor path applies both layers with exact-match
    // semantics. `--net-allow-bind '*'` likewise leaves BIND_TCP unhandled:
    // every port is allowed and nothing enforces on the on-behalf path.
    // A listed port `0` needs no special case: a Landlock `BIND_TCP` rule
    // with port 0 permits only a `bind(0)` request (the kernel then chooses
    // an ephemeral port) and does not permit explicit `bind(nonzero)`.
    if !sandbox.net_deny_bind.is_empty() || sandbox.net_allow_bind.is_all() {
        mask &= !AccessNet::BindTcp;
    }
    (mask.bits(), net_wildcard)
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
///
/// # Prerequisites
///
/// The caller must set `PR_SET_NO_NEW_PRIVS` with `prctl(2)` before calling
/// this function. This function does not set it. Without it, Landlock
/// enforcement requires `CAP_SYS_ADMIN` in the current user namespace.
pub fn confine(policy: &Sandbox) -> Result<(), SandlockError> {
    confine_inner(policy, true, false)
}

/// As [`confine`], for a child whose opens the seccomp supervisor mediates.
pub(crate) fn confine_supervised(policy: &Sandbox) -> Result<(), SandlockError> {
    confine_inner(policy, true, true)
}

/// Apply Landlock filesystem confinement without TCP bind/connect rules.
///
/// # Prerequisites
///
/// The caller must set `PR_SET_NO_NEW_PRIVS` with `prctl(2)` before calling
/// this function. This function does not set it. Without it, Landlock
/// enforcement requires `CAP_SYS_ADMIN` in the current user namespace.
pub fn confine_filesystem(policy: &Sandbox) -> Result<(), SandlockError> {
    confine_inner(policy, false, false)
}

fn confine_inner(
    policy: &Sandbox,
    handle_net: bool,
    supervised: bool,
) -> Result<(), SandlockError> {
    let ruleset_error = |e: landlock::RulesetError| ConfinementError::Landlock(e.to_string());

    // Step 1 — detect host ABI version.
    let abi = abi_version()?;

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
            return Err(ConfinementError::ProtectionUnavailable {
                protection,
                required_abi: protection.min_abi(),
                host_abi: abi,
            }
            .into());
        }
    }

    // Step 3 — build handled_access_fs / handled_access_net / scoped.
    //
    // FS: cumulative ABI base set, with `Disabled` protections masked
    // off (FsRefer/FsTruncate/FsIoctlDev).
    let handled_access_fs = BitFlags::<AccessFs>::from_bits(compute_fs_mask(abi, pol))
        .expect("known filesystem rights");

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
    let handled_access_net =
        BitFlags::<AccessNet>::from_bits(handled_access_net).expect("known network rights");

    // Scope: IPC + signal isolation, each gated on its protection's
    // resolved state.
    let scoped = compute_scope_mask(abi, pol);

    // Step 3 — create ruleset.
    // Sandlock enforces and degrades the rules already. We don't want the crate to silently
    // drop our requirements by using the default `BestEffort.`
    let mut ruleset = Ruleset::default().set_compatibility(CompatLevel::HardRequirement);

    if !handled_access_fs.is_empty() {
        ruleset = ruleset
            .handle_access(handled_access_fs)
            .map_err(ruleset_error)?;
    }

    if !handled_access_net.is_empty() {
        ruleset = ruleset
            .handle_access(handled_access_net)
            .map_err(ruleset_error)?;
    }

    if !scoped.is_empty() {
        ruleset = ruleset.scope(scoped).map_err(ruleset_error)?;
    }

    let mut ruleset = ruleset.create().map_err(ruleset_error)?;

    // Step 4 — add filesystem path rules.
    // When chroot is active, translate virtual paths (inside chroot) to host
    // paths by prepending the chroot root.  Skip paths that don't exist in
    // the rootfs.  Only chroot-translated paths are added — host paths are
    // NOT added, so any seccomp fallthrough is blocked by Landlock (fail-closed).
    // The PT_INTERP patching in handle_chroot_exec ensures the kernel loads
    // the image's ELF interpreter via an injected fd, not a host path.
    let chroot_root = policy.chroot.as_deref();
    let served = ProcGrants::of(supervised, chroot_root.is_some()) == ProcGrants::Served;
    // Writable-path grants use the resolved handled set so disabled or
    // degraded rights cannot be reintroduced. add_path_beneath_rule further
    // removes directory-only rights for non-directory paths.
    for grant in &policy.fs_writable {
        let path = grant_path(grant)?;
        if served && crate::procfs::is_supervised_proc_grant(&path) {
            continue;
        }
        if let Some(file) = open_grant(grant, &path, chroot_root)? {
            ruleset = add_file_beneath_rule(ruleset, file, &path, handled_access_fs)?;
        }
    }

    for grant in &policy.fs_readable {
        let path = grant_path(grant)?;
        // The supervisor serves procfs reads: a rule would let any link reach
        // what the handlers hide by name. Without a supervisor the rule is all
        // there is, so it stays.
        if served
            && (crate::procfs::is_supervised_proc_grant(&path)
                || shadowed_files().any(|f| f == path))
        {
            continue;
        }
        let Some(file) = open_grant(grant, &path, chroot_root)? else {
            continue;
        };
        ruleset = if served && shadowed_files().any(|f| f.starts_with(&path)) {
            add_read_rules_around_shadowed(ruleset, file, &path)?
        } else {
            add_file_beneath_rule(ruleset, file, &path, READ_ACCESS)?
        };
    }

    // GPU device paths (when gpu_devices is set)
    if let Some(ref devices) = policy.gpu_devices {
        // Shared control nodes: required for ANY GPU use, not per-GPU.
        // (nvidiactl = RM control channel; uvm = unified memory.)
        for path in &["/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools"] {
            // Ignore errors — nodes may not exist (e.g. uvm before first use)
            let _ = add_path_beneath_rule(&mut ruleset, path, handled_access_fs);
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
            let _ = add_path_beneath_rule(&mut ruleset, node, handled_access_fs);
        }

        // DRM render nodes. /dev/dri is a directory of per-GPU card*/renderD*
        // nodes; a single rule exposes ALL of them, which would reopen the
        // sharing hole this selection closes. CUDA compute does not need
        // /dev/dri, so only grant it for the all-GPUs case; per-index DRM
        // mapping would need a PCI-BDF -> renderD* lookup (future work).
        if devices.is_empty() {
            let _ = add_path_beneath_rule(&mut ruleset, "/dev/dri", handled_access_fs);
        }

        // Read-only access to GPU sysfs/procfs
        for path in &[
            "/proc/driver/nvidia",
            "/sys/bus/pci/devices",
            "/sys/module/nvidia",
        ] {
            let _ = add_path_beneath_rule(&mut ruleset, path, READ_ACCESS);
        }
    }

    // Step 5 -- add network port rules. Skip entirely when
    // `Protection::NetTcp` is not `Active` (either policy-disabled or
    // degraded on a host without TCP network hooks) — `handled_access_net`
    // is 0 in that case and the kernel would reject any rule with EINVAL.
    let net_tcp_active =
        ProtectionStatus::resolve(Protection::NetTcp, abi, pol) == ProtectionStatus::Active;
    // `BindPorts::All` installs no rules: BIND_TCP was dropped from the
    // handled set, so every bind is already allowed. A listed port `0` is
    // installed verbatim: Landlock permits only a `bind(0)` request with it
    // (the kernel then chooses an ephemeral port), not explicit nonzero binds.
    if handle_net && net_tcp_active && handled_access_net.contains(AccessNet::BindTcp) {
        if let crate::sandbox::BindPorts::Ports(ports) = &policy.net_allow_bind {
            for &port in ports {
                ruleset = add_net_rule(ruleset, port, AccessNet::BindTcp)?;
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
        // Explicit rules plus HTTP-derived reachability; HTTP intercept ports
        // are also added below (derived ports are a subset of them, kept here
        // so the gate stays in sync with the resolved allowlist).
        for rule in policy.launch_and_approvable_net_allow().iter() {
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
            ruleset = add_net_rule(ruleset, port, AccessNet::ConnectTcp)?;
        }
    }

    // Step 6 — enforce (irreversible).
    enforce_ruleset(ruleset)?;
    Ok(())
}

fn enforce_ruleset(ruleset: RulesetCreated) -> Result<(), ConfinementError> {
    // The callers already set `PR_SET_NO_NEW_PRIVS`. We don't need to do that again in the
    // crate.
    let status = ruleset
        .no_new_privs(false)
        .restrict_self()
        .map_err(|e| ConfinementError::Landlock(e.to_string()))?;
    // Under HardRequirement, compatibility failures permanently set the crate's
    // state to Dummy. Later add_rule/scope/restrict_self calls can then return Ok
    // without syscalls. Since optional path grants ignore errors, this guard is
    // load-bearing: NotEnforced must fail closed, not silently remove confinement.
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(ConfinementError::Landlock(format!(
            "ruleset was not fully enforced: {:?}",
            status.ruleset
        )));
    }

    Ok(())
}

/// Helper for wrapping the error with the given port and the rule.
/// Use this instead of `landlock`'s `add_rule` to have a better error message.
fn add_net_rule<R: RulesetCreatedAttr>(
    ruleset: R,
    port: u16,
    rule: AccessNet,
) -> Result<R, ConfinementError> {
    ruleset
        .add_rule(NetPort::new(port, rule))
        .map_err(|e| ConfinementError::Landlock(format!("add net rule for port {}: {}", port, e)))
}

/// Helper for adding a path-beneath rule.
/// Prefer this instead of using `landlock::PathBeneath` directly since this one
/// contains an important fix and it wraps the error with the given path and rule.
fn add_path_beneath_rule<R, P, A>(ruleset: R, path: P, access: A) -> Result<R, ConfinementError>
where
    R: RulesetCreatedAttr,
    P: AsRef<Path>,
    A: Into<BitFlags<AccessFs>>,
{
    let path = path.as_ref();
    let file = open_at(libc::AT_FDCWD, path, 0)
        .map_err(|e| ConfinementError::Landlock(format!("open path {:?}: {}", path, e)))?;
    add_file_beneath_rule(ruleset, file, path, access)
}

fn grant_path(grant: &Grant) -> Result<std::borrow::Cow<'_, Path>, ConfinementError> {
    grant
        .path()
        .ok_or_else(|| ConfinementError::Landlock("fd grant has no path".into()))
}

/// The inode a grant names. A descriptor is used as is: reopening its path
/// would follow whatever the path names by now. Under a chroot a path names
/// the jail's copy, and one the jail lacks names nothing.
fn open_grant(
    grant: &Grant,
    path: &Path,
    chroot_root: Option<&Path>,
) -> Result<Option<File>, ConfinementError> {
    let fail = |e| ConfinementError::Landlock(format!("open path {:?}: {}", path, e));
    if let Some(fd) = grant.as_fd() {
        return fd.try_clone().map(|fd| Some(fd.into())).map_err(fail);
    }
    let host = match chroot_root {
        Some(root) => root.join(path.strip_prefix("/").unwrap_or(path)),
        None => path.to_path_buf(),
    };
    if chroot_root.is_some() && !host.exists() {
        return Ok(None);
    }
    open_at(libc::AT_FDCWD, &host, 0).map(Some).map_err(fail)
}

/// Open directly: OpenOptions masks out O_PATH on musl.
/// See: https://github.com/rust-lang/rust/issues/164464
fn open_at(dirfd: RawFd, path: &Path, flags: i32) -> io::Result<File> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c_path` is a valid, NUL-terminated string.
    let fd = unsafe {
        libc::openat(
            dirfd,
            c_path.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | flags,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a fresh descriptor. File takes sole ownership.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn add_file_beneath_rule<R, A>(
    ruleset: R,
    file: File,
    path: &Path,
    access: A,
) -> Result<R, ConfinementError>
where
    R: RulesetCreatedAttr,
    A: Into<BitFlags<AccessFs>>,
{
    let fail = |e| ConfinementError::Landlock(format!("open path {:?}: {}", path, e));
    let metadata = file.metadata().map_err(fail)?;

    let mut access = access.into();
    if !metadata.is_dir() {
        // Directory-only rights are invalid on files/device nodes.
        // V9 is the highest ABI supported by landlock 0.4.7. This
        // filters file-applicable rights, not host ABI availability.
        access &= AccessFs::from_file(landlock::ABI::V9);
    }

    ruleset
        .add_rule(PathBeneath::new(file, access))
        .map_err(|e| ConfinementError::Landlock(format!("add path rule for {:?}: {}", path, e)))
}

// ============================================================
// Security-contract tests for the mask-compute helpers
// ============================================================
//
// These tests check the *observable* output bits of
// `compute_scope_mask` / `compute_fs_mask` / `compute_net_mask` against
// the Landlock crate's access flags, not just that the policy-state
// HashMap was mutated. Each `ProtectionState` combined with each host
// ABI produces a specific bit pattern — these tests are the contract
// pin for the Landlock attrs that exit `confine_inner`. Drift here is
// a security bug, not a refactor cleanup.

#[cfg(test)]
mod mask_contract_tests {

    use super::*;
    use crate::protection::ProtectionState;
    use crate::Sandbox;

    #[test]
    fn ignored_compatibility_failure_must_not_disable_confinement() {
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::ReadFile | AccessFs::ReadDir)
            .unwrap()
            .create()
            .unwrap()
            .set_compatibility(CompatLevel::HardRequirement);
        let file = tempfile::tempfile().unwrap();

        // A directory-only right on a regular file fails compatibility and
        // permanently poisons the ruleset, even though the error is ignored.
        assert!((&mut ruleset)
            .add_rule(PathBeneath::new(&file, AccessFs::ReadDir))
            .is_err());
        // Subsequent valid grants can misleadingly succeed in Dummy state.
        (&mut ruleset)
            .add_rule(PathBeneath::new(&file, AccessFs::ReadFile))
            .unwrap();

        // Dummy restrict_self performs no confinement syscall. Sandlock must
        // reject its successful-but-NotEnforced result, not return success.
        let status = ruleset
            .try_clone()
            .unwrap()
            .no_new_privs(false)
            .restrict_self()
            .unwrap();
        assert_eq!(status.ruleset, RulesetStatus::NotEnforced);
        assert!(matches!(
            enforce_ruleset(ruleset),
            Err(ConfinementError::Landlock(_))
        ));
    }

    // ---------- compute_scope_mask ----------

    #[test]
    fn scope_mask_strict_v6_sets_both_scope_bits() {
        let pol = ProtectionPolicy::strict_all();
        let mask = compute_scope_mask(6, &pol);
        assert_eq!(
            mask,
            Scope::Signal | Scope::AbstractUnixSocket,
            "strict_all on v6 host must request both v6 IPC scopes"
        );
    }

    #[test]
    fn scope_mask_disable_signal_clears_only_signal_bit() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::SignalScope, ProtectionState::Disabled);
        let mask = compute_scope_mask(6, &pol);
        assert!(!mask.contains(Scope::Signal), "SIGNAL must be cleared");
        assert!(
            mask.contains(Scope::AbstractUnixSocket),
            "ABSTRACT_UNIX_SOCKET must remain set"
        );
    }

    #[test]
    fn scope_mask_disable_abstract_unix_clears_only_abstract_bit() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(
            Protection::AbstractUnixSocketScope,
            ProtectionState::Disabled,
        );
        let mask = compute_scope_mask(6, &pol);
        assert!(
            !mask.contains(Scope::AbstractUnixSocket),
            "ABSTRACT_UNIX_SOCKET must be cleared",
        );
        assert!(mask.contains(Scope::Signal), "SIGNAL must remain set",);
    }

    #[test]
    fn scope_mask_disable_both_returns_zero() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::SignalScope, ProtectionState::Disabled);
        pol.set(
            Protection::AbstractUnixSocketScope,
            ProtectionState::Disabled,
        );
        assert!(
            compute_scope_mask(6, &pol).is_empty(),
            "both scopes disabled on a capable host must produce mask=0"
        );
    }

    #[test]
    fn scope_mask_allow_degraded_on_v5_host_returns_zero() {
        // v5 does not provide either v6 scope; Degradable must skip
        // silently — observable as both bits absent.
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::SignalScope, ProtectionState::Degradable);
        pol.set(
            Protection::AbstractUnixSocketScope,
            ProtectionState::Degradable,
        );
        assert!(
            compute_scope_mask(5, &pol).is_empty(),
            "Degradable scopes on a v5 host must contribute no bits"
        );
    }

    // ---------- compute_fs_mask ----------

    #[test]
    fn fs_mask_tracks_supported_abi_boundaries_without_future_rights() {
        let pol = ProtectionPolicy::strict_all();
        for (abi, expected) in [
            (0, 0),
            (1, 0x1fff),
            (2, 0x3fff),
            (3, 0x7fff),
            (4, 0x7fff),
            (5, 0xffff),
            (8, 0xffff),
            (9, 0x1ffff),
            (u32::MAX, 0x1ffff),
        ] {
            assert_eq!(compute_fs_mask(abi, &pol), expected, "ABI {abi}");
        }
    }

    #[test]
    fn fs_mask_strict_v6_includes_all_fs_protection_bits() {
        let pol = ProtectionPolicy::strict_all();
        let mask = compute_fs_mask(6, &pol);
        let mask = BitFlags::<AccessFs>::from_bits(mask).unwrap();
        for (bit, name) in [
            (AccessFs::Refer, "REFER"),
            (AccessFs::Truncate, "TRUNCATE"),
            (AccessFs::IoctlDev, "IOCTL_DEV"),
        ] {
            assert!(
                mask.contains(bit),
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
        let mask = BitFlags::<AccessFs>::from_bits(mask).unwrap();
        assert!(!mask.contains(AccessFs::Refer));
        assert!(mask.contains(AccessFs::Truncate));
        assert!(mask.contains(AccessFs::IoctlDev));
    }

    #[test]
    fn fs_mask_disable_fs_truncate_clears_only_truncate_bit() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::FsTruncate, ProtectionState::Disabled);
        let mask = compute_fs_mask(6, &pol);
        let mask = BitFlags::<AccessFs>::from_bits(mask).unwrap();
        assert!(!mask.contains(AccessFs::Truncate));
        assert!(mask.contains(AccessFs::Refer));
        assert!(mask.contains(AccessFs::IoctlDev));
    }

    #[test]
    fn fs_mask_disable_fs_ioctl_dev_clears_only_ioctl_dev_bit() {
        let mut pol = ProtectionPolicy::strict_all();
        pol.set(Protection::FsIoctlDev, ProtectionState::Disabled);
        let mask = compute_fs_mask(6, &pol);
        let mask = BitFlags::<AccessFs>::from_bits(mask).unwrap();
        assert!(!mask.contains(AccessFs::IoctlDev));
        assert!(mask.contains(AccessFs::Refer));
        assert!(mask.contains(AccessFs::Truncate));
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
        let mask = BitFlags::<AccessFs>::from_bits(mask).unwrap();
        assert!(
            !mask.contains(AccessFs::IoctlDev),
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
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(mask.is_empty(), "handle_net=false → mask is zero");
        assert!(!wildcard, "handle_net=false → wildcard is false");
    }

    #[test]
    fn net_mask_strict_no_wildcard_sets_bind_and_connect_bits() {
        let pol = ProtectionPolicy::strict_all();
        let sb = empty_sandbox();
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert_eq!(
            mask,
            AccessNet::BindTcp | AccessNet::ConnectTcp,
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
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(
            mask.is_empty(),
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
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(mask.is_empty());
        assert!(!wildcard);
    }

    #[test]
    fn net_mask_net_deny_forces_wildcard_dropping_connect_tcp() {
        // Deny-only (`--net-deny` without explicit `--net-allow`) is
        // default-allow and enforced on the on-behalf seccomp path, so
        // Landlock must not gate CONNECT_TCP.
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_deny("10.0.0.0/8")
            .build()
            .expect("net_deny sandbox builds");
        assert!(!sb.net_allow_is_active());
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert_eq!(
            mask,
            BitFlags::from(AccessNet::BindTcp),
            "deny-only must drop CONNECT_TCP so all TCP connects reach the on-behalf path",
        );
        assert!(wildcard, "deny-only must set the wildcard flag");
    }

    #[test]
    fn net_mask_combined_finite_keeps_connect_tcp() {
        // Combined finite allow + deny keeps Landlock port gating; the
        // supervisor applies allow then deny on the on-behalf path.
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_allow("127.0.0.1:443")
            .net_deny("10.0.0.0/8")
            .build()
            .expect("combined sandbox builds");
        assert!(sb.net_allow_is_active());
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(
            !wildcard,
            "combined finite must not force the connect wildcard"
        );
        assert_eq!(
            mask,
            AccessNet::BindTcp | AccessNet::ConnectTcp,
            "combined finite keeps both TCP hooks",
        );
    }

    fn approvable_sandbox(spec: &str) -> Sandbox {
        use crate::policy_fn::{Permissions, PolicyFn, Verdict};
        Sandbox::builder()
            .policy_fn(
                PolicyFn::new(|_e, _c| Verdict::Allow)
                    .approvable(Permissions::new().net_allow(spec)),
            )
            .build()
            .expect("approvable sandbox builds")
    }

    #[test]
    fn approvable_star_unhandles_connect() {
        let pol = ProtectionPolicy::strict_all();
        let sb = approvable_sandbox("*:*");
        assert!(!sb.net_allow_is_active());
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        assert!(
            wildcard,
            "an approvable *:* must not leave CONNECT_TCP gated"
        );
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(!mask.contains(AccessNet::ConnectTcp));
    }

    #[test]
    fn approvable_ports_reach_connect_rules() {
        let pol = ProtectionPolicy::strict_all();
        let sb = approvable_sandbox("tcp://*:443");
        let (_, wildcard) = compute_net_mask(6, &pol, &sb, true);
        assert!(!wildcard);
        assert!(sb
            .launch_and_approvable_net_allow()
            .iter()
            .any(|r| r.ports == vec![443]));
    }

    #[test]
    fn approvable_rejects_bad_spec_at_build() {
        use crate::policy_fn::{Permissions, PolicyFn, Verdict};
        assert!(Sandbox::builder()
            .policy_fn(
                PolicyFn::new(|_e, _c| Verdict::Allow)
                    .approvable(Permissions::new().net_allow("tcp://*:notaport")),
            )
            .build()
            .is_err());
    }

    #[test]
    fn approvable_requires_network_events() {
        use crate::policy_fn::{Permissions, PolicyFn, SyscallCategory, Verdict};
        let build = |events: &[SyscallCategory]| {
            Sandbox::builder()
                .policy_fn(
                    PolicyFn::new(|_e, _c| Verdict::Allow)
                        .events(events)
                        .approvable(Permissions::new().net_allow("*:*")),
                )
                .build()
        };
        assert!(build(&[SyscallCategory::Process]).is_err());
        assert!(build(&[SyscallCategory::Network]).is_ok());
    }

    #[test]
    fn net_mask_combined_wildcard_drops_connect_tcp() {
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_allow("tcp://*:443")
            .net_allow("tcp://127.0.0.1:*")
            .net_deny("10.0.0.0/8")
            .build()
            .expect("combined wildcard sandbox builds");
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(wildcard, "combined wildcard must set the wildcard flag");
        assert!(
            !mask.contains(AccessNet::ConnectTcp),
            "combined wildcard must drop CONNECT_TCP",
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn net_mask_http_only_keeps_connect_tcp() {
        // HTTP-only has no explicit allow rules but generates a finite
        // reachability rule; it stays a restrictive allowlist so Landlock
        // still gates CONNECT_TCP.
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .http_allow("GET api.example.com/v1/*")
            .build()
            .expect("http-only sandbox builds");
        assert!(sb.net_allow.is_empty());
        assert!(sb.net_allow_is_active());
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(
            !wildcard,
            "http-only finite must not force the connect wildcard"
        );
        assert_eq!(
            mask,
            AccessNet::BindTcp | AccessNet::ConnectTcp,
            "http-only keeps both TCP hooks",
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn net_mask_deny_only_http_stays_wildcard() {
        // Deny-only + HTTP stays default-allow: HTTP reachability must not
        // promote it to combined.
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_deny("10.0.0.0/8")
            .http_allow("GET api.example.com/v1/*")
            .build()
            .expect("deny-only+http sandbox builds");
        assert!(sb.net_allow.is_empty());
        assert!(!sb.net_allow_is_active());
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(wildcard, "deny-only+http must set the wildcard flag");
        assert_eq!(
            mask,
            BitFlags::from(AccessNet::BindTcp),
            "deny-only+http must drop CONNECT_TCP",
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn net_mask_combined_http_keeps_connect_tcp() {
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_allow("127.0.0.1:443")
            .net_deny("10.0.0.0/8")
            .http_allow("GET api.example.com/v1/*")
            .build()
            .expect("combined+http sandbox builds");
        assert!(sb.net_allow_is_active());
        let (mask, wildcard) = compute_net_mask(6, &pol, &sb, true);
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(
            !wildcard,
            "combined+http finite must not force the connect wildcard"
        );
        assert_eq!(
            mask,
            AccessNet::BindTcp | AccessNet::ConnectTcp,
            "combined+http keeps both TCP hooks",
        );
    }

    #[test]
    fn net_mask_allow_bind_zero_keeps_landlock_bind_gate() {
        // A listed port 0 is installed verbatim: Landlock permits only a
        // `bind(0)` request with it, not explicit nonzero binds, so the
        // BIND_TCP gate stays handled.
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_allow_bind("0")
            .build()
            .expect("bind-zero sandbox builds");
        let (mask, _) = compute_net_mask(6, &pol, &sb, true);
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(
            mask.contains(AccessNet::BindTcp),
            "bind port 0 must keep the Landlock BIND_TCP gate",
        );
        assert!(
            mask.contains(AccessNet::ConnectTcp),
            "bind-zero must not affect CONNECT_TCP handling",
        );
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
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(
            !mask.contains(AccessNet::BindTcp),
            "net_deny_bind must drop BIND_TCP so all TCP binds reach the on-behalf path",
        );
        assert!(
            mask.contains(AccessNet::ConnectTcp),
            "net_deny_bind must not affect CONNECT_TCP handling",
        );
    }

    #[test]
    fn net_mask_combined_bind_policy_drops_bind_tcp_for_supervisor_check() {
        let pol = ProtectionPolicy::strict_all();
        let sb = Sandbox::builder()
            .net_allow_bind("8080")
            .net_deny_bind("8080")
            .build()
            .expect("combined bind policy builds");
        let (mask, _wildcard) = compute_net_mask(6, &pol, &sb, true);
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(
            !mask.contains(AccessNet::BindTcp),
            "combined bind policy must let the supervisor apply deny precedence",
        );
        assert!(
            mask.contains(AccessNet::ConnectTcp),
            "bind policy must not alter CONNECT_TCP handling",
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
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert_eq!(
            mask,
            BitFlags::from(AccessNet::ConnectTcp),
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
        let mask = BitFlags::<AccessNet>::from_bits(mask).unwrap();
        assert!(
            mask.is_empty(),
            "net_deny + bind-all leaves no handled net access"
        );
        assert!(wildcard, "net_deny must still set the wildcard flag");
    }
}

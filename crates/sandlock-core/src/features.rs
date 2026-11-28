use crate::policy_fn::{CategorySet, SyscallCategory};
use crate::sandbox::Sandbox;

/// Feature gates derived once from a sandbox configuration and shared by the
/// seccomp filter and the supervisor, so the two cannot disagree on what is
/// active.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SandboxFeatures {
    pub(crate) memory_limit: bool,
    pub(crate) network_supervision: bool,
    /// A destination policy is active: a `net_allow` allowlist, a `net_deny`
    /// denylist, an HTTP ACL, or a live `policy_fn`. The on-behalf path is
    /// then the IP-level enforcer for connect/sendto/sendmsg and must never
    /// `Continue`; otherwise those syscalls are trapped only to gate named
    /// `AF_UNIX` sockets and IP destinations go back to the kernel.
    pub(crate) network_destination_policy: bool,
    /// `--net-deny-bind` is active, independent of the connect side.
    pub(crate) bind_denylist: bool,
    /// `connect()` to a named unix socket outside the fs-write grants is
    /// denied. Abstract sockets are scoped by Landlock instead.
    pub(crate) unix_fs_gate: bool,
    /// The host's Landlock enforces [`Self::unix_fs_gate`] itself, so the
    /// caller can connect in its own name.
    pub(crate) landlock_unix_gate: bool,
    pub(crate) random_seed: bool,
    pub(crate) time_start: bool,
    pub(crate) virtual_cpu_count: bool,
    pub(crate) virtual_hostname: bool,
    /// Off when the policy denies sysinfo: a notified syscall would bypass the deny.
    pub(crate) virtual_sysinfo: bool,
    pub(crate) cow: bool,
    pub(crate) chroot: bool,
    pub(crate) fs_denies: bool,
    pub(crate) policy_events: CategorySet,
    pub(crate) port_remap: bool,
    pub(crate) http_acl: bool,
    /// Every task that could mutate argv must be frozen before a consumer
    /// reads it, and fork events are traced so the freeze sees every task.
    pub(crate) argv_safety_required: bool,
    pub(crate) sysv_ipc_allowed: bool,
    /// Whether an outbound allow layer is active. Derived from the separated
    /// configuration (explicit allow rules plus HTTP reachability, with
    /// deny-only+HTTP staying default-allow).
    pub(crate) net_allow_present: bool,
    pub(crate) net_deny: bool,
}

impl SandboxFeatures {
    pub(crate) fn from_sandbox(
        sandbox: &Sandbox,
        sandbox_name: Option<&str>,
        handler_syscalls: &[i64],
    ) -> Self {
        let http_acl = !sandbox.http_allow.is_empty() || !sandbox.http_deny.is_empty();
        let network_destination_policy = sandbox.has_net_destination_policy();
        let bind_denylist = !sandbox.net_deny_bind.is_empty();
        let exec_handler = handler_syscalls
            .iter()
            .any(|&nr| nr == libc::SYS_execve || nr == libc::SYS_execveat);
        let policy_events = sandbox
            .policy_fn
            .as_ref()
            .map_or(CategorySet::NONE, |p| p.events);

        Self {
            memory_limit: sandbox.max_memory.is_some(),
            network_supervision: network_destination_policy || bind_denylist,
            network_destination_policy,
            bind_denylist,
            unix_fs_gate: sandbox.has_unix_fs_gate(),
            landlock_unix_gate: crate::landlock_policy::gates_named_unix(),
            random_seed: sandbox.random_seed.is_some(),
            time_start: sandbox.time_start.is_some(),
            virtual_cpu_count: sandbox.num_cpus.is_some(),
            virtual_hostname: sandbox_name.is_some(),
            virtual_sysinfo: !crate::seccomp_plan::blocklist_syscall_numbers(sandbox)
                .contains(&(libc::SYS_sysinfo as u32)),
            cow: sandbox.workdir.is_some(),
            chroot: sandbox.chroot.is_some(),
            fs_denies: !sandbox.fs_denied.is_empty(),
            policy_events,
            port_remap: sandbox.port_remap,
            http_acl,
            argv_safety_required: policy_events.contains(SyscallCategory::Exec) || exec_handler,
            sysv_ipc_allowed: sandbox.allows_sysv_ipc(),
            net_allow_present: sandbox.net_allow_is_active()
                || !sandbox.approvable_net_allow().is_empty(),
            net_deny: !sandbox.net_deny.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_fn::{PolicyFn, Verdict};

    fn argv_safety(events: &[SyscallCategory], handler_syscalls: &[i64]) -> bool {
        let sandbox = Sandbox::builder()
            .policy_fn(PolicyFn::new(|_e, _c| Verdict::Allow).events(events))
            .build()
            .unwrap();
        SandboxFeatures::from_sandbox(&sandbox, None, handler_syscalls).argv_safety_required
    }

    #[test]
    fn only_exec_events_require_argv_safety() {
        assert!(!argv_safety(&[SyscallCategory::Process], &[]));
        assert!(!argv_safety(&[SyscallCategory::Network], &[]));
        assert!(argv_safety(&[SyscallCategory::Exec], &[]));
        assert!(argv_safety(
            &[SyscallCategory::Network],
            &[libc::SYS_execve]
        ));
    }
}

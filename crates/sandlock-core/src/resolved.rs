use crate::sandbox::{Protocol, Sandbox};

/// Internal normalized view of a sandbox configuration.
///
/// `Sandbox` is the public configuration surface. `ResolvedSandbox` is the
/// private shape used by runtime setup after defaults and feature activation
/// have been reduced to named facts.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedSandbox {
    pub(crate) features: SandboxFeatures,
}

impl ResolvedSandbox {
    pub(crate) fn from_sandbox(
        sandbox: &Sandbox,
        sandbox_name: Option<&str>,
        handler_syscalls: &[i64],
    ) -> Self {
        Self {
            features: SandboxFeatures::from_sandbox(sandbox, sandbox_name, handler_syscalls),
        }
    }
}

/// Boolean feature gates derived from a sandbox configuration.
///
/// These are deliberately named around runtime behavior instead of raw option
/// names. That keeps syscall planning and supervisor setup from re-encoding
/// the same `Option`/empty-list checks in several places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SandboxFeatures {
    pub(crate) memory_limit: bool,
    pub(crate) network_supervision: bool,
    pub(crate) network_destination_policy: bool,
    pub(crate) bind_denylist: bool,
    pub(crate) unix_fs_gate: bool,
    pub(crate) random_seed: bool,
    pub(crate) time_start: bool,
    pub(crate) virtual_cpu_count: bool,
    pub(crate) virtual_hostname: bool,
    pub(crate) cow: bool,
    pub(crate) chroot: bool,
    pub(crate) fs_denies: bool,
    pub(crate) policy_fn: bool,
    pub(crate) port_remap: bool,
    pub(crate) http_acl: bool,
    pub(crate) argv_safety_required: bool,
    pub(crate) sysv_ipc_allowed: bool,
    pub(crate) udp_or_icmp_allowed: bool,
    pub(crate) net_deny: bool,
}

impl SandboxFeatures {
    fn from_sandbox(
        sandbox: &Sandbox,
        sandbox_name: Option<&str>,
        handler_syscalls: &[i64],
    ) -> Self {
        let http_acl = !sandbox.http_allow.is_empty() || !sandbox.http_deny.is_empty();
        let network_destination_policy = !sandbox.net_allow.is_empty()
            || !sandbox.net_deny.is_empty()
            || sandbox.policy_fn.is_some()
            || http_acl;
        let bind_denylist = !sandbox.net_deny_bind.is_empty();
        let exec_handler = handler_syscalls
            .iter()
            .any(|&nr| nr == libc::SYS_execve || nr == libc::SYS_execveat);

        Self {
            memory_limit: sandbox.max_memory.is_some(),
            network_supervision: network_destination_policy || bind_denylist,
            network_destination_policy,
            bind_denylist,
            unix_fs_gate: sandbox.has_unix_fs_gate(),
            random_seed: sandbox.random_seed.is_some(),
            time_start: sandbox.time_start.is_some(),
            virtual_cpu_count: sandbox.num_cpus.is_some(),
            virtual_hostname: sandbox_name.is_some(),
            cow: sandbox.workdir.is_some(),
            chroot: sandbox.chroot.is_some(),
            fs_denies: !sandbox.fs_denied.is_empty(),
            policy_fn: sandbox.policy_fn.is_some(),
            port_remap: sandbox.port_remap,
            http_acl,
            argv_safety_required: sandbox.policy_fn.is_some() || exec_handler,
            sysv_ipc_allowed: sandbox.allows_sysv_ipc(),
            udp_or_icmp_allowed: sandbox
                .net_allow
                .iter()
                .any(|r| matches!(r.protocol, Protocol::Udp | Protocol::Icmp)),
            net_deny: !sandbox.net_deny.is_empty(),
        }
    }
}

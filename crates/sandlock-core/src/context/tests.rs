use super::*;

#[test]
fn test_pipe_pair_creation() {
    let pipes = PipePair::new().expect("pipe creation failed");
    // Verify fds are valid (non-negative)
    assert!(pipes.notif_r.as_raw_fd() >= 0);
    assert!(pipes.notif_w.as_raw_fd() >= 0);
    assert!(pipes.ready_r.as_raw_fd() >= 0);
    assert!(pipes.ready_w.as_raw_fd() >= 0);
    // All four fds should be distinct
    let fds = [
        pipes.notif_r.as_raw_fd(),
        pipes.notif_w.as_raw_fd(),
        pipes.ready_r.as_raw_fd(),
        pipes.ready_w.as_raw_fd(),
    ];
    for i in 0..4 {
        for j in (i + 1)..4 {
            assert_ne!(fds[i], fds[j]);
        }
    }
}

#[test]
fn test_write_read_u32() {
    let pipes = PipePair::new().expect("pipe creation failed");
    let val = 42u32;
    write_u32_fd(pipes.notif_w.as_raw_fd(), val).expect("write failed");
    let got = read_u32_fd(pipes.notif_r.as_raw_fd()).expect("read failed");
    assert_eq!(got, val);
}

#[test]
fn test_write_read_u32_large() {
    let pipes = PipePair::new().expect("pipe creation failed");
    let val = 0xDEAD_BEEFu32;
    write_u32_fd(pipes.notif_w.as_raw_fd(), val).expect("write failed");
    let got = read_u32_fd(pipes.notif_r.as_raw_fd()).expect("read failed");
    assert_eq!(got, val);
}

#[test]
fn test_notif_syscalls_always_has_clone() {
    let policy = Sandbox::builder().build().unwrap();
    let nrs = notif_syscalls(&policy, None);
    assert!(nrs.contains(&(libc::SYS_clone as u32)));
    assert!(nrs.contains(&(libc::SYS_clone3 as u32)));
    if let Some(vfork) = arch::sys_vfork() {
        assert!(nrs.contains(&(vfork as u32)));
    }
    // Bare fork(2) is intercepted only when policy_fn is active:
    // see notif_syscalls. The default policy has no policy_fn, so
    // fork stays out of the BPF filter and hot fork-loops keep
    // bypassing the supervisor.
    if let Some(fork) = arch::sys_fork() {
        assert!(!nrs.contains(&(fork as u32)));
    }
}

#[test]
fn test_notif_syscalls_fork_gated_on_policy_fn() {
    let Some(fork) = arch::sys_fork() else { return };
    let policy = Sandbox::builder()
        .policy_fn(|_event, _ctx| crate::policy_fn::Verdict::Allow)
        .build()
        .unwrap();
    let nrs = notif_syscalls(&policy, None);
    assert!(nrs.contains(&(fork as u32)));
}

#[test]
fn test_notif_syscalls_memory() {
    // shmget only appears in notif when SysV IPC is allowed:
    // otherwise it is on the kernel blocklist and notifying would
    // bypass the deny (notif JEQs precede deny JEQs in the BPF
    // layout).
    let policy = Sandbox::builder()
        .max_memory(crate::sandbox::ByteSize::mib(256))
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    let nrs = notif_syscalls(&policy, None);
    assert!(nrs.contains(&(libc::SYS_mmap as u32)));
    assert!(nrs.contains(&(libc::SYS_munmap as u32)));
    assert!(nrs.contains(&(libc::SYS_brk as u32)));
    assert!(nrs.contains(&(libc::SYS_mremap as u32)));
    assert!(nrs.contains(&(libc::SYS_shmget as u32)));
}

#[test]
fn test_notif_syscalls_memory_excludes_shmget_when_sysv_ipc_denied() {
    // With max_memory but allows_sysv_ipc()=false (the default),
    // shmget must NOT be in notif: if it were, the BPF filter
    // would route it to RET_USER_NOTIF before reaching the deny
    // JEQ, silently bypassing the kernel-level deny.
    let policy = Sandbox::builder()
        .max_memory(crate::sandbox::ByteSize::mib(256))
        .build()
        .unwrap();
    let nrs = notif_syscalls(&policy, None);
    assert!(!nrs.contains(&(libc::SYS_shmget as u32)));
    // Other memory syscalls remain notified; they are not denied.
    assert!(nrs.contains(&(libc::SYS_mmap as u32)));
    assert!(nrs.contains(&(libc::SYS_brk as u32)));
}

#[test]
fn test_notif_syscalls_net() {
    let policy = Sandbox::builder()
        .net_allow("example.com:443")
        .build()
        .unwrap();
    let nrs = notif_syscalls(&policy, None);
    assert!(nrs.contains(&(libc::SYS_connect as u32)));
    assert!(nrs.contains(&(libc::SYS_sendto as u32)));
    assert!(nrs.contains(&(libc::SYS_sendmsg as u32)));
    assert!(nrs.contains(&(libc::SYS_sendmmsg as u32)));
}

#[test]
fn test_notif_syscalls_net_deny() {
    // --net-deny is default-allow but still needs every connect/sendto
    // routed to the on-behalf path so the DenyList can refuse matches.
    let policy = Sandbox::builder()
        .net_deny("10.0.0.0/8")
        .build()
        .unwrap();
    let nrs = notif_syscalls(&policy, None);
    assert!(nrs.contains(&(libc::SYS_connect as u32)));
    assert!(nrs.contains(&(libc::SYS_sendto as u32)));
}

#[test]
fn test_notif_syscalls_sandbox_name_enables_hostname_virtualization() {
    let policy = Sandbox::builder().build().unwrap();
    let nrs = notif_syscalls(&policy, Some("api.local"));
    assert!(nrs.contains(&(libc::SYS_uname as u32)));
    assert!(nrs.contains(&(libc::SYS_openat as u32)));
}

/// SYS_faccessat2 (439) must be in the notification filter for both
/// chroot and COW modes; glibc 2.33+ uses it instead of faccessat.
#[test]
fn test_notif_syscalls_faccessat2() {
    // Chroot mode
    let policy = Sandbox::builder()
        .chroot("/tmp")
        .build()
        .unwrap();
    let nrs = notif_syscalls(&policy, None);
    assert!(nrs.contains(&(libc::SYS_faccessat as u32)));
    assert!(nrs.contains(&(arch::SYS_FACCESSAT2 as u32)),
            "chroot notif filter must include SYS_faccessat2 (439)");

    // COW mode
    let policy = Sandbox::builder()
        .workdir("/tmp")
        .build()
        .unwrap();
    let nrs = notif_syscalls(&policy, None);
    assert!(nrs.contains(&(libc::SYS_faccessat as u32)));
    assert!(nrs.contains(&(arch::SYS_FACCESSAT2 as u32)),
            "COW notif filter must include SYS_faccessat2 (439)");
}

#[test]
fn test_blocklist_syscall_numbers_default() {
    let policy = Sandbox::builder().build().unwrap();
    let nrs = blocklist_syscall_numbers(&policy);
    // Should contain mount, ptrace, etc.
    assert!(nrs.contains(&(libc::SYS_mount as u32)));
    assert!(nrs.contains(&(libc::SYS_ptrace as u32)));
    assert!(nrs.contains(&(libc::SYS_bpf as u32)));
    // SysV IPC denied by default (no IPC namespace in sandlock)
    assert!(nrs.contains(&(libc::SYS_shmget as u32)));
    assert!(nrs.contains(&(libc::SYS_shmat as u32)));
    assert!(nrs.contains(&(libc::SYS_msgget as u32)));
    assert!(nrs.contains(&(libc::SYS_semget as u32)));
    // nfsservctl has no libc constant, so it is skipped
    assert!(!nrs.is_empty());
}

#[test]
fn test_blocklist_syscall_numbers_custom() {
    let policy = Sandbox::builder()
        .extra_deny_syscalls(vec!["mount".into(), "ptrace".into()])
        .build()
        .unwrap();
    let nrs = blocklist_syscall_numbers(&policy);
    // User-supplied blocklist still gets SysV IPC appended
    // (allows_sysv_ipc() defaults to false).
    assert!(nrs.contains(&(libc::SYS_mount as u32)));
    assert!(nrs.contains(&(libc::SYS_ptrace as u32)));
    assert!(nrs.contains(&(libc::SYS_shmget as u32)));
}

#[test]
fn test_blocklist_syscall_numbers_custom_with_sysv_ipc_allowed() {
    let policy = Sandbox::builder()
        .extra_deny_syscalls(vec!["mount".into(), "ptrace".into()])
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    let nrs = blocklist_syscall_numbers(&policy);
    // Default blocklist plus user extras: no SysV IPC append.
    assert!(nrs.contains(&(libc::SYS_mount as u32)));
    assert!(nrs.contains(&(libc::SYS_ptrace as u32)));
    assert!(nrs.contains(&(libc::SYS_bpf as u32)));
    assert!(!nrs.contains(&(libc::SYS_shmget as u32)));
}

#[test]
fn test_blocklist_syscall_numbers_default_with_sysv_ipc_allowed() {
    let policy = Sandbox::builder()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    let nrs = blocklist_syscall_numbers(&policy);
    // Default blocklist still present, but SysV IPC is permitted.
    assert!(nrs.contains(&(libc::SYS_mount as u32)));
    assert!(!nrs.contains(&(libc::SYS_shmget as u32)));
    assert!(!nrs.contains(&(libc::SYS_msgget as u32)));
    assert!(!nrs.contains(&(libc::SYS_semget as u32)));
}

// The expansion tests below inject the group deny after build(): with
// allow "sysv_ipc" set, the !allows_sysv_ipc() fallback in
// resolve_blocklist is skipped, so the members can appear only through
// group expansion of the deny entry. Going through build() instead
// would either trip the allow/deny conflict check or (deny-only) let
// the fallback add the members and mask a broken expansion.
#[test]
fn test_blocklist_syscall_numbers_expands_deny_group() {
    let mut policy = Sandbox::builder()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    policy.extra_deny_syscalls = vec!["sysv_ipc".into()];
    let nrs = blocklist_syscall_numbers(&policy);
    assert!(nrs.contains(&(libc::SYS_shmget as u32)));
    assert!(nrs.contains(&(libc::SYS_msgget as u32)));
    assert!(nrs.contains(&(libc::SYS_semget as u32)));
    assert!(nrs.contains(&(libc::SYS_semtimedop as u32)));
}

#[test]
fn test_no_supervisor_blocklist_expands_deny_group() {
    let mut policy = Sandbox::builder()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    policy.extra_deny_syscalls = vec!["sysv_ipc".into()];
    let nrs = no_supervisor_blocklist_syscall_numbers(&policy);
    assert!(nrs.contains(&(libc::SYS_shmget as u32)));
    assert!(nrs.contains(&(libc::SYS_msgctl as u32)));
}

#[test]
fn test_no_supervisor_blocklist_includes_sysv_ipc_by_default() {
    let policy = Sandbox::builder().build().unwrap();
    let nrs = no_supervisor_blocklist_syscall_numbers(&policy);
    assert!(nrs.contains(&(libc::SYS_shmget as u32)));
    assert!(nrs.contains(&(libc::SYS_msgget as u32)));
    assert!(nrs.contains(&(libc::SYS_semget as u32)));
}

#[test]
fn test_no_supervisor_blocklist_excludes_sysv_ipc_when_allowed() {
    let policy = Sandbox::builder()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    let nrs = no_supervisor_blocklist_syscall_numbers(&policy);
    assert!(!nrs.contains(&(libc::SYS_shmget as u32)));
    assert!(!nrs.contains(&(libc::SYS_msgget as u32)));
    assert!(!nrs.contains(&(libc::SYS_semget as u32)));
}

#[test]
fn test_arg_filters_has_clone_ioctl_prctl_socket() {
    use crate::sys::structs::{
        BPF_JEQ, BPF_JSET, BPF_JMP, BPF_K,
    };
    let policy = Sandbox::builder().build().unwrap();
    let filters = arg_filters(&policy);
    // Should contain JEQ for clone syscall nr
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == libc::SYS_clone as u32));
    // Should contain JSET for CLONE_NS_FLAGS
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JSET | BPF_K)
        && f.k == CLONE_NS_FLAGS as u32));
    // Should contain JEQ for ioctl syscall nr
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == libc::SYS_ioctl as u32));
    // Should contain JEQ for TIOCSTI, TIOCLINUX, and SIOCGIF*/SIOCETHTOOL
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == TIOCSTI as u32));
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == TIOCLINUX as u32));
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == SIOCGIFCONF as u32));
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == SIOCETHTOOL as u32));
    // Should contain JEQ for prctl syscall nr
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == libc::SYS_prctl as u32));
    // Should contain JEQ for PR_SET_DUMPABLE
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == PR_SET_DUMPABLE));
}

#[test]
fn test_arg_filters_raw_sockets() {
    use crate::sys::structs::{BPF_ALU, BPF_AND, BPF_JEQ, BPF_JMP, BPF_K};
    // Raw sockets are blocked by default: no `icmp-raw://*` rule.
    let policy = Sandbox::builder().build().unwrap();
    let filters = arg_filters(&policy);
    // Should have AF_INET check
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == AF_INET));
    // Should have AF_INET6 check
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == AF_INET6));
    // Should have ALU AND SOCK_TYPE_MASK
    assert!(filters.iter().any(|f| f.code == (BPF_ALU | BPF_AND | BPF_K)
        && f.k == SOCK_TYPE_MASK));
    // Should have JEQ SOCK_RAW
    assert!(filters.iter().any(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K)
        && f.k == SOCK_RAW));
}

#[test]
fn test_arg_filters_udp_denied_by_default() {
    // SOCK_DGRAM creation is denied when no net rule exists: nothing traps
    // sends, so socket() is the only enforcement point.
    let policy = Sandbox::builder().build().unwrap();
    assert_eq!(count_jeq_2(&arg_filters(&policy)), 2);
}

/// AF_INET and SOCK_DGRAM share the constant 2, so presence of the
/// SOCK_DGRAM JEQ is observed as the JEQ-with-k==2 count: the AF_INET
/// domain check contributes one in every socket filter, the type check
/// contributes the second only when SOCK_DGRAM is in the blocked set.
fn count_jeq_2(filters: &[crate::sys::structs::SockFilter]) -> usize {
    use crate::sys::structs::{BPF_JEQ, BPF_JMP, BPF_K};
    filters.iter()
        .filter(|f| f.code == (BPF_JMP | BPF_JEQ | BPF_K) && f.k == 2)
        .count()
}

#[test]
fn test_arg_filters_udp_creatable_with_tcp_only_rules() {
    // Any net rule moves UDP enforcement to send time: the on-behalf
    // handlers deny destinations for rule-less protocols, so socket()
    // must succeed (glibc getaddrinfo probes create UDP sockets).
    let policy = Sandbox::builder().net_allow("1.1.1.1:443").build().unwrap();
    assert_eq!(count_jeq_2(&arg_filters(&policy)), 1);
}

#[test]
fn test_arg_filters_udp_creatable_with_net_deny() {
    let policy = Sandbox::builder().net_deny("10.0.0.0/8").build().unwrap();
    assert_eq!(count_jeq_2(&arg_filters(&policy)), 1);
}

#[test]
fn test_syscall_name_to_nr_covers_defaults() {
    // Every name in DEFAULT_BLOCKLIST_SYSCALLS should resolve unless the
    // running architecture does not expose that syscall.
    // `nfsservctl` now resolves: the syscalls crate carries it (kernel
    // returns ENOSYS, but the ABI number exists), so it is enforced in the
    // blocklist rather than silently dropped. `ioperm`/`iopl` are x86-only.
    let expected_unresolved: &[&str] = &[
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        "ioperm",
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        "iopl",
    ];
    let mut skipped = 0;
    for name in DEFAULT_BLOCKLIST_SYSCALLS {
        match syscall_name_to_nr(name) {
            Some(_) => {}
            None => {
                assert!(
                    expected_unresolved.contains(name),
                    "unexpected unresolved syscall: {}",
                    name
                );
                skipped += 1;
            }
        }
    }
    assert_eq!(skipped, expected_unresolved.len());
}

#[test]
fn test_effective_nofile_clamps_to_both_inherited_bounds() {
    // A request below both bounds is applied verbatim, the ordinary case.
    let split = libc::rlimit { rlim_cur: 1024, rlim_max: 1_048_576 };
    assert_eq!(effective_nofile(64, &split), 64);

    // A request *between* the inherited soft and hard limits must not widen the
    // guest's budget: with the distro-default 1024/1048576 split, asking for
    // 65536 would otherwise hand the sandboxed process 64x the descriptors the
    // same command gets unsandboxed, under a setting named "max".
    assert_eq!(effective_nofile(65_536, &split), 1024);

    // A request above the hard limit cannot be applied at all (raising a hard
    // limit needs CAP_SYS_RESOURCE), so it clamps rather than aborting the
    // child.
    assert_eq!(effective_nofile(u32::MAX, &split), 1024);
    let raised = libc::rlimit { rlim_cur: 4096, rlim_max: 4096 };
    assert_eq!(effective_nofile(u32::MAX, &raised), 4096);

    // An unlimited inheritance leaves the request alone.
    let unlimited = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    assert_eq!(effective_nofile(4096, &unlimited), 4096);
}

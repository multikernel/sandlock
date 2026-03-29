use sandlock_core::policy::{ByteSize, FsIsolation, BranchAction, Policy};

#[test]
fn test_default_policy() {
    let policy = Policy::builder().build().unwrap();
    assert_eq!(policy.max_processes, 64);
    assert!(policy.no_raw_sockets);
    assert!(policy.strict);
    assert!(policy.close_fds);
    assert!(!policy.privileged);
    assert!(policy.fs_writable.is_empty());
    assert!(policy.fs_readable.is_empty());
}

#[test]
fn test_builder_fs_paths() {
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_write("/tmp")
        .build()
        .unwrap();
    assert_eq!(policy.fs_readable.len(), 2);
    assert_eq!(policy.fs_writable.len(), 1);
}

#[test]
fn test_builder_network() {
    let policy = Policy::builder()
        .net_bind_port(8080)
        .net_connect_port(443)
        .net_connect_port(80)
        .build()
        .unwrap();
    assert_eq!(policy.net_bind, vec![8080]);
    assert_eq!(policy.net_connect, vec![443, 80]);
}

#[test]
fn test_builder_resource_limits() {
    let policy = Policy::builder()
        .max_memory(ByteSize::mib(512))
        .max_processes(20)
        .max_cpu(50)
        .build()
        .unwrap();
    assert_eq!(policy.max_memory.unwrap().0, 512 * 1024 * 1024);
    assert_eq!(policy.max_processes, 20);
    assert_eq!(policy.max_cpu.unwrap(), 50);
}

#[test]
fn test_mutually_exclusive_syscalls() {
    let result = Policy::builder()
        .deny_syscalls(vec!["mount".into()])
        .allow_syscalls(vec!["read".into()])
        .build();
    assert!(result.is_err());
}

#[test]
fn test_invalid_cpu_percent() {
    assert!(Policy::builder().max_cpu(0).build().is_err());
    assert!(Policy::builder().max_cpu(101).build().is_err());
}

#[test]
fn test_fs_isolation_requires_workdir() {
    assert!(Policy::builder()
        .fs_isolation(FsIsolation::OverlayFs)
        .build()
        .is_err());
}

#[test]
fn test_bytesize_parsing() {
    assert_eq!(ByteSize::parse("512M").unwrap().0, 512 * 1024 * 1024);
    assert_eq!(ByteSize::parse("1G").unwrap().0, 1024 * 1024 * 1024);
    assert_eq!(ByteSize::parse("100K").unwrap().0, 100 * 1024);
    assert_eq!(ByteSize::parse("1024").unwrap().0, 1024);
}

#[test]
fn test_bytesize_parse_case_insensitive() {
    assert_eq!(ByteSize::parse("512m").unwrap().0, 512 * 1024 * 1024);
    assert_eq!(ByteSize::parse("1g").unwrap().0, 1024 * 1024 * 1024);
    assert_eq!(ByteSize::parse("100k").unwrap().0, 100 * 1024);
}

#[test]
fn test_bytesize_parse_invalid() {
    assert!(ByteSize::parse("not_a_size").is_err());
    assert!(ByteSize::parse("").is_err());
    assert!(ByteSize::parse("M").is_err());
}

#[test]
fn test_clean_env() {
    let p = Policy::builder().build().unwrap();
    assert!(!p.clean_env, "clean_env should default to false");

    let p = Policy::builder().clean_env(true).build().unwrap();
    assert!(p.clean_env);
}

#[test]
fn test_env_var() {
    let p = Policy::builder()
        .env_var("FOO", "bar")
        .env_var("BAZ", "qux")
        .build()
        .unwrap();
    assert_eq!(p.env.len(), 2);
}

#[test]
fn test_no_udp_default_false() {
    let p = Policy::builder().build().unwrap();
    assert!(!p.no_udp, "no_udp should default to false");
}

#[test]
fn test_no_raw_sockets_default_true() {
    let p = Policy::builder().build().unwrap();
    assert!(p.no_raw_sockets, "no_raw_sockets should default to true");
}

#[test]
fn test_branch_action_defaults() {
    let p = Policy::builder()
        .workdir("/tmp")
        .build()
        .unwrap();
    assert_eq!(p.on_exit, BranchAction::Commit);
    assert_eq!(p.on_error, BranchAction::Commit);
}

#[test]
fn test_isolate_flags() {
    let p = Policy::builder()
        .isolate_ipc(true)
        .isolate_signals(true)
        .build()
        .unwrap();
    assert!(p.isolate_ipc);
    assert!(p.isolate_signals);
}

#[test]
fn test_port_remap_flag() {
    let p = Policy::builder().port_remap(true).build().unwrap();
    assert!(p.port_remap);
}

#[test]
fn test_fs_deny() {
    let p = Policy::builder()
        .fs_deny("/proc/kcore")
        .fs_deny("/sys/firmware")
        .build()
        .unwrap();
    assert_eq!(p.fs_denied.len(), 2);
}

#[test]
fn test_cpu_cores_default_none() {
    let p = Policy::builder().build().unwrap();
    assert!(p.cpu_cores.is_none());
}

#[test]
fn test_cpu_cores_builder() {
    let p = Policy::builder()
        .cpu_cores(vec![0, 2, 3])
        .build()
        .unwrap();
    assert_eq!(p.cpu_cores, Some(vec![0, 2, 3]));
}

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
fn test_effective_nofile_clamps_to_both_inherited_bounds() {
    // A request below both bounds is applied verbatim, the ordinary case.
    let split = libc::rlimit {
        rlim_cur: 1024,
        rlim_max: 1_048_576,
    };
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
    let raised = libc::rlimit {
        rlim_cur: 4096,
        rlim_max: 4096,
    };
    assert_eq!(effective_nofile(u32::MAX, &raised), 4096);

    // An unlimited inheritance leaves the request alone.
    let unlimited = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    assert_eq!(effective_nofile(4096, &unlimited), 4096);
}

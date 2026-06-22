//! Launch a confined process from a memfd via Sandbox.exec_fd.
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd};

/// Seal a static binary into a memfd and run it via execveat(AT_EMPTY_PATH).
/// The rootfs-helper "true" applet exits 0, proving the mechanism works.
#[tokio::test(flavor = "multi_thread")]
async fn exec_fd_launches_from_memfd() {
    if sandlock_core::landlock_abi_version().is_err() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper");
    if !helper.exists() {
        eprintln!("skipping: rootfs-helper not built");
        return;
    }
    let bytes = std::fs::read(&helper).unwrap();

    // Create a memfd and write the helper binary into it.
    let name = std::ffi::CString::new("sandlock-exec-fd-test").unwrap();
    let mfd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    assert!(mfd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
    let mut f = unsafe { std::fs::File::from_raw_fd(mfd) };
    f.write_all(&bytes).unwrap();

    let mut sb = sandlock_core::Sandbox::builder()
        .fs_read("/")
        .build()
        .unwrap();
    // Use the memfd fd directly; keep f alive until the run completes so the
    // child can execveat from it.
    sb.exec_fd = Some(f.as_raw_fd());

    // argv[0] = "rootfs-helper" triggers normal dispatch; "true" exits 0.
    let res = sb.run_interactive(&["rootfs-helper", "true"]).await;
    drop(f);

    let r = res.expect("run should succeed");
    assert!(
        matches!(r.exit_status, sandlock_core::ExitStatus::Code(0)),
        "expected exit 0, got {:?}", r.exit_status,
    );
}

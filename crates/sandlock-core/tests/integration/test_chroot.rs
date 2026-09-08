use sandlock_core::sandbox::BranchAction;
#[allow(unused_imports)]
use sandlock_core::{Sandbox};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Path to the static rootfs-helper binary (compiled by build.rs).
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .expect("rootfs-helper not found — build.rs should have compiled it")
}

/// Minimal fs_readable set needed to run rootfs-helper under chroot.
fn minimal_exec_policy(rootfs: &PathBuf) -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .chroot(rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/proc")
        .fs_read("/dev")
}

fn temp_dir(name: &str) -> PathBuf {
    // Prefer cargo's per-test-binary tmp dir (under `target/`, the same
    // filesystem as the compiled rootfs-helper) so build_test_rootfs can
    // hard-link the helper into the rootfs instead of copying it. A
    // cross-filesystem temp such as /tmp (often tmpfs) forces the fs::copy
    // fallback, whose writable fd can be inherited by a concurrent fork+exec in
    // another parallel test and leave the helper briefly open for write, making
    // the eventual execve fail with ETXTBSY (Text file busy).
    let base = option_env!("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("sandlock-test-chroot-{}-{}", name, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Build a self-contained rootfs with the static rootfs-helper binary.
///
/// Layout:
///   usr/bin/rootfs-helper   — the real binary
///   usr/bin/sh              — symlink -> rootfs-helper
///   usr/bin/cat             — symlink -> rootfs-helper
///   usr/bin/echo            — symlink -> rootfs-helper
///   usr/bin/ls              — symlink -> rootfs-helper
///   usr/bin/pwd             — symlink -> rootfs-helper
///   usr/bin/readlink        — symlink -> rootfs-helper
///   usr/bin/true            — symlink -> rootfs-helper
///   usr/bin/write           — symlink -> rootfs-helper
///   bin                     — symlink -> usr/bin  (merged /usr)
///   sbin                    — symlink -> usr/sbin (merged /usr)
///   etc/
///   proc/
///   dev/
///   tmp/                    — mode 1777
fn build_test_rootfs(name: &str) -> PathBuf {
    let rootfs = temp_dir(name);
    let helper = helper_binary();

    // Create real directories
    for dir in &["usr/bin", "usr/sbin", "etc", "proc", "dev", "tmp"] {
        let _ = fs::create_dir_all(rootfs.join(dir));
    }

    // Set /tmp sticky
    let _ = fs::set_permissions(rootfs.join("tmp"), fs::Permissions::from_mode(0o1777));

    // Hard-link the helper binary (atomic, avoids ETXTBSY races from copy).
    let dest = rootfs.join("usr/bin/rootfs-helper");
    fs::hard_link(&helper, &dest)
        .or_else(|_| fs::copy(&helper, &dest).map(|_| ()))
        .expect("failed to install rootfs-helper into rootfs");

    // Create busybox-style symlinks (relative, within rootfs)
    for cmd in &["sh", "cat", "echo", "ls", "pwd", "readlink", "true", "write"] {
        let link = rootfs.join(format!("usr/bin/{}", cmd));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink("rootfs-helper", &link)
            .expect("failed to create busybox symlink");
    }

    // Merged /usr symlinks (like real distros)
    let _ = std::os::unix::fs::symlink("usr/bin", rootfs.join("bin"));
    let _ = std::os::unix::fs::symlink("usr/sbin", rootfs.join("sbin"));

    rootfs
}

fn cleanup_rootfs(rootfs: &PathBuf) {
    let _ = fs::remove_dir_all(rootfs);
}

/// List / inside chroot shows rootfs contents (should see "usr", "tmp", "bin", "etc")
#[tokio::test]
async fn test_chroot_ls_root() {
    let rootfs = build_test_rootfs("ls-root");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/tmp")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "ls", "/"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "ls / should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert!(stdout.contains("usr"), "should list usr, got: {}", stdout);
            assert!(stdout.contains("tmp"), "should list tmp, got: {}", stdout);
            assert!(stdout.contains("bin"), "should list bin, got: {}", stdout);
            assert!(stdout.contains("etc"), "should list etc, got: {}", stdout);
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Path traversal via /../../ stays confined — reads a file unique to the chroot.
#[tokio::test]
async fn test_chroot_no_escape() {
    let rootfs = build_test_rootfs("no-escape");

    // Write a sentinel file only inside the chroot's /etc
    let sentinel = "sandlock-chroot-sentinel";
    fs::write(rootfs.join("etc/sentinel"), sentinel).unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    // Path traversal: /../../etc/sentinel should resolve to /etc/sentinel inside
    // the chroot (the sentinel file we created), not escape to the host.
    let result = policy.clone().run(&["rootfs-helper", "cat", "/../../etc/sentinel"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "cat should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert_eq!(
                stdout.trim(),
                sentinel,
                "should read chroot sentinel, got: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// pwd returns / inside chroot
#[tokio::test]
async fn test_chroot_getcwd() {
    let rootfs = build_test_rootfs("getcwd");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "pwd"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "pwd should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert_eq!(stdout, "/", "pwd should return /, got: {}", stdout);
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// A short absolute path must be reachable (issue #178). The old handler
/// redirected the child through "/proc/self/fd/N", 16 bytes that cannot fit
/// the buffer behind a path as short as "/tmp", so every short mount point
/// failed with ENAMETOOLONG while ls and open on the same path worked.
#[tokio::test]
async fn test_chroot_chdir_short_path() {
    let rootfs = build_test_rootfs("chdir-short");

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy.clone().run(&["rootfs-helper", "chdir", "/tmp"]).await {
        Ok(r) => {
            assert!(
                r.success(),
                "chdir(/tmp) should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert_eq!(r.stdout_str().unwrap_or("").trim(), "OK /tmp");
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// The virtual root is the shortest path there is, and no redirect can ever
/// fit its two-byte buffer. `cd /` has to work without one.
#[tokio::test]
async fn test_chroot_chdir_virtual_root() {
    let rootfs = build_test_rootfs("chdir-root");

    let policy = minimal_exec_policy(&rootfs).build().unwrap();

    match policy.clone().run(&["rootfs-helper", "chdir", "/"]).await {
        Ok(r) => {
            assert!(
                r.success(),
                "chdir(/) should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert_eq!(r.stdout_str().unwrap_or("").trim(), "OK /");
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// A relative path opened after a chdir must resolve against the directory
/// the child moved to. The supervisor resolves the path itself, so this is
/// what proves its notion of the cwd actually followed the chdir.
#[tokio::test]
async fn test_chroot_relative_open_follows_chdir() {
    let rootfs = build_test_rootfs("chdir-relative");
    fs::write(rootfs.join("tmp/marker.txt"), "marker-body\n").unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "sh", "-c", "chdir /tmp && cat marker.txt"])
        .await
    {
        Ok(r) => {
            assert!(
                r.success(),
                "relative cat after chdir should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("marker-body"),
                "relative open should have read /tmp/marker.txt, got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// fchdir carries a dirfd instead of a path, so a supervisor tracking the cwd
/// has to observe this spelling too. Chained after a chdir, which is where the
/// supervisor's own notion takes over: miss the fchdir and that notion goes
/// stale, sending the following relative open back to the chdir's directory.
#[tokio::test]
async fn test_chroot_relative_open_follows_fchdir() {
    let rootfs = build_test_rootfs("fchdir-relative");
    fs::write(rootfs.join("tmp/marker.txt"), "from-tmp\n").unwrap();
    fs::write(rootfs.join("etc/marker.txt"), "from-etc\n").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_write("/tmp")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "chdir /tmp && fchdir /etc && cat marker.txt",
        ])
        .await
    {
        Ok(r) => {
            assert!(
                r.success(),
                "relative cat after fchdir should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                stdout.contains("from-etc"),
                "relative open should have read /etc/marker.txt, got: {}",
                stdout
            );
            assert!(
                !stdout.contains("from-tmp"),
                "relative open resolved against the earlier chdir, got: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// /proc/self/cwd is the kernel's own view of the cwd, and the kernel's view
/// is the one the supervisor stopped moving. It has to be answered from the
/// tracked cwd or it reports wherever exec left the child.
#[tokio::test]
async fn test_chroot_proc_self_cwd_link_follows_chdir() {
    let rootfs = build_test_rootfs("proc-self-cwd-link");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .fs_write("/tmp")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "sh", "-c", "chdir /tmp && readlink /proc/self/cwd"])
        .await
    {
        Ok(r) => {
            // Exact match on the readlink line (the chdir prints its own):
            // the test rootfs itself lives under a host path containing
            // "/tmp", so a substring check would pass on a leak.
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert_eq!(
                stdout.lines().last().unwrap_or("").trim(),
                "/tmp",
                "readlink /proc/self/cwd should report the sandbox cwd, full stdout: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Opening *through* /proc/self/cwd has to land in the same directory the
/// link reports, so the magic link needs rewriting on the resolution path
/// too, not just when it is read.
#[tokio::test]
async fn test_chroot_open_through_proc_self_cwd() {
    let rootfs = build_test_rootfs("proc-self-cwd-open");
    fs::write(rootfs.join("tmp/marker.txt"), "from-tmp\n").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .fs_write("/tmp")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "chdir /tmp && cat /proc/self/cwd/marker.txt",
        ])
        .await
    {
        Ok(r) => {
            assert!(
                r.success(),
                "open through /proc/self/cwd should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("from-tmp"),
                "should have read /tmp/marker.txt, got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// A cwd the sandbox cannot name must never be answered with the host path
/// it happens to sit at. Without a `cwd` the child starts wherever sandlock
/// was launched, which is outside the virtual root entirely.
#[tokio::test]
async fn test_chroot_proc_self_cwd_never_leaks_a_host_path() {
    let rootfs = build_test_rootfs("proc-self-cwd-leak");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "readlink", "/proc/self/cwd"])
        .await
    {
        Ok(r) => {
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert!(
                !stdout.contains(rootfs.to_str().unwrap()),
                "cwd link leaked the rootfs's host path: {}",
                stdout
            );
            let launch_dir = std::env::current_dir().unwrap();
            assert!(
                !stdout.contains(launch_dir.to_str().unwrap()),
                "cwd link leaked the launch directory: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Removing a symlink must remove the link, not what it points at. The
/// chroot resolver follows the final component to find the file a path names,
/// which is right for open and wrong for unlink: it deleted the target and
/// left the dangling link behind.
#[tokio::test]
async fn test_chroot_unlink_removes_the_symlink_not_its_target() {
    let rootfs = build_test_rootfs("unlink-symlink");
    fs::write(rootfs.join("tmp/target.txt"), "target-body\n").unwrap();
    std::os::unix::fs::symlink("target.txt", rootfs.join("tmp/link.txt")).unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy.clone().run(&["rootfs-helper", "rm", "/tmp/link.txt"]).await {
        Ok(r) => {
            assert!(r.success(), "rm should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            assert!(
                rootfs.join("tmp/target.txt").exists(),
                "rm of a symlink deleted its target"
            );
            assert!(
                fs::symlink_metadata(rootfs.join("tmp/link.txt")).is_err(),
                "rm of a symlink left the link in place"
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// lstat must describe the link itself. Resolution for the policy check
/// follows the final component, so the no-follow spellings were being handed
/// an already-resolved path and reported the target's type and size.
#[tokio::test]
async fn test_chroot_lstat_describes_the_symlink() {
    let rootfs = build_test_rootfs("lstat-symlink");
    fs::write(rootfs.join("tmp/target.txt"), "target-body\n").unwrap();
    std::os::unix::fs::symlink("target.txt", rootfs.join("tmp/link.txt")).unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "legacy-lstat", "/tmp/link.txt"])
        .await
    {
        Ok(r) => {
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                stdout.contains("type=link"),
                "lstat should describe the link itself, got: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Renaming a symlink moves the link. Following the final component first
/// would rename whatever it points at, leaving the old name dangling.
#[tokio::test]
async fn test_chroot_rename_moves_the_symlink_not_its_target() {
    let rootfs = build_test_rootfs("rename-symlink");
    fs::write(rootfs.join("tmp/target.txt"), "target-body\n").unwrap();
    std::os::unix::fs::symlink("target.txt", rootfs.join("tmp/link.txt")).unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "mv", "/tmp/link.txt", "/tmp/moved.txt"])
        .await
    {
        Ok(r) => {
            assert!(r.success(), "mv should succeed, stderr: {}", r.stderr_str().unwrap_or(""));
            assert!(
                rootfs.join("tmp/target.txt").exists(),
                "rename of a symlink moved its target"
            );
            let moved = fs::symlink_metadata(rootfs.join("tmp/moved.txt"));
            assert!(
                moved.map(|m| m.file_type().is_symlink()).unwrap_or(false),
                "the moved entry should still be a symlink"
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// The /proc magic links are symlinks, and lstat has to say so even though
/// paths *through* them are rewritten to the directory they stand for.
#[tokio::test]
async fn test_chroot_lstat_of_proc_self_cwd_is_a_link() {
    let rootfs = build_test_rootfs("lstat-proc-cwd");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .fs_write("/tmp")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "legacy-lstat", "/proc/self/cwd"])
        .await
    {
        Ok(r) => {
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                stdout.contains("type=link"),
                "lstat of /proc/self/cwd should report a symlink, got: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Reading a magic link is a read of another process's state, so it needs the
/// same per-PID gate the /proc open path applies. Opening /proc/1/cwd was
/// already refused; readlinking it went straight to the supervisor's own view
/// of the host's process table.
#[tokio::test]
async fn test_chroot_readlink_of_a_foreign_pid_is_refused() {
    let rootfs = build_test_rootfs("readlink-foreign-pid");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "readlink", "/proc/1/cwd"])
        .await
    {
        Ok(r) => {
            assert!(
                !r.success(),
                "readlink of a non-sandbox pid should fail, stdout: {}",
                r.stdout_str().unwrap_or("")
            );
            assert!(
                !r.stdout_str().unwrap_or("").contains('/'),
                "readlink of a non-sandbox pid returned a path: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// An fd whose file the sandbox cannot name must not be described with the
/// host path behind it. /proc/<pid>/fd/N is a magic link, so the "target"
/// readlink hands back is a real host path the kernel synthesized, not link
/// text: an inherited stdio fd, or here a supervisor-opened /dev/null with
/// no /dev mount to map it into, would spell out where it lives on the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_chroot_fd_link_does_not_leak_a_host_path() {
    use sandlock_core::StdioMode;
    use std::fs::File;
    use std::io::Read;

    let rootfs = build_test_rootfs("fd-link-leak");

    let mut sb = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    match sb
        .popen(
            &["rootfs-helper", "readlink", "/proc/self/fd/0"],
            StdioMode::Null,
            StdioMode::Piped,
            StdioMode::Piped,
        )
        .await
    {
        Ok(mut child) => {
            let mut out = String::new();
            if let Some(stdout) = child.take_stdout() {
                let _ = File::from(stdout).read_to_string(&mut out);
            }
            let _ = child.wait().await;
            let link = out.trim().to_string();
            assert!(
                !link.starts_with('/'),
                "fd link named a path the sandbox cannot reach: {}",
                link
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// openat2 must be mediated like every other open spelling. It was trapped
/// for the deny check but never routed to the chroot handler, so an absolute
/// path reached the kernel as written and resolved against the host root
/// instead of the rootfs.
#[tokio::test]
async fn test_chroot_openat2_resolves_inside_the_rootfs() {
    let rootfs = build_test_rootfs("openat2-absolute");
    fs::write(rootfs.join("etc/marker.txt"), "from-rootfs\n").unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_read("/etc").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "openat2", "/etc/marker.txt"])
        .await
    {
        Ok(r) => {
            assert!(
                r.success(),
                "openat2 of a rootfs path should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("from-rootfs"),
                "openat2 should have read the rootfs file, got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// The same for a relative openat2 after a chdir: it resolves against the
/// supervisor's notion of the cwd, like every other relative path does.
#[tokio::test]
async fn test_chroot_openat2_relative_follows_chdir() {
    let rootfs = build_test_rootfs("openat2-relative");
    fs::write(rootfs.join("tmp/marker.txt"), "from-tmp\n").unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_write("/tmp").build().unwrap();

    match policy
        .clone()
        .run(&["rootfs-helper", "sh", "-c", "chdir /tmp && openat2 marker.txt"])
        .await
    {
        Ok(r) => {
            assert!(
                r.success(),
                "relative openat2 after chdir should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("from-tmp"),
                "openat2 should have read /tmp/marker.txt, got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// A RESOLVE_NO_SYMLINKS openat2 must still refuse a symlink once the
/// supervisor performs the open on its behalf. The child asked the kernel to
/// refuse it; servicing the open must not quietly grant what it declined.
#[tokio::test]
async fn test_chroot_openat2_honors_resolve_no_symlinks() {
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;

    let rootfs = build_test_rootfs("openat2-nosymlinks");
    fs::write(rootfs.join("etc/marker.txt"), "from-rootfs\n").unwrap();
    std::os::unix::fs::symlink("marker.txt", rootfs.join("etc/link.txt")).unwrap();

    let policy = minimal_exec_policy(&rootfs).fs_read("/etc").build().unwrap();

    match policy
        .clone()
        .run(&[
            "rootfs-helper",
            "openat2",
            "/etc/link.txt",
            &RESOLVE_NO_SYMLINKS.to_string(),
        ])
        .await
    {
        Ok(r) => {
            assert!(
                !r.success(),
                "openat2 through a symlink with RESOLVE_NO_SYMLINKS should fail, stdout: {}",
                r.stdout_str().unwrap_or("")
            );
            assert!(
                r.stderr_str().unwrap_or("").contains("openat2"),
                "expected the helper's openat2 error, got: {}",
                r.stderr_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// chdir into a same-path mount (/proc) from a READ-ONLY path buffer must
/// succeed. Regression for the busybox-`top` EFAULT: rewriting the child's
/// path argument to /proc/self/fd/N faults when the path lives in read-only
/// memory (a .rodata literal). The handler instead lets the kernel run the
/// original chdir unchanged when the on-behalf-resolved directory is identical
/// to the requested path, which holds for the /proc mount.
#[tokio::test]
async fn test_chroot_chdir_proc_readonly_buffer() {
    let rootfs = build_test_rootfs("chdir-proc-ro");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "chdir", "/proc"])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "chdir(/proc) from a read-only buffer should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            // cwd must be /proc (getcwd may render the mount root with a
            // trailing slash; the meaningful assertion is that we landed there).
            let cwd = r.stdout_str().unwrap_or("").trim().trim_end_matches('/').to_string();
            assert_eq!(cwd, "OK /proc", "cwd after chdir should be /proc");
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// chdir("/proc/self") must land on the CHILD's own /proc/<pid> dir, not the
/// supervisor's. sandlock services /proc via an on-behalf openat2 in the
/// supervisor task, so a literal "self" would resolve against the supervisor.
/// The chdir handler canonicalizes /proc/self to the child's numeric PID (same
/// as the open path), so getcwd() after the chdir renders the child's own
/// /proc/<pid> and its basename matches the child's getpid(). Before the fix the
/// cwd pointed at the supervisor's /proc/<pid> and the basename mismatched.
#[tokio::test]
async fn test_chroot_chdir_proc_self_resolves_to_child() {
    let rootfs = build_test_rootfs("chdir-proc-self");

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .build()
        .unwrap();

    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "chdir-self", "/proc/self"])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "chdir(/proc/self) should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            // The helper checks getcwd()'s basename == its own getpid(); "OK"
            // means "self" resolved to the child's own /proc/<pid>, not the
            // supervisor's.
            let out = r.stdout_str().unwrap_or("").trim().to_string();
            assert!(
                out.starts_with("OK /proc/"),
                "self must resolve to the child's own /proc/<pid>, got: {:?}",
                out
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// A dirfd-relative /proc read under a chroot with NO /proc mount must still
/// hit the synthesis shim. Regression: resolve_open_target took the proc
/// dirfd's real symlink target (`<chroot>/proc`) as the base, so
/// `openat(open("/proc"), "meminfo")` normalized to `<chroot>/proc/meminfo` and
/// missed the `== "/proc/meminfo"` synthesis match, falling through to the
/// chroot handler which ENOENT'd on the empty rootfs procfs, while the absolute
/// spelling was synthesized. The resolver now maps the dirfd base back into the
/// virtual namespace so both spellings synthesize identically.
#[tokio::test]
async fn test_chroot_proc_dirfd_relative_is_virtualized() {
    let rootfs = build_test_rootfs("proc-dirfd");

    // No fs_mount for /proc: it is the empty rootfs dir, so the file can only
    // come from synthesis. max_memory engages the /proc/meminfo shim.
    let policy = minimal_exec_policy(&rootfs)
        .max_memory(sandlock_core::sandbox::ByteSize::mib(256))
        .build()
        .unwrap();

    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "proc-dirfd", "meminfo"])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "dirfd-relative /proc/meminfo must be synthesized (not ENOENT), stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let out = r.stdout_str().unwrap_or("");
            assert!(out.contains("MemTotal"), "expected synthesized meminfo, got: {:?}", out);
            assert!(
                out.contains("262144"),
                "expected virtual 256MiB MemTotal (262144 kB), got: {:?}",
                out
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// A path that resolves (through symlinks) to a `/proc/self/fd/N` magic link
/// must open as a dup of the child's own fd, not fail. Regression: container
/// images wire logging through `error.log -> /dev/stderr -> /proc/self/fd/2`;
/// openat2(RESOLVE_IN_ROOT) refuses to traverse the magic link out of the
/// resolve root (EXDEV directly, or ENOENT when it points into another mount),
/// so the open handler must recognize the fd reference and hand back a dup of
/// the child's stderr. Before the fix this open failed and killed servers like
/// nginx at startup.
#[tokio::test]
async fn test_chroot_magic_fd_symlink_resolves_to_child_fd() {
    let rootfs = build_test_rootfs("magic-fd-link");
    std::os::unix::fs::symlink("/dev/stderr", rootfs.join("tmp/errlog")).unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_mount("/proc", "/proc")
        .fs_mount("/dev", "/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "write-fd-link", "/tmp/errlog", "MAGIC_MARKER"])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "open of errlog -> /dev/stderr -> /proc/self/fd/2 must succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            // The write lands on the child's own stderr via the magic link.
            assert!(
                r.stderr_str().unwrap_or("").contains("MAGIC_MARKER"),
                "marker must reach the child's stderr through the magic link, stderr: {:?}",
                r.stderr_str()
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// echo hello > /tmp/test.txt && cat /tmp/test.txt works, file appears in rootfs/tmp
#[tokio::test]
async fn test_chroot_write_file() {
    let rootfs = build_test_rootfs("write-file");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "sh", "-c", "echo hello > /tmp/test.txt && cat /tmp/test.txt"],
    )
    .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert_eq!(stdout, "hello", "cat should output hello, got: {}", stdout);
            // File should appear in rootfs/tmp (since /tmp inside chroot maps to rootfs/tmp)
            let real_path = rootfs.join("tmp/test.txt");
            assert!(
                real_path.exists(),
                "test.txt should exist at {}",
                real_path.display()
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Directory opens under chroot + COW must stay inside the chroot.
#[tokio::test]
async fn test_chroot_cow_directory_open_stays_in_rootfs() {
    let rootfs = build_test_rootfs("cow-dir-open");
    let tmp_dir = rootfs.join("tmp");

    fs::write(rootfs.join("tmp/rootfs-only.txt"), "rootfs").unwrap();

    let host_marker = std::env::temp_dir().join(format!(
        "sandlock-host-marker-{}",
        std::process::id()
    ));
    fs::write(&host_marker, "host").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "ls", "/tmp"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "ls /tmp should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert!(
                stdout.contains("rootfs-only.txt"),
                "expected to see rootfs file in /tmp, got: {}",
                stdout
            );
            assert!(
                !stdout.contains(host_marker.file_name().unwrap().to_string_lossy().as_ref()),
                "host /tmp leaked into chroot listing: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    let _ = fs::remove_file(&host_marker);
    cleanup_rootfs(&rootfs);
}

/// chroot + COW with BranchAction::Abort discards writes
#[tokio::test]
async fn test_chroot_with_cow() {
    let rootfs = build_test_rootfs("cow");
    let tmp_dir = rootfs.join("tmp");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "sh", "-c", "echo cow-test > /tmp/cow.txt"],
    )
    .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            // With abort, file should NOT exist
            let cow_file = tmp_dir.join("cow.txt");
            assert!(
                !cow_file.exists(),
                "cow.txt should not exist after abort, but found at {}",
                cow_file.display()
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// A file deleted in the COW branch (a whiteout) must return ENOENT on a
/// read-open under CHROOT mode — the sync `handle_open` path. Before the fix,
/// `handle_open` returned `Ok(None)` for the whiteout and `chroot/dispatch.rs`
/// fell through to `openat2_in_root` on the still-present lower file, leaking the
/// pre-delete bytes. This is the chroot-mode sibling of the async
/// `test_seccomp_cow_read_deleted_file_is_enoent`, and it exercises the real
/// dispatch arm (not just the branch object): `cat` issues a bare
/// `open(O_RDONLY)` with no preceding `stat` (rootfs-helper.c), so it drives the
/// open path rather than short-circuiting on the (correct) stat ENOENT.
#[tokio::test]
async fn test_chroot_cow_read_deleted_file_is_enoent() {
    let rootfs = build_test_rootfs("cow-read-deleted");
    let tmp_dir = rootfs.join("tmp");
    // Seed the LOWER file with sentinel content that must never leak.
    fs::write(tmp_dir.join("secret.txt"), "PREDELETE").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    // `rm` marks the file deleted in the branch (whiteout); `cat` then
    // bare-opens it in the same cage/branch. With the fix the open returns
    // ENOENT and nothing is printed; without it the untouched lower "PREDELETE"
    // bytes leak to stdout. (rootfs-helper's `sh -c` dispatches applets
    // in-process, so `rm` and `cat` share one COW branch.)
    let result = policy
        .clone()
        
        .run(&["rootfs-helper", "sh", "-c", "rm /tmp/secret.txt; cat /tmp/secret.txt"])
        .await;
    match result {
        Ok(r) => {
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                !stdout.contains("PREDELETE"),
                "pre-delete lower bytes leaked through the chroot read path (stdout: {:?})",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// readlink /proc/self/root returns /
#[tokio::test]
async fn test_chroot_proc_self_root() {
    let rootfs = build_test_rootfs("proc-self-root");

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "readlink", "/proc/self/root"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "readlink should succeed, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").trim().to_string();
            assert_eq!(
                stdout, "/",
                "readlink /proc/self/root should return /, got: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Writing to /tmp should fail when only fs_read is granted (no fs_write("/tmp"))
#[tokio::test]
async fn test_chroot_write_denied_without_fs_write() {
    let rootfs = build_test_rootfs("write-denied");

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_read("/tmp")
        // Deliberately NO fs_write("/tmp")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "sh", "-c", "echo denied > /tmp/should-fail.txt"],
    )
    .await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "write should fail without fs_write, but got exit=0"
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// execve inside chroot with fs_readable=["/"] should work — regression test
/// for a bug where the seccomp path rewrite truncated /proc/self/fd/N when
/// the original path buffer was shorter than the replacement string.
#[tokio::test]
async fn test_chroot_exec_with_root_readable() {
    let rootfs = build_test_rootfs("exec-root-readable");

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_read("/")
        .build()
        .unwrap();

    // Use /bin/rootfs-helper which goes through the bin -> usr/bin symlink
    let result = policy.clone().run(&["/bin/rootfs-helper", "echo", "chroot-exec-ok"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "/bin/rootfs-helper should succeed with fs_read(\"/\"), exit={:?} stderr: {} stdout: {}",
                r.code(), r.stderr_str().unwrap_or(""), r.stdout_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("");
            assert!(
                stdout.contains("chroot-exec-ok"),
                "should print chroot-exec-ok, got: {}",
                stdout
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// fs_deny should override fs_read inside chroot using virtual paths.
#[tokio::test]
async fn test_chroot_fs_deny_blocks_virtual_path() {
    let rootfs = build_test_rootfs("fs-deny");

    fs::write(rootfs.join("etc/hostname"), "sandlock-test-host").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .fs_deny("/etc/hostname")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/etc/hostname"]).await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "cat /etc/hostname should fail when fs_deny overrides fs_read, exit={:?} stdout={}",
                r.code(),
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Reading /etc/hostname should fail when /etc is not in fs_readable
#[tokio::test]
async fn test_chroot_read_denied_without_fs_read() {
    let rootfs = build_test_rootfs("read-denied");

    // Create a hostname file in the rootfs
    fs::write(rootfs.join("etc/hostname"), "sandlock-test-host").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        // Deliberately NO fs_read("/etc")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/etc/hostname"]).await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "cat /etc/hostname should fail without fs_read(\"/etc\"), exit={:?} stdout={}",
                r.code(),
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// fs_mount maps a host directory to a virtual path inside the chroot.
/// A file written to the host directory should be readable at the virtual path.
#[tokio::test]
async fn test_fs_mount_read_write() {
    let rootfs = build_test_rootfs("fs-mount-rw");

    // Create a /work directory inside the rootfs so the mount point exists
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let work_dir = temp_dir("fs-mount-work");

    // Write a test file in the host directory that will be mounted at /work
    fs::write(work_dir.join("input.txt"), "hello mount").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/tmp")
        .fs_write("/tmp")
        .fs_read("/work")
        .fs_write("/work")
        .fs_mount("/work", &work_dir)
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/work/input.txt"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "cat /work/input.txt failed: exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            assert_eq!(
                r.stdout_str().unwrap_or("").trim(),
                "hello mount",
                "expected 'hello mount', got: {}",
                r.stdout_str().unwrap_or("")
            );
        }
        Err(e) => eprintln!("fs_mount test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&rootfs);
    let _ = fs::remove_dir_all(&work_dir);
}

/// When the chroot image ships its own `/etc/hosts`, the synthetic file
/// the sandbox sees should be seeded from the image's content (so any
/// private-registry / internal-service entries the image baked in
/// survive virtualization) — with loopback entries added only if the
/// image didn't already provide them.
#[tokio::test]
async fn test_chroot_etc_hosts_seeded_from_image() {
    let rootfs = build_test_rootfs("etc-hosts-image-seed");
    // Put a hosts file in the image that has its own entry but is
    // missing both loopback families on purpose.
    fs::write(
        rootfs.join("etc/hosts"),
        "10.0.0.5 internal.registry.local\n",
    )
    .unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/etc/hosts"]).await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "cat /etc/hosts should succeed inside chroot, stderr: {}",
                r.stderr_str().unwrap_or("")
            );
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert!(
                stdout.contains("10.0.0.5 internal.registry.local"),
                "image's /etc/hosts entry missing: {stdout}"
            );
            assert!(
                stdout.contains("127.0.0.1 localhost"),
                "v4 loopback should be injected for the image: {stdout}"
            );
            assert!(
                stdout.contains("::1 localhost"),
                "v6 loopback should be injected for the image: {stdout}"
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// When the image already ships loopback entries, the synthesizer must
/// not duplicate them — the sandbox should see exactly the image's view
/// of localhost, not two copies of it.
#[tokio::test]
async fn test_chroot_etc_hosts_no_duplicate_loopback() {
    let rootfs = build_test_rootfs("etc-hosts-no-dup");
    fs::write(
        rootfs.join("etc/hosts"),
        "127.0.0.1 localhost\n::1 localhost\n10.0.0.5 svc.local\n",
    )
    .unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/etc")
        .build()
        .unwrap();

    let result = policy.clone().run(&["rootfs-helper", "cat", "/etc/hosts"]).await;
    match result {
        Ok(r) => {
            assert!(r.success(), "cat /etc/hosts should succeed");
            let stdout = r.stdout_str().unwrap_or("").to_string();
            assert_eq!(
                stdout.matches("127.0.0.1 localhost").count(),
                1,
                "v4 loopback duplicated: {stdout}"
            );
            assert_eq!(
                stdout.matches("::1 localhost").count(),
                1,
                "v6 loopback duplicated: {stdout}"
            );
            assert!(stdout.contains("10.0.0.5 svc.local"), "image entry missing: {stdout}");
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// `max_open_files` under `chroot`: the cap applies as usual, but a value too
/// low to start the process does *not* surface as `EMFILE`. Under `chroot` the
/// exec fd is injected by the supervisor, and an injection the guest's
/// descriptor limit refuses is answered `EIO`, so the run exits 127 with
/// "Input/output error". The documentation promises that errno for this mode;
/// this test is what keeps it honest.
#[tokio::test]
async fn test_max_open_files_chroot_exec_error_is_eio() {
    let rootfs = build_test_rootfs("max-open-files");

    // A workable cap changes nothing about the run.
    let ok = minimal_exec_policy(&rootfs)
        .max_open_files(64)
        .build()
        .unwrap()
        .run(&["rootfs-helper", "true"])
        .await;
    match ok {
        Ok(r) => assert!(
            r.success(),
            "a 64-descriptor cap should still run under chroot, stderr: {}",
            r.stderr_str().unwrap_or("")
        ),
        Err(e) => {
            eprintln!("Chroot test skipped: {}", e);
            cleanup_rootfs(&rootfs);
            return;
        }
    }

    // Too low to install the injected exec fd: the guest never reaches `main`.
    let too_low = minimal_exec_policy(&rootfs)
        .max_open_files(3)
        .build()
        .unwrap()
        .run(&["rootfs-helper", "true"])
        .await
        .unwrap();
    assert_eq!(
        too_low.code(),
        Some(127),
        "a cap below the chroot startup floor must fail the exec, stderr: {}",
        too_low.stderr_str().unwrap_or("")
    );
    let stderr = too_low.stderr_str().unwrap_or("").to_string();
    assert!(
        stderr.contains("Input/output error") || stderr.contains("os error 5"),
        "the chroot exec failure is reported as EIO, not EMFILE, got: {stderr}"
    );

    cleanup_rootfs(&rootfs);
}

/// A dense parent fd table must not raise the chroot startup floor.
///
/// Regression test: `close_fds_above` used to enumerate `/proc/self/fd`, which
/// the already-installed confinement denies under chroot, so it silently closed
/// nothing and the child carried the parent's whole fd table into exec. The
/// injected exec fd then had to land above all of them, and a parent holding
/// descriptors past the cap (a busy parallel test run) turned the exec into
/// EMFILE-reported-as-EIO. The floor must depend on the sandbox, not on how
/// many files the embedding process happens to have open.
#[tokio::test]
async fn test_max_open_files_chroot_ignores_parent_fd_density() {
    let rootfs = build_test_rootfs("max-open-files-density");

    // Occupy fd numbers well past the cap for the duration of the spawn.
    let _hold: Vec<fs::File> = (0..80)
        .map(|_| fs::File::open("/dev/null").expect("open /dev/null"))
        .collect();

    let result = minimal_exec_policy(&rootfs)
        .max_open_files(64)
        .build()
        .unwrap()
        .run(&["rootfs-helper", "true"])
        .await;
    match result {
        Ok(r) => assert!(
            r.success(),
            "a 64-descriptor cap must not fail just because the parent holds \
             more fds than the cap, stderr: {}",
            r.stderr_str().unwrap_or("")
        ),
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// AT_SYMLINK_FOLLOW asks for the inode behind a symlink, and the supervisor
/// performs the link itself from outside the chroot. If the source is resolved
/// by walking its parent and appending the last component, a symlink whose
/// target does not exist inside the root comes back as the symlink itself, and
/// the host kernel then resolves it a second time against the real root: the
/// guest picks any host path it likes and gets a hard link to it inside the
/// sandbox, readable and writable.
#[tokio::test]
async fn test_chroot_hardlink_follow_cannot_reach_a_host_file() {
    use std::os::unix::fs::MetadataExt;

    let rootfs = build_test_rootfs("hardlink-follow-escape");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    // Outside the rootfs and outside every grant, but on the same filesystem,
    // so a hard link to it is physically possible and the refusal below is the
    // only thing standing in the way.
    let host_dir = temp_dir("hardlink-follow-host");
    let host_secret = host_dir.join("host-only.txt");
    fs::write(&host_secret, "HOST-ONLY").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .build()
        .unwrap();

    let bait = host_secret.to_string_lossy().to_string();
    let planted = match policy
        .clone()
        .run(&["rootfs-helper", "ln", "-s", &bait, "/work/bait"])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Chroot test skipped: {}", e);
            cleanup_rootfs(&rootfs);
            let _ = fs::remove_dir_all(&host_dir);
            return;
        }
    };
    // A symlink is just a string, so planting it is allowed; the target is
    // meaningless inside the root. Without this the refusal below would prove
    // nothing.
    assert!(
        planted.success(),
        "planting the symlink should be allowed, exit={:?} stderr={}",
        planted.code(),
        planted.stderr_str().unwrap_or("")
    );

    let followed = policy
        .clone()
        .run(&["rootfs-helper", "linkat", "/work/bait", "/work/pwn", "follow"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        !followed.success(),
        "following a symlink out of the root should be refused, exit={:?} stderr={}",
        followed.code(),
        followed.stderr_str().unwrap_or("")
    );
    // The sandbox says the same thing about a target that is missing and one
    // that lives outside the root: from inside, the outside does not exist.
    assert!(
        followed
            .stderr_str()
            .unwrap_or("")
            .contains("No such file or directory"),
        "the refusal should report the target as absent, stderr={}",
        followed.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::metadata(&host_secret).unwrap().nlink(),
        1,
        "the host file gained a second name inside the sandbox"
    );

    let read_back = policy
        .clone()
        .run(&["rootfs-helper", "cat", "/work/pwn"])
        .await
        .expect("third run should launch once the first did");
    assert!(
        !read_back.stdout_str().unwrap_or("").contains("HOST-ONLY"),
        "host file contents were read from inside the sandbox: {}",
        read_back.stdout_str().unwrap_or("")
    );

    // The write side of the same escape: the destination name is writable by
    // policy, so this run succeeds either way. What it proves is which inode
    // that name refers to.
    let write_back = policy
        .clone()
        .run(&["rootfs-helper", "write", "/work/pwn", "OWNED"])
        .await
        .expect("fourth run should launch once the first did");
    assert!(
        write_back.success(),
        "writing the destination name should be allowed by policy, exit={:?} stderr={}",
        write_back.code(),
        write_back.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::read_to_string(&host_secret).unwrap().trim(),
        "HOST-ONLY",
        "a write inside the sandbox reached the host file, so the link landed \
         on the host inode"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&host_dir);
}

/// The other side of the same branch: a symlink whose target does resolve
/// inside the root still links the target's inode, not the symlink. Pins that
/// the confined resolution above did not turn AT_SYMLINK_FOLLOW into a blanket
/// refusal, and that the flag is honoured rather than quietly dropped.
#[tokio::test]
async fn test_chroot_hardlink_follow_links_the_target_inode() {
    use std::os::unix::fs::MetadataExt;

    let rootfs = build_test_rootfs("hardlink-follow-target");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .build()
        .unwrap();

    let setup = match policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "write /work/orig.txt PAYLOAD && ln -s orig.txt /work/link",
        ])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Chroot test skipped: {}", e);
            cleanup_rootfs(&rootfs);
            return;
        }
    };
    assert!(
        setup.success(),
        "creating the file and the symlink should succeed, exit={:?} stderr={}",
        setup.code(),
        setup.stderr_str().unwrap_or("")
    );

    let linked = policy
        .clone()
        .run(&["rootfs-helper", "linkat", "/work/link", "/work/alias.txt", "follow"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        linked.success(),
        "following a symlink that resolves inside the root should be allowed, \
         exit={:?} stderr={}",
        linked.code(),
        linked.stderr_str().unwrap_or("")
    );

    let target = rootfs.join("work/orig.txt");
    let alias = rootfs.join("work/alias.txt");
    assert!(
        !fs::symlink_metadata(&alias).unwrap().file_type().is_symlink(),
        "the flag was dropped: the new name copied the symlink instead of \
         linking its target"
    );
    assert_eq!(
        fs::metadata(&target).unwrap().ino(),
        fs::metadata(&alias).unwrap().ino(),
        "the new name should be a second name for the target's inode"
    );

    cleanup_rootfs(&rootfs);
}

/// A hard link hands out a second name for an inode, so after link(2) the
/// authority over that inode is the union of the policy on both names. Under
/// chroot the supervisor performs the link itself, so nothing downstream can
/// re-check it: if only the destination is gated, a guest can name a file it
/// may read but not write under a writable prefix and then write to it there.
///
/// Read-only mount flavour: /ro is readable (so the source resolves) but never
/// writable, /rw is writable.
#[tokio::test]
async fn test_chroot_hardlink_cannot_escalate_read_only_mount() {
    let rootfs = build_test_rootfs("hardlink-ro-mount");
    fs::create_dir_all(rootfs.join("ro")).unwrap();
    fs::create_dir_all(rootfs.join("rw")).unwrap();

    // Both host directories sit under the same temp base and therefore on the
    // same filesystem. A cross-filesystem pair would fail with EXDEV and the
    // escalation could not be attempted at all, making the test vacuous.
    let ro_dir = temp_dir("hardlink-ro-src");
    let rw_dir = temp_dir("hardlink-ro-dst");
    let secret = ro_dir.join("secret.txt");
    fs::write(&secret, "SECRET").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/ro")
        .fs_read("/rw")
        .fs_write("/rw")
        .fs_mount_ro("/ro", &ro_dir)
        .fs_mount("/rw", &rw_dir)
        .build()
        .unwrap();

    let direct = match policy
        .clone()
        .run(&["rootfs-helper", "write", "/ro/secret.txt", "PWNED"])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Chroot test skipped: {}", e);
            cleanup_rootfs(&rootfs);
            let _ = fs::remove_dir_all(&ro_dir);
            let _ = fs::remove_dir_all(&rw_dir);
            return;
        }
    };
    // Baseline: the policy grants no write on the source name. Without this
    // the link denial below would prove nothing.
    assert!(
        !direct.success(),
        "writing a read-only mount directly should fail, exit={:?}",
        direct.code()
    );

    let linked = policy
        .clone()
        .run(&["rootfs-helper", "ln", "/ro/secret.txt", "/rw/alias"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        !linked.success(),
        "hard-linking a read-only mount into a writable mount should be \
         refused, exit={:?} stderr={}",
        linked.code(),
        linked.stderr_str().unwrap_or("")
    );

    // The consequence, spelled out: whatever now lives at the destination name
    // must not be the protected inode. Writing through it is allowed by policy
    // (/rw is writable), so this run must succeed on its own terms; if it ever
    // stops doing so, the host-side check below would hold for a reason that
    // has nothing to do with the escalation.
    let through_alias = policy
        .clone()
        .run(&["rootfs-helper", "write", "/rw/alias", "PWNED"])
        .await
        .expect("third run should launch once the first did");
    assert!(
        through_alias.success(),
        "the escalation attempt itself must run, exit={:?} stderr={}",
        through_alias.code(),
        through_alias.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::read_to_string(&secret).unwrap().trim(),
        "SECRET",
        "a write to the destination name reached the read-only mount, so the \
         link aliased the protected inode"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&ro_dir);
    let _ = fs::remove_dir_all(&rw_dir);
}

/// fs_deny flavour of the same escalation: aliasing a denied file needs write
/// authority on the denied name, which fs_deny withholds, so the chain never
/// starts. Both the read and the write escalation are checked.
#[tokio::test]
async fn test_chroot_hardlink_cannot_alias_denied_path() {
    let rootfs = build_test_rootfs("hardlink-fs-deny");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let work_dir = temp_dir("hardlink-deny-work");
    let secret = work_dir.join("secret.txt");
    fs::write(&secret, "SECRET").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .fs_mount("/work", &work_dir)
        .fs_deny("/work/secret.txt")
        .build()
        .unwrap();

    let direct = match policy
        .clone()
        .run(&["rootfs-helper", "cat", "/work/secret.txt"])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Chroot test skipped: {}", e);
            cleanup_rootfs(&rootfs);
            let _ = fs::remove_dir_all(&work_dir);
            return;
        }
    };
    // Baseline: fs_deny wins over the surrounding writable mount.
    assert!(
        !direct.success(),
        "fs_deny should block reading the file by its own name, exit={:?} stdout={}",
        direct.code(),
        direct.stdout_str().unwrap_or("")
    );

    let linked = policy
        .clone()
        .run(&["rootfs-helper", "ln", "/work/secret.txt", "/work/alias.txt"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        !linked.success(),
        "hard-linking a denied path to an allowed name should be refused, \
         exit={:?} stderr={}",
        linked.code(),
        linked.stderr_str().unwrap_or("")
    );

    let via_alias = policy
        .clone()
        .run(&["rootfs-helper", "cat", "/work/alias.txt"])
        .await
        .expect("third run should launch once the first did");
    assert!(
        !via_alias.stdout_str().unwrap_or("").contains("SECRET"),
        "the denied file became readable under a second name: {}",
        via_alias.stdout_str().unwrap_or("")
    );

    // /work is writable, so this run must succeed whichever inode the second
    // name turns out to hold. Asserting that keeps the host-side check below
    // from passing because the write never happened.
    let through_alias = policy
        .clone()
        .run(&["rootfs-helper", "write", "/work/alias.txt", "PWNED"])
        .await
        .expect("fourth run should launch once the first did");
    assert!(
        through_alias.success(),
        "the escalation attempt itself must run, exit={:?} stderr={}",
        through_alias.code(),
        through_alias.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::read_to_string(&secret).unwrap().trim(),
        "SECRET",
        "a write to the second name reached the denied inode"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&work_dir);
}

/// The other side of the predicate: when the policy grants writes on both
/// names the link must still go through. Uses linkat(2) directly so the *at
/// entry point is exercised alongside the legacy link(2) the other tests take.
#[tokio::test]
async fn test_chroot_hardlink_allowed_when_both_sides_writable() {
    use std::os::unix::fs::MetadataExt;

    let rootfs = build_test_rootfs("hardlink-allowed");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let work_dir = temp_dir("hardlink-allowed-work");
    fs::write(work_dir.join("orig.txt"), "payload").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .fs_mount("/work", &work_dir)
        .build()
        .unwrap();

    // A probe run carries the skip convention, so a host that cannot launch
    // the sandbox at all is the only thing it can hide. The run under test
    // then has to launch, or this test would be the one place where an
    // over-denying gate could ship unnoticed.
    if let Err(e) = policy.clone().run(&["rootfs-helper", "true"]).await {
        eprintln!("Chroot test skipped: {}", e);
        cleanup_rootfs(&rootfs);
        let _ = fs::remove_dir_all(&work_dir);
        return;
    }

    let linked = policy
        .clone()
        .run(&["rootfs-helper", "linkat", "/work/orig.txt", "/work/alias.txt"])
        .await
        .expect("second run should launch once the probe did");
    assert!(
        linked.success(),
        "linking within a writable mount should be allowed, exit={:?} stderr={}",
        linked.code(),
        linked.stderr_str().unwrap_or("")
    );
    let orig = fs::metadata(work_dir.join("orig.txt")).unwrap();
    let alias = fs::metadata(work_dir.join("alias.txt")).unwrap();
    assert_eq!(
        orig.ino(),
        alias.ino(),
        "the second name should be a hard link, not a copy"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&work_dir);
}

/// The gate has to judge the inode the link will name, which under a mount is
/// not the name the child spelled: the mount resolver reports the requested
/// path back, so a symlink to a denied file inside the mount would be checked
/// as the symlink's own (allowed) name. AT_SYMLINK_FOLLOW is the spelling that
/// reaches that branch, and it needs no knowledge of any host path: a relative
/// symlink next to the target is enough.
#[tokio::test]
async fn test_chroot_hardlink_follow_cannot_alias_a_denied_path_under_a_mount() {
    let rootfs = build_test_rootfs("hardlink-follow-deny");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let work_dir = temp_dir("hardlink-follow-deny-work");
    let secret = work_dir.join("secret.txt");
    fs::write(&secret, "SECRET").unwrap();

    let policy = minimal_exec_policy(&rootfs)
        .fs_read("/work")
        .fs_write("/work")
        .fs_mount("/work", &work_dir)
        .fs_deny("/work/secret.txt")
        .build()
        .unwrap();

    let planted = match policy
        .clone()
        .run(&["rootfs-helper", "ln", "-s", "secret.txt", "/work/s"])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Chroot test skipped: {}", e);
            cleanup_rootfs(&rootfs);
            let _ = fs::remove_dir_all(&work_dir);
            return;
        }
    };
    // fs_deny covers the file, not the name of a symlink beside it, so
    // planting the bait is allowed and the refusal below is about the target.
    assert!(
        planted.success(),
        "planting the symlink should be allowed, exit={:?} stderr={}",
        planted.code(),
        planted.stderr_str().unwrap_or("")
    );

    let followed = policy
        .clone()
        .run(&["rootfs-helper", "linkat", "/work/s", "/work/alias.txt", "follow"])
        .await
        .expect("second run should launch once the first did");
    assert!(
        !followed.success(),
        "following a symlink to a denied file should be refused, exit={:?} stderr={}",
        followed.code(),
        followed.stderr_str().unwrap_or("")
    );

    let via_alias = policy
        .clone()
        .run(&["rootfs-helper", "cat", "/work/alias.txt"])
        .await
        .expect("third run should launch once the first did");
    assert!(
        !via_alias.stdout_str().unwrap_or("").contains("SECRET"),
        "the denied file became readable under a second name: {}",
        via_alias.stdout_str().unwrap_or("")
    );

    let through_alias = policy
        .clone()
        .run(&["rootfs-helper", "write", "/work/alias.txt", "PWNED"])
        .await
        .expect("fourth run should launch once the first did");
    assert!(
        through_alias.success(),
        "the escalation attempt itself must run, exit={:?} stderr={}",
        through_alias.code(),
        through_alias.stderr_str().unwrap_or("")
    );
    assert_eq!(
        fs::read_to_string(&secret).unwrap().trim(),
        "SECRET",
        "a write to the second name reached the denied inode"
    );

    cleanup_rootfs(&rootfs);
    let _ = fs::remove_dir_all(&work_dir);
}

/// A copy-on-write branch stages writes in an upper layer and, under
/// BranchAction::Abort, throws them away. A hard link cannot be half staged:
/// with one name inside the workdir and the other below it, there is nothing
/// to stage, and performing the link for real would create the name in the
/// pristine workdir instead. EXDEV is the kernel's own word for a link that
/// cannot span two sides.
#[tokio::test]
async fn test_chroot_hardlink_into_a_branch_is_refused() {
    let rootfs = build_test_rootfs("hardlink-branch-in");
    let tmp_dir = rootfs.join("tmp");
    fs::create_dir_all(rootfs.join("work")).unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/work")
        .fs_write("/work")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "write /work/a.txt LEAKED && ln /work/a.txt /tmp/pulled-in.txt",
        ])
        .await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "a hard link into the branch should be refused, exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stderr_str().unwrap_or("").contains("Invalid cross-device link"),
                "the refusal should read as a cross-device link, stderr={}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                !tmp_dir.join("pulled-in.txt").exists(),
                "the branch was aborted, yet the link landed in the workdir itself"
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// The other direction, and the damaging one: a name taken out of the workdir
/// aliases the *lower* inode, so a write through it edits the very file the
/// branch promised to leave alone, and the edit outlives the abort.
#[tokio::test]
async fn test_chroot_hardlink_out_of_a_branch_is_refused() {
    let rootfs = build_test_rootfs("hardlink-branch-out");
    let tmp_dir = rootfs.join("tmp");
    fs::create_dir_all(rootfs.join("work")).unwrap();
    fs::write(tmp_dir.join("orig.txt"), "ORIGINAL").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read("/work")
        .fs_write("/work")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "ln /tmp/orig.txt /work/alias.txt && write /work/alias.txt OVERWRITTEN",
        ])
        .await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "a hard link out of the branch should be refused, exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            assert!(
                !rootfs.join("work/alias.txt").exists(),
                "the second name was created outside the branch"
            );
            assert_eq!(
                fs::read_to_string(tmp_dir.join("orig.txt")).unwrap().trim(),
                "ORIGINAL",
                "the aborted branch still edited the file it was staging over"
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// Both names inside the workdir is the case the branch can stage, so it must
/// keep working, and it must stay in the branch: after an abort neither the
/// second name nor the copy of the first is left in the workdir.
#[tokio::test]
async fn test_chroot_hardlink_within_a_branch_stays_in_the_branch() {
    let rootfs = build_test_rootfs("hardlink-branch-within");
    let tmp_dir = rootfs.join("tmp");
    fs::write(tmp_dir.join("orig.txt"), "ORIGINAL").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "ln /tmp/orig.txt /tmp/alias.txt && cat /tmp/alias.txt",
        ])
        .await;
    match result {
        Ok(r) => {
            assert!(
                r.success(),
                "a link between two names inside the workdir should be allowed, \
                 exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stdout_str().unwrap_or("").contains("ORIGINAL"),
                "the second name should read as the file it links, stdout={}",
                r.stdout_str().unwrap_or("")
            );
            assert!(
                !tmp_dir.join("alias.txt").exists(),
                "the aborted branch left its second name in the workdir"
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// A file deleted in the branch is a whiteout: the lower entry is still on
/// disk with its pre-delete bytes. Linking it must answer ENOENT rather than
/// resurrect it, which is the same rule the read-open path already follows.
#[tokio::test]
async fn test_chroot_hardlink_to_a_file_deleted_in_the_branch_is_enoent() {
    let rootfs = build_test_rootfs("hardlink-branch-whiteout");
    let tmp_dir = rootfs.join("tmp");
    fs::write(tmp_dir.join("orig.txt"), "PREDELETE").unwrap();

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .workdir(&tmp_dir)
        .on_exit(BranchAction::Abort)
        .build()
        .unwrap();

    let result = policy
        .clone()
        .run(&[
            "rootfs-helper",
            "sh",
            "-c",
            "rm /tmp/orig.txt && ln /tmp/orig.txt /tmp/alias.txt",
        ])
        .await;
    match result {
        Ok(r) => {
            assert!(
                !r.success(),
                "linking a file the branch deleted should be refused, exit={:?} stderr={}",
                r.code(),
                r.stderr_str().unwrap_or("")
            );
            assert!(
                r.stderr_str().unwrap_or("").contains("No such file or directory"),
                "the deleted file should read as absent, stderr={}",
                r.stderr_str().unwrap_or("")
            );
            assert!(
                !tmp_dir.join("alias.txt").exists(),
                "the pre-delete inode came back under a second name in the workdir"
            );
        }
        Err(e) => eprintln!("Chroot test skipped: {}", e),
    }

    cleanup_rootfs(&rootfs);
}

/// chmod is not a Landlock-gated operation, so an fchmodat2 left to the
/// kernel resolves its absolute path against the host root: `chmod -h`
/// inside the chroot reaches the host's file, or gets ENOENT when the host
/// has none at that path.
#[tokio::test]
async fn test_chroot_fchmodat2_resolves_in_rootfs() {
    use std::os::unix::fs::PermissionsExt;
    let rootfs = build_test_rootfs("fchmodat2");
    let name = format!("sandlock-fchmodat2-{}", std::process::id());
    let inside = rootfs.join("tmp").join(&name);
    let decoy = std::path::Path::new("/tmp").join(&name);
    for p in [&inside, &decoy] {
        fs::write(p, "x").unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o644)).unwrap();
    }

    let policy = Sandbox::builder()
        .chroot(&rootfs)
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let virt = format!("/tmp/{name}");
    let result = policy
        .clone()
        .run(&["rootfs-helper", "chmod2", "600", &virt, "nofollow"])
        .await
        .unwrap();
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let (got_inside, got_decoy) = (mode(&inside), mode(&decoy));
    let _ = fs::remove_file(&decoy);
    cleanup_rootfs(&rootfs);

    assert!(result.success(), "chmod2 should succeed, stderr: {}", result.stderr_str().unwrap_or(""));
    assert_eq!(got_inside, 0o600, "the rootfs file must carry the new mode");
    assert_eq!(got_decoy, 0o644, "the host file at the same path must be untouched");
}

// Each test here spawns a full `sandlock` process.
// Running all tests in parallel exhausts kernel resources on most hosts.
// Limit parallelism when running this suite:
//   cargo test -p sandlock-cli --test learn_test -- --test-threads=4

use std::io::Read;
use std::process::Command;

fn sandlock_bin() -> Command {
    let cmd = Command::new(env!("CARGO_BIN_EXE_sandlock"));
    cmd
}

/// Drop `-r /lib64` from a CLI argument list when the host has no `/lib64`
/// (RISC-V glibc and musl put the loader under `/lib`, with no `/lib64` at
/// all). `-r` maps to a mandatory `fs_read`, so requiring `/lib64` on such a
/// host aborts confinement; this mirrors `fs_read_if_exists` at the CLI layer.
/// On hosts that have `/lib64` (x86-64) the arguments pass through unchanged.
#[allow(dead_code)]
fn args_for_host(args: &[&str]) -> Vec<String> {
    let has_lib64 = std::path::Path::new("/lib64").exists();
    let mut out: Vec<String> = Vec::with_capacity(args.len());
    for a in args {
        if *a == "/lib64" && !has_lib64 {
            if out.last().map(|s| s == "-r").unwrap_or(false) {
                out.pop();
            }
            continue;
        }
        out.push((*a).to_string());
    }
    out
}

// ── Filesystem reads ──────────────────────────────────────────────────────────

/// Reads are recorded in the profile.
#[test]
fn test_learn_captures_fs_read() {
    let output = sandlock_bin()
        .args(["learn", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains("/etc/hostname"),
        "expected /etc/hostname under read = [...], got: {read_line}",
    );
}

/// When the workload binary is a symlink, the real binary path is captured via process maps.
/// Skipped on hosts where python3 resolves directly (not a symlink).
#[test]
fn test_learn_captures_real_binary_path_via_maps() {
    let python3 = std::process::Command::new("which")
        .arg("python3")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if python3.is_empty() { return; }
    let real = match std::fs::canonicalize(&python3) {
        Ok(p) => p,
        Err(_) => return,
    };
    if real.to_str() == Some(python3.as_str()) {
        eprintln!("skipped: python3 is not a symlink on this host");
        return;
    }
    let real_str = real.to_str().unwrap().to_string();

    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", "pass"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains(&real_str),
        "real binary {real_str} not in reads (only visible via r-xp maps): {read_line}",
    );
}

// ── Filesystem writes ─────────────────────────────────────────────────────────

/// Writes to existing files are recorded in the profile. COW ensures real file content is unchanged.
#[test]
fn test_learn_captures_fs_write() {
    let tmp1 = tempfile::NamedTempFile::new().expect("tempfile");
    let tmp2 = tempfile::Builder::new().tempdir_in("/var/tmp").expect("tempdir");
    let tmp2_file = tmp2.path().join("sandlock-learn-write2.txt");
    let path1 = tmp1.path().to_str().unwrap().to_owned();
    let path2 = tmp2_file.to_str().unwrap().to_owned();
    let cmd = format!("echo x > {path1} && echo y > {path2}");
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains(&path1), "expected {path1} under write = [...], got: {write_line}");
    assert!(write_line.contains(&path2) || write_line.contains(tmp2.path().to_str().unwrap()),
        "expected {path2} (or its parent) under write = [...], got: {write_line}");
    // COW: real file must not have been modified
    let content = std::fs::read_to_string(&path1).unwrap_or_default();
    assert!(content.is_empty(), "COW isolation failed: real file was written to");
}

/// Creates to non-existent files collapse to the parent directory.
/// COW ensures the real filesystem is not modified during learn.
#[test]
fn test_learn_new_file_collapses_to_parent() {
    let dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let path = dir.path().join("write-test.txt");
    let path_str = path.to_str().unwrap();
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &format!("echo x > {path_str}")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(
        write_line.contains("/var/tmp"),
        "expected /var/tmp under write = [...], got: {write_line}",
    );
    assert!(!path.exists(), "COW isolation failed: real filesystem was modified");
}

/// Directory creates and deletions are captured. COW ensures the real filesystem is not modified.
#[test]
fn test_learn_captures_dir_create_and_delete() {
    let base = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let dir = base.path().join("newdir");
    let dir_str = dir.to_str().unwrap();
    let file = tempfile::NamedTempFile::new_in(base.path()).expect("tempfile");
    let file_path = file.path().to_str().unwrap().to_owned();
    let cmd = format!("mkdir {dir_str} && rm {file_path}");
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains("/var/tmp"),
        "expected /var/tmp in write = [...], got: {write_line}");
    assert!(!dir.exists(), "COW isolation failed: dir was created on real FS");
    assert!(std::path::Path::new(&file_path).exists(), "COW isolation failed: file was deleted on real FS");
}

/// Renames capture both source and destination parents. COW ensures the real filesystem is not modified.
#[test]
fn test_learn_captures_rename() {
    let src = tempfile::NamedTempFile::new_in("/var/tmp").expect("tempfile in /var/tmp");
    let src_path = src.path().to_str().unwrap().to_owned();
    let dst = "/tmp/sandlock-learn-rename-dst-test";
    let cmd = format!("mv {src_path} {dst}");
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains("/var/tmp"), "expected /var/tmp (src parent) in: {write_line}");
    assert!(write_line.contains("/tmp"), "expected /tmp (dst parent) in: {write_line}");
    assert!(src.path().exists(), "COW isolation failed: src was deleted on real FS");
    assert!(!std::path::Path::new(dst).exists(), "COW isolation failed: dst was created on real FS");
}

/// Symlink creates are captured by the link path, not the target.
/// COW ensures the real filesystem is not modified.
#[test]
fn test_learn_captures_symlink() {
    let dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let link = dir.path().join("link");
    let link_str = link.to_str().unwrap();
    let cmd = format!("ln -s hostname {link_str}");
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains("/var/tmp"), "expected /var/tmp (link parent) in: {write_line}");
    assert!(!link.exists(), "COW isolation failed: symlink created on real FS");
}

/// Hard link creates are captured by destination; source appears in reads.
/// COW ensures the real filesystem is not modified.
#[test]
fn test_learn_captures_hardlink() {
    let src = tempfile::NamedTempFile::new_in("/var/tmp").expect("tempfile in /var/tmp");
    let src_path = src.path().to_str().unwrap().to_owned();
    let dst_dir = tempfile::TempDir::new_in("/tmp").expect("tempdir in /tmp");
    let dst = dst_dir.path().join("hardlink");
    let dst_str = dst.to_str().unwrap();
    let cmd = format!("ln {src_path} {dst_str}");
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(write_line.contains("/tmp"), "expected /tmp (dst parent) in: {write_line}");
    assert!(!write_line.contains("/var/tmp"), "src parent /var/tmp wrongly recorded as write in: {write_line}");
    assert!(read_line.contains(&src_path), "expected src {src_path} in reads: {read_line}");
    assert!(!dst.exists(), "COW isolation failed: hardlink created on real FS");
}

/// Truncate is captured as a write on the file path itself. COW ensures the real file is unchanged.
#[test]
fn test_learn_captures_truncate() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), "original content").expect("write");
    let path = tmp.path().to_str().unwrap().to_owned();
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &format!("truncate -s 0 {path}")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains(&path),
        "expected file path {path} in write = [...], got: {write_line}");
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(content, "original content", "COW isolation failed: real file was truncated");
}

// ── Network ───────────────────────────────────────────────────────────────────

/// TCP connections are recorded under [network] allow.
#[test]
fn test_learn_captures_net_connect() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _t = std::thread::spawn(move || { let _ = listener.accept(); });

    let script = format!(
        "import socket; s=socket.socket(); s.connect(('127.0.0.1',{port})); s.close()"
    );
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = format!("127.0.0.1:{port}");
    let net_line = stdout.lines().find(|l| l.starts_with("allow = [")).unwrap_or("");
    assert!(
        net_line.contains(&expected),
        "expected {expected} under [network] allow = [...], got: {net_line}",
    );
}

/// IPv6 endpoints are recorded with brackets: tcp://[::1]:port.
/// Skipped on hosts without IPv6 loopback.
#[test]
fn test_learn_captures_ipv6_connect() {
    let listener = match std::net::TcpListener::bind("[::1]:0") {
        Ok(l) => l,
        Err(_) => { eprintln!("skipped: IPv6 loopback unavailable"); return; }
    };
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || { let _ = listener.accept(); });

    let script = format!(
        "import socket; s=socket.socket(socket.AF_INET6); s.connect(('::1',{port})); s.close()"
    );
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = format!("tcp://[::1]:{port}");
    let net_line = stdout.lines().find(|l| l.starts_with("allow = [")).unwrap_or("");
    assert!(net_line.contains(&expected),
        "expected {expected} under [network] allow = [...], got: {net_line}");
}

/// getaddrinfo routing probes (UDP connect to port 80) must not appear in the profile.
#[test]
fn test_learn_no_phantom_udp_from_getaddrinfo() {
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c",
               "import socket; socket.getaddrinfo('localhost', 80)"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let allow_line = stdout.lines().find(|l| l.starts_with("allow = [")).unwrap_or("allow = []");
    assert!(!allow_line.contains("udp://"),
        "phantom UDP entries from routing probes must not appear in profile: {allow_line}");
}

/// Bind calls are recorded under [network] allow_bind.
#[test]
fn test_learn_captures_bind() {
    let script = concat!(
        "import socket\n",
        "s = socket.socket()\n",
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "s.bind(('127.0.0.1', 19876))\n",
        "s.close()\n",
    );
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let bind_line = stdout.lines().find(|l| l.starts_with("allow_bind = [")).unwrap_or("");
    assert!(
        bind_line.contains("19876"),
        "expected 19876 in allow_bind, got: {bind_line}",
    );
}

/// AF_UNIX named bind: the socket path's parent directory is recorded in writes
#[test]
fn test_learn_captures_unix_bind() {
    let dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let sock = dir.path().join("test.sock");
    let sock_str = sock.to_str().unwrap();
    let script = format!(
        "import socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); \
         s.bind('{sock_str}'); s.close()"
    );
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    let parent = dir.path().to_str().unwrap();
    assert!(write_line.contains(parent),
        "expected parent dir {parent} in write = [...], got: {write_line}");
}

/// mknod/mknodat: FIFO creates are captured by the parent directory (Landlock
/// MAKE_FIFO is a directory right, so the parent is what sandlock run needs).
#[test]
fn test_learn_captures_mknod() {
    let dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let fifo = dir.path().join("test.fifo");
    let fifo_str = fifo.to_str().unwrap();
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c",
               &format!("import os; os.mkfifo('{fifo_str}')")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    let parent = dir.path().to_str().unwrap();
    assert!(write_line.contains(parent),
        "expected parent dir {parent} in write = [...], got: {write_line}");
    assert!(!fifo.exists(), "COW isolation failed: FIFO was created on real FS");
}

/// UDP destinations via sendto and sendmsg are both recorded under [network] allow.
#[test]
fn test_learn_captures_udp() {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 16];
        let _ = sock.recv_from(&mut buf);
        let _ = sock.recv_from(&mut buf);
    });

    let script = format!(
        "import socket\n\
         s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n\
         s.sendto(b'hi',('127.0.0.1',{port}))\n\
         s.sendmsg([b'hi'],[],0,('127.0.0.1',{port}))\n\
         s.close()"
    );
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = format!("udp://127.0.0.1:{port}");
    assert!(
        stdout.contains(&expected),
        "expected {expected} in network output, got:\n{stdout}",
    );
}

/// All destinations in a sendmmsg call are recorded, not just the first.
#[test]
fn test_learn_captures_sendmmsg_all_destinations() {
    let sock1 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let sock2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port1 = sock1.local_addr().unwrap().port();
    let port2 = sock2.local_addr().unwrap().port();
    std::thread::spawn(move || { let mut b = [0u8;8]; let _ = sock1.recv_from(&mut b); });
    std::thread::spawn(move || { let mut b = [0u8;8]; let _ = sock2.recv_from(&mut b); });

    let script = format!(concat!(
        "import ctypes, socket, struct\n",
        "libc = ctypes.CDLL('libc.so.6')\n",
        "class iovec(ctypes.Structure):\n",
        "    _fields_ = [('iov_base', ctypes.c_void_p), ('iov_len', ctypes.c_size_t)]\n",
        "class msghdr(ctypes.Structure):\n",
        "    _fields_ = [\n",
        "        ('msg_name', ctypes.c_void_p),\n",
        "        ('msg_namelen', ctypes.c_uint),\n",
        "        ('_p1', ctypes.c_uint),\n",
        "        ('msg_iov', ctypes.c_void_p),\n",
        "        ('msg_iovlen', ctypes.c_size_t),\n",
        "        ('msg_control', ctypes.c_void_p),\n",
        "        ('msg_controllen', ctypes.c_size_t),\n",
        "        ('msg_flags', ctypes.c_int),\n",
        "        ('_p2', ctypes.c_uint),\n",
        "    ]\n",
        "class mmsghdr(ctypes.Structure):\n",
        "    _fields_ = [('msg_hdr', msghdr), ('msg_len', ctypes.c_uint), ('_p', ctypes.c_uint)]\n",
        "def sai(port):\n",
        "    return struct.pack('=HH4s8x', socket.AF_INET, socket.htons(port), socket.inet_aton('127.0.0.1'))\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n",
        "a1 = ctypes.create_string_buffer(sai({port1}))\n",
        "a2 = ctypes.create_string_buffer(sai({port2}))\n",
        "data = ctypes.create_string_buffer(b'x')\n",
        "iovs = (iovec * 2)()\n",
        "iovs[0].iov_base = ctypes.cast(data, ctypes.c_void_p).value\n",
        "iovs[0].iov_len = 1\n",
        "iovs[1].iov_base = ctypes.cast(data, ctypes.c_void_p).value\n",
        "iovs[1].iov_len = 1\n",
        "vec = (mmsghdr * 2)()\n",
        "vec[0].msg_hdr.msg_name = ctypes.cast(a1, ctypes.c_void_p).value\n",
        "vec[0].msg_hdr.msg_namelen = 16\n",
        "vec[0].msg_hdr.msg_iov = ctypes.cast(ctypes.pointer(iovs[0]), ctypes.c_void_p).value\n",
        "vec[0].msg_hdr.msg_iovlen = 1\n",
        "vec[1].msg_hdr.msg_name = ctypes.cast(a2, ctypes.c_void_p).value\n",
        "vec[1].msg_hdr.msg_namelen = 16\n",
        "vec[1].msg_hdr.msg_iov = ctypes.cast(ctypes.pointer(iovs[1]), ctypes.c_void_p).value\n",
        "vec[1].msg_hdr.msg_iovlen = 1\n",
        "libc.sendmmsg(s.fileno(), vec, 2, 0)\n",
        "s.close()\n",
    ), port1 = port1, port2 = port2);

    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", &script])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let allow_line = stdout.lines().find(|l| l.starts_with("allow = [")).unwrap_or("");
    assert!(allow_line.contains(&format!("udp://127.0.0.1:{port1}")),
        "expected port {port1} in allow, got: {allow_line}");
    assert!(allow_line.contains(&format!("udp://127.0.0.1:{port2}")),
        "expected port {port2} (second sendmmsg destination) in allow, got: {allow_line}");
}

// ── Resource limits ───────────────────────────────────────────────────────────

/// Resource peaks are recorded under [limits].
#[test]
fn test_learn_captures_resource_limits() {
    let output = sandlock_bin()
        .args(["learn", "--", "sleep", "0.2"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("memory = \""), "expected memory limit in learn output, got:\n{stdout}");
    assert!(stdout.contains("processes = "), "expected processes limit in learn output, got:\n{stdout}");
    // TODO: uncomment when open_files enforcement is implemented in the supervisor
    // assert!(stdout.contains("open_files = "), "expected open_files limit in learn output, got:\n{stdout}");
}

// ── Path collapse and dedup ───────────────────────────────────────────────────

/// A write-open of a device node under learn reaches the real device: a COW
/// stub in the upper layer would leave ncurses apps without a tty.
#[test]
fn test_learn_device_write_open_reaches_real_device() {
    let output = sandlock_bin()
        .args([
            "learn", "--", "python3", "-c",
            "import os, stat; fd = os.open('/dev/null', os.O_RDWR); \
             print('ISCHR', stat.S_ISCHR(os.fstat(fd).st_mode))",
        ])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ISCHR True"), "expected a real character device, got:\n{stdout}");
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains("/dev/null"), "expected /dev/null in writes, got: {write_line}");
}

/// Dedup removes a path when an ancestor is already in the read set.
#[test]
fn test_read_dedup_removes_leaf_when_ancestor_present() {
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", "ls /etc > /dev/null && cat /etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(read_line.contains("/etc"), "expected /etc in reads, got: {read_line}");
    assert!(!read_line.contains("/etc/hostname"),
        "expected /etc/hostname removed by dedup (covered by /etc), got: {read_line}");
}

/// N-threshold collapse replaces individual files with their parent directory.
///
/// Uses a private tempdir rather than /usr/bin: learn canonicalizes observed
/// paths, and on hosts where coreutils are symlinks into a multicall link farm
/// (e.g. Ubuntu rust-coreutils on riscv64) the /usr/bin names scatter across
/// parents that never reach the collapse threshold (issue #170).
#[test]
fn test_collapse_threshold_reads() {
    let dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let dir_path = dir.path().canonicalize().expect("canonicalize tempdir");
    let observed: Vec<String> = (1..=4)
        .map(|i| {
            let p = dir_path.join(format!("observed{i}.txt"));
            std::fs::write(&p, "collapse me\n").expect("write observed file");
            p.to_str().unwrap().to_owned()
        })
        .collect();

    let mut cmd = sandlock_bin();
    cmd.args(["learn", "--collapse=4", "--", "cat"]);
    cmd.args(&observed);
    let output = cmd.output().expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains(&format!("\"{}\"", dir_path.display())),
        "expected {} collapsed in reads, got: {read_line}",
        dir_path.display(),
    );
    assert!(!read_line.contains("observed1.txt"),
        "expected individual files removed after collapse, got: {read_line}");
}

/// --collapse-prefix forces collapse regardless of the file count threshold.
///
/// Two observed files stay below the N=4 default threshold, so only the
/// prefix can produce the directory grant. Hermetic for the same reason as
/// test_collapse_threshold_reads (issue #170).
#[test]
fn test_collapse_prefix_forces_collapse() {
    let dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let dir_path = dir.path().canonicalize().expect("canonicalize tempdir");
    let observed: Vec<String> = (1..=2)
        .map(|i| {
            let p = dir_path.join(format!("observed{i}.txt"));
            std::fs::write(&p, "collapse me\n").expect("write observed file");
            p.to_str().unwrap().to_owned()
        })
        .collect();

    let mut cmd = sandlock_bin();
    cmd.args(["learn", "--collapse-prefix", dir_path.to_str().unwrap(), "--", "cat"]);
    cmd.args(&observed);
    let output = cmd.output().expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains(&format!("\"{}\"", dir_path.display())),
        "expected {} collapsed in reads, got: {read_line}",
        dir_path.display(),
    );
    assert!(!read_line.contains("observed1.txt"),
        "expected individual files removed after prefix collapse, got: {read_line}");
}

/// Guarded paths are not collapsed by the N-threshold; individual files are kept.
#[test]
fn test_collapse_guarded_not_collapsed_by_threshold() {
    let output = sandlock_bin()
        .args(["learn", "--collapse", "--", "sh", "-c",
               "cat /etc/hostname /etc/hosts /etc/resolv.conf /etc/passwd"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(read_line.contains("/etc/hostname"),
        "expected individual /etc files kept (guarded, not collapsed), got: {read_line}");
}

/// --collapse-prefix on a guarded path requires --force-sensitive-collapse.
#[test]
fn test_collapse_prefix_guarded_requires_force() {
    let output = sandlock_bin()
        .args(["learn", "--collapse-prefix", "/etc", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(!output.status.success(), "expected failure without --force-sensitive-collapse");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--force-sensitive-collapse"),
        "expected hint about --force-sensitive-collapse in stderr, got: {stderr}");
}

/// --collapse-prefix on a guarded path with --force-sensitive-collapse collapses and emits a warning.
#[test]
fn test_collapse_prefix_guarded_with_force() {
    let output = sandlock_bin()
        .args(["learn", "--collapse-prefix", "/etc", "--force-sensitive-collapse",
               "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(
        read_line.contains("/etc\"") || read_line.contains("/etc,"),
        "expected /etc in reads after forced collapse, got: {read_line}",
    );
    assert!(!read_line.contains("/etc/hostname"),
        "expected /etc/hostname removed after collapse, got: {read_line}");
    assert!(stderr.contains("guarded directory"),
        "expected guarded directory warning, got: {stderr}");
}

/// Write collapse to filesystem root is skipped entirely.
#[test]
fn test_write_collapse_skips_root() {
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", "echo x > /sandlock_learn_root_test_$$"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(!write_line.contains("\"/\""), "write list must not contain \"/\", got: {write_line}");
    assert!(stderr.contains("filesystem root"),
        "expected filesystem root warning in stderr, got: {stderr}");
}

/// Write collapse to a sensitive path emits a warning and observed-vs-granted diff.
#[test]
fn test_write_collapse_warns_sensitive() {
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", "echo x > /etc/sandlock_learn_sensitive_test_$$"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(
        output.status.success(),
        "sandlock learn failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(write_line.contains("/etc"), "expected /etc in write list, got: {write_line}");
    assert!(stderr.contains("guarded directory"),
        "expected 'guarded directory' warning in stderr, got: {stderr}");
    assert!(stderr.contains("unobserved siblings now writable under"),
        "expected observed-vs-granted diff in stderr, got: {stderr}");
}

/// Write collapse to a protected path is skipped entirely.
#[test]
fn test_write_collapse_skips_protected() {
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", "echo x > /root/sandlock_learn_protected_test_$$"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(), "stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("");
    assert!(!write_line.contains("/root\"") && !write_line.contains("/root,"),
        "write list must not contain /root (protected), got: {write_line}");
    assert!(stderr.contains("protected path"),
        "expected 'protected path' error in stderr, got: {stderr}");
}

/// mkdirat on an existing target (EEXIST) must not add the parent to the write set.
#[test]
fn test_mkdirat_eexist_no_write() {
    let base = tempfile::TempDir::new_in("/var/tmp").expect("tempdir in /var/tmp");
    let existing = base.path().join("already_there");
    std::fs::create_dir(&existing).expect("create subdir");
    let existing_str = existing.to_str().unwrap();
    let base_str = base.path().to_str().unwrap();
    // mkdirat fires pre-syscall; without the EEXIST guard the parent
    // (base_str) would be inserted into the write set.
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &format!("mkdir {existing_str} 2>/dev/null; true")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("write = []");
    assert!(!write_line.contains(base_str),
        "mkdirat on existing target must not insert parent {base_str} into writes, got: {write_line}");
}

/// Direct write to "/" must be dropped with a warning, not recorded.
#[test]
fn test_direct_write_root_skipped() {
    let dir = format!("/sandlock_learn_root_mkdir_{}", std::process::id());
    let output = sandlock_bin()
        .args(["learn", "--", "sh", "-c", &format!("mkdir {dir} 2>/dev/null; true")])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let write_line = stdout.lines().find(|l| l.starts_with("write = [")).unwrap_or("write = []");
    assert!(!write_line.contains("\"/\""),
        "direct write of \"/\" must be dropped, got: {write_line}");
    assert!(stderr.contains("direct write of '/'"),
        "expected direct write warning in stderr, got: {stderr}");
}

/// /proc/self/maps must appear in the profile as /proc/self/maps
#[test]
fn test_proc_self_maps_preserved() {
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", "open('/proc/self/maps').read()"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(read_line.contains("\"/proc/self/maps\""),
        "/proc/self/maps must be recorded as-is, got: {read_line}");
    let has_numeric_pid = read_line.split("\"/proc/").skip(1).any(|s| {
        s.chars().next().map_or(false, |c| c.is_ascii_digit())
    });
    assert!(!has_numeric_pid,
        "must not contain a numeric-pid /proc/<pid>/... entry, got: {read_line}");
}

/// /proc/self/exe is a symlink to the real binary; it must be resolved to the
/// binary path, not recorded as /proc/self/exe.
#[test]
fn test_proc_self_exe_resolves_to_binary() {
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", "import os; os.open('/proc/self/exe', os.O_RDONLY)"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(!read_line.contains("\"/proc/self/exe\""),
        "/proc/self/exe must be resolved to the binary path, not recorded as-is: {read_line}");
    let interp = std::process::Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("run python3");
    let interp = String::from_utf8_lossy(&interp.stdout).trim().to_string();
    let interp = std::fs::canonicalize(&interp).expect("canonicalize python3");
    let expected = format!("\"{}\"", interp.display());
    assert!(read_line.contains(&expected),
        "expected resolved interpreter {expected} in reads, got: {read_line}");
}

/// Opening /proc/self itself (no sub-entry) must be recorded as /proc/self,
/// not resolved to /proc/<pid> and then dropped as junk.
#[test]
fn test_proc_self_bare_preserved() {
    let output = sandlock_bin()
        .args(["learn", "--", "python3", "-c", "import os; os.listdir('/proc/self')"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "sandlock learn failed: stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let read_line = stdout.lines().find(|l| l.starts_with("read = [")).unwrap_or("");
    assert!(read_line.contains("\"/proc/self\""),
        "/proc/self must be recorded as-is, got: {read_line}");
}

// ── Merge and canonicalization ────────────────────────────────────────────────

/// --merge unions observations from a new run into an existing profile.
#[test]
fn test_learn_merge_unions_profiles() {
    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    let learn1 = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn1.status.success(),
        "first learn failed: {}", String::from_utf8_lossy(&learn1.stderr));

    let learn2 = sandlock_bin()
        .args(["learn", "--merge", &profile_path, "--", "cat", "/etc/os-release"])
        .output()
        .expect("failed to run sandlock learn --merge");
    assert!(learn2.status.success(),
        "merge learn failed: {}", String::from_utf8_lossy(&learn2.stderr));

    let merged = std::fs::read_to_string(&profile_path).expect("read merged profile");
    assert!(merged.contains("/etc/hostname") || merged.contains("/etc"),
        "merged profile missing /etc/hostname: {merged}");
    assert!(merged.contains("/etc/os-release") || merged.contains("/etc"),
        "merged profile missing /etc/os-release: {merged}");
    assert!(merged.contains("hostname"),
        "merged profile must keep [program] from first run: {merged}");

    // deny rules and port ranges in the existing profile must survive a merge.
    let existing = format!(
        "[filesystem]\ndeny = [\"/secret\"]\n\n[network]\nallow_bind = [\"9000-9005\", 8080]\n"
    );
    std::fs::write(&profile_path, &existing).expect("write existing profile");
    let learn3 = sandlock_bin()
        .args(["learn", "--merge", &profile_path, "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run sandlock learn --merge");
    assert!(learn3.status.success(),
        "merge with deny rules failed: {}", String::from_utf8_lossy(&learn3.stderr));
    let merged2 = std::fs::read_to_string(&profile_path).expect("read merged profile");
    assert!(merged2.contains("/secret"),
        "deny rule must survive merge: {merged2}");
    assert!(merged2.contains("9000-9005"),
        "port range spec must survive merge verbatim: {merged2}");
    assert!(merged2.contains("8080"),
        "numeric port must survive merge: {merged2}");
}

/// Paths accessed through symlinks are recorded as their canonical real path.
#[test]
fn test_learn_symlink_path_canonicalized() {
    let real_dir = tempfile::TempDir::new_in("/var/tmp").expect("tempdir");
    let file = real_dir.path().join("data.txt");
    std::fs::write(&file, "hello").expect("write file");
    let real_path = file.to_str().unwrap().to_owned();

    let link = format!("/tmp/sandlock-e7-link-{}", std::process::id());
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(real_dir.path(), &link).expect("create symlink");
    let via_link = format!("{link}/data.txt");

    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();

    let learn = sandlock_bin()
        .args(["learn", "-o", &profile_path, "--", "cat", &via_link])
        .output()
        .expect("failed to run sandlock learn");
    assert!(learn.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    let profile_content = std::fs::read_to_string(&profile_path).expect("read profile");
    assert!(
        profile_content.contains(real_dir.path().to_str().unwrap()),
        "profile must contain canonical path {}, got:\n{profile_content}",
        real_dir.path().display()
    );

    let run = sandlock_bin()
        .args(["run", "--profile-file", &profile_path, "--", "cat", &real_path])
        .output()
        .expect("failed to run sandlock run");
    assert!(run.status.success(),
        "run via real path failed (canonicalization not applied): {}",
        String::from_utf8_lossy(&run.stderr));

    let _ = std::fs::remove_file(&link);
}

// ── HTTP learning ─────────────────────────────────────────────────────────────

/// Spawn a minimal HTTP server on an ephemeral port and return the port.
/// The server loops over incoming connections, returning a 200 OK for each.
fn spawn_http_server() -> u16 {
    use std::io::Write;
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // Accept multiple connections so the server handles repeated test requests.
        for stream in listener.incoming() {
            let mut stream = match stream { Ok(s) => s, Err(_) => break };
            // Read until the end of HTTP headers.
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = stream.write_all(response);
        }
    });
    port
}

/// A plaintext HTTP request is captured and written as an [http] allow rule.
#[test]
fn test_learn_captures_http_request() {
    let port = spawn_http_server();
    let url = format!("http://127.0.0.1:{port}/hello");

    let output = sandlock_bin()
        .args(["learn", "--http-port", &port.to_string(), "--", "curl", "-sf", &url])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&output.stderr));

    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(profile.contains("[http]"), "expected [http] section: {profile}");
    assert!(profile.contains("ports"), "expected ports in [http]: {profile}");
    assert!(profile.contains(&port.to_string()), "expected port {port} in [http].ports: {profile}");
    assert!(profile.contains("GET"), "expected GET rule in [http].allow: {profile}");
    assert!(profile.contains("/hello"), "expected /hello path in [http].allow: {profile}");
}

/// --http-port writes only the intercepted port to [http].ports, not port 80.
#[test]
fn test_learn_http_port_not_inflated() {
    let port = spawn_http_server();
    let url = format!("http://127.0.0.1:{port}/hello");

    let output = sandlock_bin()
        .args(["learn", "--http-port", &port.to_string(), "--", "curl", "-sf", &url])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&output.stderr));

    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(profile.contains(&format!("ports = [{}]", port)),
        "expected only port {port} in [http].ports, got: {profile}");
}

/// Multiple distinct requests to different paths are all recorded and deduplicated.
#[test]
fn test_learn_captures_http_multiple_paths() {
    let port = spawn_http_server();
    let url_a = format!("http://127.0.0.1:{port}/a");
    let url_b = format!("http://127.0.0.1:{port}/b");
    // Request /a twice to verify deduplication.
    let cmd = format!("curl -sf {url_a} && curl -sf {url_b} && curl -sf {url_a}");

    let output = sandlock_bin()
        .args(["learn", "--http-port", &port.to_string(), "--", "sh", "-c", &cmd])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&output.stderr));

    let profile = String::from_utf8_lossy(&output.stdout);
    let allow_count = profile.matches("GET 127.0.0.1").count();
    assert_eq!(allow_count, 2,
        "expected exactly 2 unique GET rules (/a and /b), got {allow_count}: {profile}");
}

/// Returns the first system CA bundle path that exists on this machine,
/// or None if no known path is found (test is skipped in that case).
fn system_ca_bundle() -> Option<&'static str> {
    for path in &[
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path);
        }
    }
    None
}

/// Returns true if host:443 accepts a TCP connection within 3 seconds.
fn https_reachable(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut it) = format!("{host}:443").to_socket_addrs() else { return false };
    let Some(addr) = it.next() else { return false };
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3)).is_ok()
}

/// HTTPS traffic via --http-inject-ca is captured and written as an [http] allow rule.
/// Uses a real HTTPS server (example.com) so that TLS termination, MITM cert signing,
/// CA injection, and proxy forwarding are all exercised end to end.
/// Skipped if example.com is unreachable or no system CA bundle is found.
#[test]
fn test_learn_captures_https_request() {
    if !https_reachable("example.com") {
        eprintln!("skipping test_learn_captures_https_request: example.com unreachable");
        return;
    }
    let Some(ca_bundle) = system_ca_bundle() else {
        eprintln!("skipping test_learn_captures_https_request: no system CA bundle found");
        return;
    };

    let output = sandlock_bin()
        .args([
            "learn",
            "--http-inject-ca", ca_bundle,
            "--", "curl", "-sf", "https://example.com/",
        ])
        .output()
        .expect("failed to run sandlock learn");
    assert!(output.status.success(),
        "learn failed: {}", String::from_utf8_lossy(&output.stderr));

    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(profile.contains("[http]"), "expected [http] section: {profile}");
    assert!(profile.contains("example.com"), "expected example.com in [http].allow: {profile}");
    assert!(profile.contains("[config]"), "expected [config] section: {profile}");
    assert!(profile.contains("http_inject_ca"), "expected http_inject_ca in [config]: {profile}");
    assert!(profile.contains(ca_bundle), "expected ca bundle path in [config]: {profile}");
}

/// --merge keeps a hand-written ${HOME} and does not append its expanded twin.
#[test]
fn test_learn_merge_preserves_home_variable() {
    let home = std::env::var("HOME").expect("HOME set");
    let probe_dir = std::path::PathBuf::from(&home).join(".config");
    std::fs::create_dir_all(&probe_dir).expect("create probe dir");
    let probe = probe_dir.join("sandlock-merge-probe");
    std::fs::write(&probe, b"ok").expect("write probe");

    let profile = tempfile::NamedTempFile::new().expect("tempfile");
    let profile_path = profile.path().to_str().unwrap().to_owned();
    std::fs::write(&profile_path, "[filesystem]\nread = [\"${HOME}/.config\", \"/usr\"]\n")
        .expect("seed profile");

    let learn = sandlock_bin()
        .args(["learn", "--merge", &profile_path, "--", "cat", probe.to_str().unwrap()])
        .output()
        .expect("failed to run sandlock learn --merge");
    let _ = std::fs::remove_file(&probe);
    assert!(learn.status.success(),
        "merge learn failed: {}", String::from_utf8_lossy(&learn.stderr));

    let merged = std::fs::read_to_string(&profile_path).expect("read merged profile");
    let parsed: sandlock_core::ProfileInput = toml::from_str(&merged).expect("parse merged");
    let reads: Vec<String> = parsed.filesystem.read.iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    assert!(reads.iter().any(|r| r == "${HOME}/.config"),
        "merge dropped the ${{HOME}} spelling: {reads:?}");
    assert!(!reads.iter().any(|r| r.starts_with(&format!("{home}/.config"))),
        "merge added a machine-specific duplicate of ${{HOME}}/.config: {reads:?}");
}

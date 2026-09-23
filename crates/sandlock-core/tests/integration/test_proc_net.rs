use std::net::{TcpListener, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;

use sandlock_core::{Sandbox, SandboxBuilder};

fn proc_grant() -> SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
}

fn inode(fd: &impl AsRawFd) -> u64 {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) }, 0);
    stat.st_ino
}

async fn run_python(builder: SandboxBuilder, script: &str) {
    let result = builder
        .build()
        .unwrap()
        .run(&["python3", "-c", script])
        .await
        .unwrap();
    assert!(result.success(), "{}", result.stderr_str().unwrap_or(""));
    assert_eq!(result.stdout_str().unwrap_or("").trim(), "OK");
}

#[tokio::test]
async fn test_proc_net_socket_tables_isolate_families_and_unix() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tcp6 = TcpListener::bind("[::1]:0").unwrap();
    let udp6 = UdpSocket::bind("[::1]:0").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let unix = UnixListener::bind(directory.path().join("foreign.sock")).unwrap();
    let owned_path = directory.path().join("owned.sock");
    let script = format!(
        r#"
import errno, os, socket
try:
    socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4)
except OSError as error:
    assert error.errno == errno.EAFNOSUPPORT, error
else:
    raise AssertionError('sandbox opened NETLINK_SOCK_DIAG')
sockets = []
fixtures = [(socket.AF_INET, socket.SOCK_STREAM, '127.0.0.1', 'tcp', {tcp}),
            (socket.AF_INET, socket.SOCK_DGRAM, '127.0.0.1', 'udp', {udp}),
            (socket.AF_INET6, socket.SOCK_STREAM, '::1', 'tcp6', {tcp6}),
            (socket.AF_INET6, socket.SOCK_DGRAM, '::1', 'udp6', {udp6})]
for family, kind, address, table, foreign in fixtures:
    sock = socket.socket(family, kind)
    sock.bind((address, 0))
    if kind == socket.SOCK_STREAM:
        sock.listen()
    sockets.append(sock)
    own = os.fstat(sock.fileno()).st_ino
    rows = [row.split() for row in open('/proc/net/' + table).read().splitlines()[1:]]
    found = {{int(row[9]) for row in rows}}
    assert own in found, (table, own, rows)
    assert foreign not in found, (table, foreign, rows)
    row = next(row for row in rows if int(row[9]) == own)
    assert int(row[1].split(':')[1], 16) == sock.getsockname()[1], row
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind({path:?})
sock.listen()
own = os.fstat(sock.fileno()).st_ino
rows = open('/proc/net/unix').read().splitlines()[1:]
found = {{int(row.split()[6]) for row in rows}}
assert own in found, rows
assert {unix} not in found, rows
assert any(row.endswith({path:?}) for row in rows if int(row.split()[6]) == own), rows
assert all('foreign.sock' not in row for row in rows), rows
print('OK')
"#,
        tcp = inode(&tcp),
        udp = inode(&udp),
        tcp6 = inode(&tcp6),
        udp6 = inode(&udp6),
        unix = inode(&unix),
        path = owned_path.to_str().unwrap()
    );
    run_python(
        proc_grant()
            .fs_write(directory.path())
            .net_allow("udp://127.0.0.1:53")
            .net_allow_bind("*"),
        &script,
    )
    .await;
}

#[tokio::test]
async fn test_proc_net_remapped_listener_survives_dup_and_fork() {
    let foreign = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = foreign.local_addr().unwrap().port();
    let script = format!(
        r#"
import os, socket, traceback
sock = socket.socket()
sock.bind(('127.0.0.1', {port}))
sock.listen()
own = os.fstat(sock.fileno()).st_ino
assert sock.getsockname()[1] == {port}
fd = os.dup(sock.fileno())
sock.close()
def check():
    rows = [row.split() for row in open('/proc/net/tcp').read().splitlines()[1:]]
    owned = [row for row in rows if int(row[9]) == own]
    assert len(owned) == 1, rows
    assert int(owned[0][1].split(':')[1], 16) == {port}, owned
    assert not any(int(row[9]) == {foreign} for row in rows), rows
check()
pid = os.fork()
if pid == 0:
    try:
        check()
    except BaseException:
        traceback.print_exc()
        os._exit(1)
    os._exit(0)
assert os.waitpid(pid, 0)[1] == 0
check()
os.close(fd)
assert not any(int(row.split()[9]) == own for row in open('/proc/net/tcp').read().splitlines()[1:])
print('OK')
"#,
        foreign = inode(&foreign)
    );
    run_python(
        proc_grant().net_allow_bind_port(port).port_remap(true),
        &script,
    )
    .await;
}

#[tokio::test]
async fn test_proc_net_outbound_connection_without_explicit_bind_is_owned() {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let script = format!(
        r#"
import os, socket
sock = socket.socket()
sock.connect(('127.0.0.1', {port}))
own = os.fstat(sock.fileno()).st_ino
rows = [row.split() for row in open('/proc/net/tcp').read().splitlines()[1:]]
owned = [row for row in rows if int(row[9]) == own]
assert len(owned) == 1, rows
assert owned[0][3] == '01', owned
assert int(owned[0][1].split(':')[1], 16) == sock.getsockname()[1], owned
assert int(owned[0][2].split(':')[1], 16) == {port}, owned
assert not any(int(row[9]) == {foreign} for row in rows), rows
print('OK')
"#,
        foreign = inode(&server)
    );
    run_python(proc_grant().net_allow(format!("127.0.0.1:{port}")), &script).await;
}

#[tokio::test]
async fn test_proc_net_sockstat_counts_owned_sockets_and_hides_netlink_transport() {
    let _foreign_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let _foreign_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let script = r#"
import os, socket

def stats(path):
    result = {}
    for line in open(path):
        fields = line.split()
        result[fields[0].rstrip(':')] = {fields[i]: int(fields[i+1]) for i in range(1, len(fields), 2)}
    return result

before = stats('/proc/net/sockstat')
before6 = stats('/proc/net/sockstat6')
assert before['TCP']['inuse'] == 0, before
assert before['UDP']['inuse'] == 0, before
sockets = []
for family, address in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
    for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
        sock = socket.socket(family, kind)
        sock.bind((address, 0))
        if kind == socket.SOCK_STREAM:
            sock.listen()
        sockets.append(sock)
left, right = socket.socketpair()
sockets.extend([left, right])
duplicate = os.dup(left.fileno())
netlink = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
transport = os.fstat(netlink.fileno()).st_ino
unix_inodes = {int(row.split()[6]) for row in open('/proc/net/unix').read().splitlines()[1:]}
assert transport not in unix_inodes, unix_inodes
assert os.fstat(left.fileno()).st_ino in unix_inodes
assert os.fstat(right.fileno()).st_ino in unix_inodes
after = stats('/proc/net/sockstat')
after6 = stats('/proc/net/sockstat6')
assert after['sockets']['used'] - before['sockets']['used'] == 6, (before, after)
assert after['TCP']['inuse'] - before['TCP']['inuse'] == 1, (before, after)
assert after['UDP']['inuse'] - before['UDP']['inuse'] == 1, (before, after)
assert after6['TCP6']['inuse'] - before6['TCP6']['inuse'] == 1, (before6, after6)
assert after6['UDP6']['inuse'] - before6['UDP6']['inuse'] == 1, (before6, after6)
netlink.close()
os.close(duplicate)
for sock in sockets:
    sock.close()
assert stats('/proc/net/sockstat')['sockets']['used'] == before['sockets']['used']
print('OK')
"#;
    run_python(
        proc_grant()
            .net_allow("udp://127.0.0.1:53")
            .net_allow_bind("*"),
        script,
    )
    .await;
}

#[tokio::test]
async fn test_proc_net_worker_thread_reads_all_owned_sockets() {
    run_python(
        proc_grant().net_allow_bind("*"),
        r#"
import os, socket, threading, traceback
sockets = []
for _ in range(8):
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen()
    sockets.append(sock)
expected = {os.fstat(sock.fileno()).st_ino for sock in sockets}
errors = []
def check():
    try:
        for _ in range(3):
            rows = open('/proc/net/tcp').read().splitlines()[1:]
            assert {int(row.split()[9]) for row in rows} == expected, rows
    except BaseException:
        errors.append(traceback.format_exc())
worker = threading.Thread(target=check)
worker.start()
worker.join()
assert not errors, errors
print('OK')
"#,
    )
    .await;
}

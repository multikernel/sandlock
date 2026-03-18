# SPDX-License-Identifier: Apache-2.0
"""Integration tests for Sandlock sandbox.

These tests exercise the full sandbox lifecycle including fork,
confinement, and cleanup.  All tests use temporary directories,
never system paths like /home.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import pytest

from sandlock import Sandbox, Policy, Result
from sandlock._landlock import landlock_abi_version

# Libraries the child process needs to run Python.
# Include the real Python prefix (may be /opt/... on CI with setup-python).
_PYTHON_PREFIX = os.path.dirname(os.path.dirname(os.path.realpath(sys.executable)))
_PYTHON_READABLE = list(dict.fromkeys([
    "/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev",
    _PYTHON_PREFIX,
]))


# --- Basic lifecycle ---

class TestRunIntegration:
    def test_echo(self):
        result = Sandbox(Policy()).run(["echo", "hello world"])
        assert result.success
        assert result.stdout.strip() == b"hello world"

    def test_exit_code(self):
        result = Sandbox(Policy()).run(["python3", "-c", "import sys; sys.exit(42)"])
        assert not result.success
        assert result.exit_code == 42

    def test_stderr_captured(self):
        result = Sandbox(Policy()).run(
            ["python3", "-c", "import sys; sys.stderr.write('err\\n')"]
        )
        assert b"err" in result.stderr

    def test_timeout(self):
        result = Sandbox(Policy()).run(["sleep", "60"], timeout=0.5)
        assert not result.success
        assert "timed out" in result.error.lower()

    def test_shell_command_flag(self):
        """sandlock run -e 'cmd' should execute via /bin/sh -c."""
        r = subprocess.run(
            ["sandlock", "run", "-e", "echo hello world"],
            capture_output=True,
        )
        assert r.returncode == 0
        assert b"hello world" in r.stdout

    def test_shell_command_with_shell_features(self):
        """sandlock run -e should support pipes and redirects."""
        r = subprocess.run(
            ["sandlock", "run", "-e", "echo foo | tr f b"],
            capture_output=True,
        )
        assert r.returncode == 0
        assert b"boo" in r.stdout

    def test_shell_command_and_positional_are_exclusive(self):
        """Providing both -e and positional command should still work (positional ignored)."""
        r = subprocess.run(
            ["sandlock", "run", "-e", "echo from-flag", "echo", "from-positional"],
            capture_output=True,
        )
        assert r.returncode == 0
        assert b"from-flag" in r.stdout


class TestCallIntegration:
    def test_return_value(self):
        result = Sandbox(Policy()).call(lambda: {"answer": 42})
        assert result.success
        assert result.value == {"answer": 42}

    def test_exception_propagation(self):
        def fail():
            raise RuntimeError("intentional")

        result = Sandbox(Policy()).call(fail)
        assert not result.success
        assert "RuntimeError" in result.error

    def test_runs_in_separate_process(self):
        parent_pid = os.getpid()
        result = Sandbox(Policy()).call(os.getpid)
        assert result.success
        assert result.value != parent_pid

    def test_timeout(self):
        import time
        result = Sandbox(Policy()).call(lambda: time.sleep(60), timeout=0.5)
        assert not result.success


# --- Landlock filesystem enforcement ---

@pytest.mark.skipif(
    landlock_abi_version() < 1,
    reason="Landlock not available on this kernel",
)
class TestLandlockEnforcement:
    def test_can_read_allowed_path(self):
        with tempfile.TemporaryDirectory() as td:
            testfile = os.path.join(td, "readable.txt")
            with open(testfile, "w") as f:
                f.write("secret")

            policy = Policy(
                fs_readable=[*_PYTHON_READABLE, td],
            )
            result = Sandbox(policy).run(
                ["python3", "-c", f"print(open('{testfile}').read())"]
            )
            assert result.success
            assert b"secret" in result.stdout

    def test_cannot_read_outside_allowed(self):
        """Child cannot read a temp dir that's not in fs_readable."""
        with tempfile.TemporaryDirectory() as allowed, \
             tempfile.TemporaryDirectory() as forbidden:
            testfile = os.path.join(forbidden, "nope.txt")
            with open(testfile, "w") as f:
                f.write("nope")

            policy = Policy(
                fs_readable=[*_PYTHON_READABLE, allowed],
            )
            result = Sandbox(policy).run(
                ["python3", "-c", f"open('{testfile}').read()"]
            )
            assert not result.success

    def test_can_write_to_writable_path(self):
        with tempfile.TemporaryDirectory() as td:
            outfile = os.path.join(td, "out.txt")
            policy = Policy(
                fs_readable=_PYTHON_READABLE,
                fs_writable=[td],
            )
            result = Sandbox(policy).run(
                ["python3", "-c", f"open('{outfile}', 'w').write('written')"]
            )
            assert result.success
            assert open(outfile).read() == "written"

    def test_cannot_write_to_readable_only_path(self):
        with tempfile.TemporaryDirectory() as td:
            outfile = os.path.join(td, "nope.txt")
            policy = Policy(
                fs_readable=[*_PYTHON_READABLE, td],
                fs_writable=[],
            )
            result = Sandbox(policy).run(
                ["python3", "-c", f"open('{outfile}', 'w').write('x')"]
            )
            assert not result.success

    def test_denied_path_blocks_top_level(self):
        """fs_denied paths are blocked when not under a broader rule."""
        with tempfile.TemporaryDirectory() as allowed, \
             tempfile.TemporaryDirectory() as denied:
            testfile = os.path.join(denied, "file.txt")
            with open(testfile, "w") as f:
                f.write("hidden")

            policy = Policy(
                fs_readable=[*_PYTHON_READABLE, allowed],
                fs_denied=[denied],
            )
            result = Sandbox(policy).run(
                ["python3", "-c", f"open('{testfile}').read()"]
            )
            assert not result.success


# --- seccomp syscall enforcement ---

class TestSeccompEnforcement:
    def test_default_deny_blocks_mount(self):
        """mount(2) is in the default deny list and should fail."""
        policy = Policy(fs_readable=_PYTHON_READABLE)
        result = Sandbox(policy).run(
            ["python3", "-c", """
import ctypes, os
libc = ctypes.CDLL(None)
ret = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
if ret < 0:
    print("BLOCKED", os.strerror(ctypes.get_errno()))
else:
    print("ALLOWED")
"""]
        )
        assert result.success  # python3 exits 0
        assert b"BLOCKED" in result.stdout

    def test_default_deny_blocks_ptrace(self):
        """ptrace(2) is in the default deny list."""
        policy = Policy(fs_readable=_PYTHON_READABLE)
        result = Sandbox(policy).run(
            ["python3", "-c", """
import ctypes, os, errno
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME
err = ctypes.get_errno()
print("BLOCKED" if err == errno.EPERM else f"UNEXPECTED {err}")
"""]
        )
        assert result.success
        assert b"BLOCKED" in result.stdout

    def test_allowlist_blocks_unknown_syscall(self):
        """In allowlist mode, unlisted syscalls should fail."""
        from sandlock import DEFAULT_ALLOW_SYSCALLS

        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            allow_syscalls=DEFAULT_ALLOW_SYSCALLS,
        )
        # unshare is NOT in the allowlist
        result = Sandbox(policy).run(
            ["python3", "-c", """
import ctypes, os, errno
libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWUTS = 0x04000000
ret = libc.unshare(CLONE_NEWUTS)
err = ctypes.get_errno()
print("BLOCKED" if err == errno.EPERM else f"UNEXPECTED {err}")
"""]
        )
        assert result.success
        assert b"BLOCKED" in result.stdout

    def test_clone3_threading_works(self):
        """Python threading (clone3 on modern glibc) should work in sandbox."""
        policy = Policy(fs_readable=_PYTHON_READABLE)
        result = Sandbox(policy).run(
            ["python3", "-c", """
import threading
results = []
def worker(n):
    results.append(n)
threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print(f'THREADS_OK {len(results)}')
"""]
        )
        assert result.success
        assert b"THREADS_OK 4" in result.stdout

    def test_clone3_namespace_flags_blocked(self):
        """clone3 with namespace flags should be denied."""
        policy = Policy(fs_readable=_PYTHON_READABLE)
        result = Sandbox(policy).run(
            ["python3", "-c", """
import ctypes, os, errno
libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWUSER = 0x10000000
ret = libc.unshare(CLONE_NEWUSER)
err = ctypes.get_errno()
print("BLOCKED" if err == errno.EPERM else f"UNEXPECTED {err}")
"""]
        )
        assert result.success
        assert b"BLOCKED" in result.stdout

    def test_allowlist_allows_normal_operations(self):
        """Allowlist mode should still allow basic Python operations."""
        from sandlock import DEFAULT_ALLOW_SYSCALLS

        with tempfile.TemporaryDirectory() as td:
            outfile = os.path.join(td, "out.txt")
            policy = Policy(
                fs_readable=_PYTHON_READABLE,
                fs_writable=[td],
                allow_syscalls=DEFAULT_ALLOW_SYSCALLS,
            )
            result = Sandbox(policy).run(
                ["python3", "-c", f"""
import os, json
# Exercise: file I/O, forking (subprocess), signals
with open('{outfile}', 'w') as f:
    f.write(json.dumps({{'pid': os.getpid()}}))
print('ok')
"""]
            )
            assert result.success
            assert b"ok" in result.stdout
            assert os.path.exists(outfile)


# --- Network enforcement ---

@pytest.mark.skipif(
    landlock_abi_version() < 1,
    reason="Landlock not available (needed for notif supervisor)",
)
class TestNetworkEnforcement:
    def test_net_allow_hosts_blocks_unlisted_domain(self):
        """Unlisted domains should fail to resolve."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            net_allow_hosts=["localhost"],
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import socket
try:
    socket.getaddrinfo('example.com', 80)
    print('RESOLVED')
except socket.gaierror:
    print('BLOCKED')
"""]
        )
        assert result.success
        assert b"BLOCKED" in result.stdout

    def test_net_allow_hosts_allows_listed_domain(self):
        """Listed domains should resolve."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            net_allow_hosts=["localhost"],
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import socket
try:
    socket.getaddrinfo('localhost', 80)
    print('RESOLVED')
except socket.gaierror:
    print('BLOCKED')
"""]
        )
        assert result.success
        assert b"RESOLVED" in result.stdout

    def test_net_allow_hosts_blocks_hardcoded_ip(self):
        """Even hardcoded IPs outside the allowed set should be blocked."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            net_allow_hosts=["localhost"],
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('8.8.8.8', 53))
    print('CONNECTED')
except ConnectionRefusedError:
    print('BLOCKED')
except OSError as e:
    print(f'ERROR {e}')
finally:
    s.close()
"""]
        )
        assert result.success
        assert b"BLOCKED" in result.stdout

    def test_net_allow_hosts_allows_loopback(self):
        """Loopback should always be allowed."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            net_allow_hosts=["localhost"],
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.connect(('127.0.0.1', 1))  # port 1 is unlikely open
    print('CONNECTED')
except ConnectionRefusedError:
    # ECONNREFUSED from kernel (not from sandbox) = connect was allowed
    print('ALLOWED')
except OSError as e:
    print(f'ERROR {e}')
finally:
    s.close()
"""]
        )
        assert result.success
        assert b"ALLOWED" in result.stdout

    def test_net_allow_hosts_blocks_udp_sendto(self):
        """UDP sendto to disallowed IPs should be blocked."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            net_allow_hosts=["localhost"],
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b'x', ('8.8.8.8', 53))
    print('SENT')
except ConnectionRefusedError:
    print('BLOCKED')
except OSError as e:
    print(f'ERROR {e}')
finally:
    s.close()
"""]
        )
        assert result.success
        assert b"BLOCKED" in result.stdout


# --- Landlock TCP port enforcement ---

@pytest.mark.skipif(
    landlock_abi_version() < 4,
    reason="Landlock ABI v4+ required for TCP port rules",
)
class TestLandlockNetworkPorts:
    def test_net_connect_blocks_unlisted_port(self):
        """TCP connect to an unlisted port should fail."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            net_connect=["80"],
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import socket, errno
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('127.0.0.1', 443))
    print('CONNECTED')
except OSError as e:
    if e.errno == errno.EACCES:
        print('BLOCKED')
    else:
        print(f'ERROR {e}')
finally:
    s.close()
"""]
        )
        assert result.success
        assert b"BLOCKED" in result.stdout

    def test_net_bind_blocks_unlisted_port(self):
        """TCP bind to an unlisted port should fail."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            net_bind=["8080"],
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import socket, errno
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(('127.0.0.1', 9090))
    print('BOUND')
except OSError as e:
    if e.errno == errno.EACCES:
        print('BLOCKED')
    else:
        print(f'ERROR {e}')
finally:
    s.close()
"""]
        )
        assert result.success
        assert b"BLOCKED" in result.stdout


# --- Environment variable control ---

class TestEnvControl:
    def test_clean_env_strips_custom_vars(self):
        """clean_env=True should strip non-essential variables."""
        os.environ["SANDLOCK_TEST_SECRET"] = "hunter2"
        try:
            policy = Policy(clean_env=True)
            result = Sandbox(policy).run(
                ["python3", "-c", """
import os
val = os.environ.get('SANDLOCK_TEST_SECRET')
print(f'VAR={val}')
"""]
            )
            assert result.success
            assert b"VAR=None" in result.stdout
        finally:
            del os.environ["SANDLOCK_TEST_SECRET"]

    def test_clean_env_keeps_essentials(self):
        """clean_env=True should keep PATH, HOME, TERM, etc."""
        policy = Policy(clean_env=True)
        result = Sandbox(policy).run(
            ["python3", "-c", """
import os
path = os.environ.get('PATH', '')
home = os.environ.get('HOME', '')
print(f'HAS_PATH={bool(path)}')
print(f'HAS_HOME={bool(home)}')
"""]
        )
        assert result.success
        assert b"HAS_PATH=True" in result.stdout
        assert b"HAS_HOME=True" in result.stdout

    def test_env_set_injects_variable(self):
        """env= should inject variables into the child."""
        policy = Policy(env={"SANDLOCK_GREETING": "hello"})
        result = Sandbox(policy).run(
            ["python3", "-c", """
import os
print(os.environ.get('SANDLOCK_GREETING'))
"""]
        )
        assert result.success
        assert b"hello" in result.stdout

    def test_env_set_overrides_existing(self):
        """env= should override inherited variables."""
        os.environ["SANDLOCK_TEST_OVERRIDE"] = "old"
        try:
            policy = Policy(env={"SANDLOCK_TEST_OVERRIDE": "new"})
            result = Sandbox(policy).run(
                ["python3", "-c", """
import os
print(os.environ.get('SANDLOCK_TEST_OVERRIDE'))
"""]
            )
            assert result.success
            assert b"new" in result.stdout
        finally:
            del os.environ["SANDLOCK_TEST_OVERRIDE"]

    def test_clean_env_with_env_set(self):
        """clean_env + env should start clean then add specified vars."""
        policy = Policy(clean_env=True, env={"MY_VAR": "injected"})
        result = Sandbox(policy).run(
            ["python3", "-c", """
import os
print(f'MY_VAR={os.environ.get("MY_VAR")}')
print(f'ENV_COUNT={len(os.environ)}')
"""]
        )
        assert result.success
        assert b"MY_VAR=injected" in result.stdout

    def test_default_inherits_all(self):
        """Default behavior should inherit parent env."""
        os.environ["SANDLOCK_TEST_INHERIT"] = "visible"
        try:
            policy = Policy()
            result = Sandbox(policy).run(
                ["python3", "-c", """
import os
print(os.environ.get('SANDLOCK_TEST_INHERIT'))
"""]
            )
            assert result.success
            assert b"visible" in result.stdout
        finally:
            del os.environ["SANDLOCK_TEST_INHERIT"]


# --- IPC scoping (Landlock ABI v6+) ---

@pytest.mark.skipif(
    landlock_abi_version() < 6,
    reason="Landlock ABI v6+ required for IPC scoping",
)
class TestIpcScoping:
    def test_isolate_ipc_blocks_abstract_unix_socket(self):
        """Abstract UNIX socket connect to a host-domain socket should fail."""
        import socket as _socket

        # Create an abstract UNIX socket server in the parent (host domain)
        server = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        addr = "\0sandlock-test-ipc-" + str(os.getpid())
        server.bind(addr)
        server.listen(1)

        try:
            policy = Policy(
                fs_readable=_PYTHON_READABLE,
                isolate_ipc=True,
            )
            result = Sandbox(policy).run(
                ["python3", "-c", f"""
import socket, errno
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('\\0{addr[1:]}')
    print('CONNECTED')
except OSError as e:
    if e.errno == errno.EPERM:
        print('BLOCKED')
    else:
        print(f'ERROR {{e}}')
finally:
    s.close()
"""]
            )
            assert result.success
            assert b"BLOCKED" in result.stdout
        finally:
            server.close()

    def test_isolate_ipc_allows_within_sandbox(self):
        """Abstract UNIX sockets within the sandbox domain should still work."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            isolate_ipc=True,
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import socket, os
addr = '\\0sandlock-test-internal-' + str(os.getpid())
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(addr)
server.listen(1)
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    client.connect(addr)
    print('CONNECTED')
except OSError as e:
    print(f'ERROR {e}')
finally:
    client.close()
    server.close()
"""]
        )
        assert result.success
        assert b"CONNECTED" in result.stdout

    def test_isolate_signals_blocks_kill_to_parent(self):
        """Sandboxed process should not be able to signal the parent."""
        parent_pid = os.getpid()
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            isolate_signals=True,
        )
        result = Sandbox(policy).run(
            ["python3", "-c", f"""
import os, signal, errno
try:
    os.kill({parent_pid}, 0)  # signal 0 = check permission
    print('ALLOWED')
except PermissionError:
    print('BLOCKED')
except OSError as e:
    if e.errno == errno.EPERM:
        print('BLOCKED')
    else:
        print(f'ERROR {{e}}')
"""]
        )
        assert result.success
        assert b"BLOCKED" in result.stdout

    def test_isolate_signals_allows_self_signal(self):
        """Sandboxed process should be able to signal itself."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            isolate_signals=True,
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import os, signal
try:
    os.kill(os.getpid(), 0)  # signal 0 to self
    print('ALLOWED')
except OSError as e:
    print(f'ERROR {e}')
"""]
        )
        assert result.success
        assert b"ALLOWED" in result.stdout

    def test_without_isolate_ipc_allows_abstract_socket(self):
        """Without isolate_ipc, abstract UNIX sockets to host should work."""
        import socket as _socket

        server = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        addr = "\0sandlock-test-noipc-" + str(os.getpid())
        server.bind(addr)
        server.listen(1)

        try:
            policy = Policy(
                fs_readable=_PYTHON_READABLE,
                isolate_ipc=False,
            )
            result = Sandbox(policy).run(
                ["python3", "-c", f"""
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('\\0{addr[1:]}')
    print('CONNECTED')
except OSError as e:
    print(f'ERROR {{e}}')
finally:
    s.close()
"""]
            )
            assert result.success
            assert b"CONNECTED" in result.stdout
        finally:
            server.close()


# --- /proc pid isolation ---

@pytest.mark.skipif(
    landlock_abi_version() < 1,
    reason="Landlock not available",
)
class TestProcIsolation:
    @pytest.mark.skip(reason="pid isolation via pgid scan needs investigation")
    def test_proc_auto_isolation_blocks_foreign_pid(self):
        """-r /proc auto-enables pid isolation; foreign PIDs are hidden."""
        from sandlock._notif_policy import NotifPolicy, default_proc_rules

        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            notif_policy=NotifPolicy(
                rules=default_proc_rules(),
                isolate_pids=True,
            ),
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import os
# PID 1 (init) should be blocked
try:
    open('/proc/1/comm').read()
    print('VISIBLE')
except (PermissionError, FileNotFoundError, OSError):
    print('HIDDEN')
"""]
        )
        assert result.success
        assert b"HIDDEN" in result.stdout

    def test_getdents_hides_foreign_pids(self):
        """readdir(/proc) should only show sandbox PIDs when isolate_pids=True."""
        from sandlock._notif_policy import NotifPolicy, default_proc_rules

        policy = Policy(
            fs_readable=_PYTHON_READABLE,
            notif_policy=NotifPolicy(
                rules=default_proc_rules(),
                isolate_pids=True,
            ),
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import os
pids = [e for e in os.listdir('/proc') if e.isdigit()]
my_pid = str(os.getpid())
assert my_pid in pids, 'own PID not visible'
assert '1' not in pids, 'PID 1 should be hidden'
assert len(pids) < 10, f'too many PIDs visible: {len(pids)}'
print('OK')
"""]
        )
        assert result.success

    def test_always_isolates_when_proc_readable(self):
        """PID isolation is always on when /proc is in fs_readable."""
        policy = Policy(
            fs_readable=_PYTHON_READABLE,
        )
        result = Sandbox(policy).run(
            ["python3", "-c", """
import os
pids = [e for e in os.listdir('/proc') if e.isdigit()]
assert '1' not in pids, 'PID 1 should be hidden'
print('OK')
"""]
        )
        assert result.success

    def test_proc_mounts_virtualized(self):
        """/proc/mounts is virtualized to empty."""
        policy = Policy(fs_readable=_PYTHON_READABLE)
        result = Sandbox(policy).run(
            ["python3", "-c", """
with open('/proc/mounts') as f:
    data = f.read()
assert data == '', f'/proc/mounts not empty: {len(data)} bytes'
print('OK')
"""]
        )
        assert result.success, result.error

    def test_proc_self_mountinfo_virtualized(self):
        """/proc/self/mountinfo is virtualized to empty."""
        policy = Policy(fs_readable=_PYTHON_READABLE)
        result = Sandbox(policy).run(
            ["python3", "-c", """
with open('/proc/self/mountinfo') as f:
    data = f.read()
assert data == '', f'/proc/self/mountinfo not empty: {len(data)} bytes'
print('OK')
"""]
        )
        assert result.success, result.error

    def test_proc_pid_mountinfo_virtualized(self):
        """/proc/<pid>/mountinfo is virtualized to empty."""
        policy = Policy(fs_readable=_PYTHON_READABLE)
        result = Sandbox(policy).run(
            ["python3", "-c", """
import os
pid = os.getpid()
with open(f'/proc/{pid}/mountinfo') as f:
    data = f.read()
assert data == '', f'/proc/{pid}/mountinfo not empty: {len(data)} bytes'
print('OK')
"""]
        )
        assert result.success, result.error


# --- Resource limits (seccomp notif based) ---

class TestResourceLimits:
    def test_process_limit(self):
        """max_processes via seccomp notif should prevent fork bombs."""
        policy = Policy(max_processes=10)
        result = Sandbox(policy).run(
            ["python3", "-c", """
import os, time
# Fork children that stay alive (sleep), so they accumulate
pids = []
for i in range(50):
    try:
        pid = os.fork()
        if pid == 0:
            time.sleep(10)
            os._exit(0)
        pids.append(pid)
    except OSError:
        print(f'FORK_LIMITED at {i}')
        break
else:
    print('UNLIMITED')
# Clean up
import signal
for p in pids:
    try:
        os.kill(p, signal.SIGKILL)
        os.waitpid(p, 0)
    except (ProcessLookupError, ChildProcessError):
        pass
"""]
        )
        assert b"FORK_LIMITED" in result.stdout


# --- Strict mode ---

class TestStrictMode:
    def test_strict_is_default(self):
        assert Policy().strict is True

    def test_non_strict_allows_degradation(self):
        policy = Policy(strict=False)
        result = Sandbox(policy).call(lambda: "ok")
        assert result.success
        assert result.value == "ok"

    @pytest.mark.skipif(
        landlock_abi_version() >= 1,
        reason="Landlock is available — cannot test strict failure",
    )
    def test_strict_fails_when_landlock_unavailable(self):
        policy = Policy(fs_readable=["/tmp"], strict=True)
        result = Sandbox(policy).run(["echo", "hello"])
        assert not result.success


# --- COW filesystem isolation (parametrized over all backends) ---

from sandlock.policy import FsIsolation, BranchAction


def _cow_backend_available(isolation: FsIsolation) -> bool:
    """Check if a COW backend works on this system."""
    td = tempfile.mkdtemp()
    try:
        policy = Policy(
            workdir=td,
            fs_isolation=isolation,
            fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev", "/tmp"],
            fs_writable=["/tmp", td],
        )
        result = Sandbox(policy).run(["echo", "ok"])
        return result.success and result.stdout.strip() == b"ok"
    except Exception:
        return False
    finally:
        import shutil
        shutil.rmtree(td, ignore_errors=True)


# Collect available backends
_COW_BACKENDS = [FsIsolation.NONE]  # seccomp COW — always available
if _cow_backend_available(FsIsolation.OVERLAYFS):
    _COW_BACKENDS.append(FsIsolation.OVERLAYFS)
# BranchFS requires external binary — skip in CI


def _make_cow_policy(workdir, td, isolation, **kwargs):
    """Build a Policy for COW testing with a given backend."""
    return Policy(
        workdir=workdir,
        fs_isolation=isolation,
        fs_readable=[*_PYTHON_READABLE, td, "/tmp"],
        fs_writable=[td, "/tmp"],
        **kwargs,
    )


@pytest.mark.parametrize("isolation", _COW_BACKENDS,
                         ids=[i.value for i in _COW_BACKENDS])
class TestCOW:
    def test_abort_discards_new_file(self, isolation):
        """New files are discarded on abort."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")
            with open(f"{td}/project/orig.txt", "w") as f:
                f.write("original")

            policy = _make_cow_policy(
                f"{td}/project", td, isolation,
                on_exit=BranchAction.ABORT,
            )
            result = Sandbox(policy).run(
                ["python3", "-c",
                 "open('new.txt','w').write('created'); "
                 "print(open('orig.txt').read())"]
            )
            assert result.success
            assert b"original" in result.stdout
            assert not os.path.exists(f"{td}/project/new.txt")
            assert open(f"{td}/project/orig.txt").read() == "original"

    def test_commit_on_success(self, isolation):
        """Default on_exit=COMMIT merges writes back."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")

            policy = _make_cow_policy(f"{td}/project", td, isolation)
            result = Sandbox(policy).run(
                ["python3", "-c", "open('committed.txt','w').write('yes')"]
            )
            assert result.success
            assert open(f"{td}/project/committed.txt").read() == "yes"

    def test_abort_on_error(self, isolation):
        """Default on_error=ABORT discards writes on failure."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")

            policy = _make_cow_policy(f"{td}/project", td, isolation)
            result = Sandbox(policy).run(
                ["python3", "-c",
                 "open('should_vanish.txt','w').write('gone'); "
                 "raise SystemExit(1)"]
            )
            assert not result.success
            assert not os.path.exists(f"{td}/project/should_vanish.txt")

    def test_original_unmodified(self, isolation):
        """Modifying an existing file via COW doesn't change the original."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")
            with open(f"{td}/project/data.txt", "w") as f:
                f.write("before")

            policy = _make_cow_policy(
                f"{td}/project", td, isolation,
                on_exit=BranchAction.ABORT,
            )
            result = Sandbox(policy).run(
                ["python3", "-c",
                 "open('data.txt','w').write('after'); "
                 "print(open('data.txt').read())"]
            )
            assert result.success
            assert b"after" in result.stdout
            assert open(f"{td}/project/data.txt").read() == "before"

    def test_disk_quota_kills_on_overage(self, isolation):
        """max_disk enforces quota on writes."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")

            policy = _make_cow_policy(
                f"{td}/project", td, isolation,
                max_disk="10K",
            )
            result = Sandbox(policy).run(
                ["python3", "-c",
                 "import time\n"
                 "open('big.bin','wb').write(b'x'*102400)\n"
                 "time.sleep(5)\n"
                 "print('survived')"]
            )
            assert not result.success
            assert b"survived" not in result.stdout

    def test_disk_quota_allows_under_limit(self, isolation):
        """Writes under max_disk quota succeed."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")

            policy = _make_cow_policy(
                f"{td}/project", td, isolation,
                max_disk="1M",
            )
            result = Sandbox(policy).run(
                ["python3", "-c",
                 "open('small.bin','wb').write(b'x'*1024)\n"
                 "print('ok')"]
            )
            assert result.success
            assert b"ok" in result.stdout

    def test_disk_quota_only_counts_delta(self, isolation):
        """Existing files in workdir don't count toward quota."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")
            with open(f"{td}/project/existing.bin", "wb") as f:
                f.write(b"x" * 51200)

            policy = _make_cow_policy(
                f"{td}/project", td, isolation,
                max_disk="10K",
            )
            result = Sandbox(policy).run(
                ["python3", "-c",
                 "open('small.bin','wb').write(b'y'*5120)\n"
                 "size = __import__('os').path.getsize('existing.bin')\n"
                 "print(f'orig={size}')"]
            )
            assert result.success
            assert b"orig=51200" in result.stdout

    def test_cow_execve_runs_upper_binary(self, isolation):
        """execve on a binary created in COW upper layer should work."""
        import subprocess as sp

        def create_and_exec():
            with open('hello.sh', 'w') as f:
                f.write('#!/bin/sh\necho HELLO_FROM_COW\n')
            os.chmod('hello.sh', 0o755)
            return sp.check_output(['./hello.sh']).decode().strip()

        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")
            policy = _make_cow_policy(
                f"{td}/project", td, isolation,
                on_exit=BranchAction.ABORT,
            )
            result = Sandbox(policy).call(create_and_exec)
            assert result.success, f"Failed: {result.error}"
            assert result.value == "HELLO_FROM_COW"
            assert not os.path.exists(f"{td}/project/hello.sh")

    def test_cow_execve_modified_binary(self, isolation):
        """execve on a binary modified in COW upper layer runs the new version."""
        import subprocess as sp

        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")
            with open(f"{td}/project/run.sh", "w") as f:
                f.write("#!/bin/sh\necho ORIGINAL\n")
            os.chmod(f"{td}/project/run.sh", 0o755)

            def modify_and_exec():
                with open('run.sh', 'w') as f:
                    f.write('#!/bin/sh\necho MODIFIED\n')
                return sp.check_output(['./run.sh']).decode().strip()

            policy = _make_cow_policy(
                f"{td}/project", td, isolation,
                on_exit=BranchAction.ABORT,
            )
            result = Sandbox(policy).call(modify_and_exec)
            assert result.success, f"Failed: {result.error}"
            assert result.value == "MODIFIED"
            assert open(f"{td}/project/run.sh").read() == "#!/bin/sh\necho ORIGINAL\n"

    def test_cow_chown_goes_to_upper(self, isolation):
        """chown on a COW file operates on the upper copy, not the original."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")
            with open(f"{td}/project/file.txt", "w") as f:
                f.write("data")
            orig_stat = os.stat(f"{td}/project/file.txt")

            policy = _make_cow_policy(
                f"{td}/project", td, isolation,
                on_exit=BranchAction.ABORT,
            )
            result = Sandbox(policy).run(
                ["python3", "-c", """
import os
# chown to same uid/gid (always allowed, but triggers COW copy)
st = os.stat('file.txt')
os.chown('file.txt', st.st_uid, st.st_gid)
# Verify the file is still readable after chown
print('OK', open('file.txt').read())
"""]
            )
            assert result.success
            assert b"OK data" in result.stdout
            # Original unchanged after abort
            assert open(f"{td}/project/file.txt").read() == "data"

    def test_cow_utimensat_goes_to_upper(self, isolation):
        """utime on a COW file operates on the upper copy, not the original."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")
            with open(f"{td}/project/file.txt", "w") as f:
                f.write("data")
            orig_mtime = os.stat(f"{td}/project/file.txt").st_mtime

            policy = _make_cow_policy(
                f"{td}/project", td, isolation,
                on_exit=BranchAction.ABORT,
            )
            result = Sandbox(policy).run(
                ["python3", "-c", """
import os
os.utime('file.txt', (1000000, 1000000))
st = os.stat('file.txt')
print(f'MTIME {int(st.st_mtime)}')
"""]
            )
            assert result.success
            assert b"MTIME 1000000" in result.stdout
            # Original mtime unchanged after abort
            assert os.stat(f"{td}/project/file.txt").st_mtime == orig_mtime

    def test_cow_utimensat_committed(self, isolation):
        """utime changes are committed on success."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(f"{td}/project")
            with open(f"{td}/project/file.txt", "w") as f:
                f.write("data")

            policy = _make_cow_policy(f"{td}/project", td, isolation)
            result = Sandbox(policy).run(
                ["python3", "-c", """
import os
os.utime('file.txt', (2000000, 2000000))
print('OK')
"""]
            )
            assert result.success
            assert b"OK" in result.stdout
            # After commit, mtime should be updated
            assert int(os.stat(f"{td}/project/file.txt").st_mtime) == 2000000


# --- Deterministic time ---

class TestDeterministicTime:
    def test_time_start_shifts_clock_in_call(self):
        """Sandbox.call with time_start sees shifted time (vDSO patched)."""
        def check_year():
            import time, datetime
            t = time.time()
            return datetime.datetime.fromtimestamp(
                t, tz=datetime.timezone.utc).year

        policy = Policy(time_start="2000-01-01T00:00:00Z")
        result = Sandbox(policy).call(check_year)
        assert result.success, f"Failed: {result.error}"
        assert result.value == 2000

    def test_time_start_accepts_unix_timestamp(self):
        """time_start accepts a numeric Unix timestamp."""
        def check_year():
            import time, datetime
            t = time.time()
            return datetime.datetime.fromtimestamp(
                t, tz=datetime.timezone.utc).year

        # 946684800 = 2000-01-01T00:00:00Z
        policy = Policy(time_start=946684800)
        result = Sandbox(policy).call(check_year)
        assert result.success
        assert result.value == 2000

    def test_time_start_monotonic_advances(self):
        """Time advances at real speed from the start point."""
        def check_elapsed():
            import time
            t1 = time.time()
            time.sleep(0.1)
            t2 = time.time()
            return t2 - t1

        policy = Policy(time_start="2000-01-01T00:00:00Z")
        result = Sandbox(policy).call(check_elapsed)
        assert result.success
        # Should have elapsed ~0.1 seconds
        assert 0.05 < result.value < 0.5

    def test_time_start_shifts_clock_in_run(self):
        """Sandbox.run with time_start sees shifted time (vDSO patched remotely)."""
        policy = Policy(
            time_start="2000-01-01T00:00:00Z",
            fs_readable=_PYTHON_READABLE,
        )
        result = Sandbox(policy).run(
            ["python3", "-c",
             "import time,datetime;"
             "print(datetime.datetime.fromtimestamp("
             "time.time(),tz=datetime.timezone.utc).year)"]
        )
        assert result.success, f"Failed: {result.stderr}"
        assert b"2000" in result.stdout

    def test_time_start_none_is_real_time(self):
        """Without time_start, time is real."""
        def check_year():
            import time, datetime
            t = time.time()
            return datetime.datetime.fromtimestamp(
                t, tz=datetime.timezone.utc).year

        result = Sandbox(Policy()).call(check_year)
        assert result.success
        assert result.value >= 2026


# --- Deterministic memory layout (ASLR) ---

class TestNoRandomizeMemory:
    def test_no_randomize_memory_deterministic_addresses(self):
        """no_randomize_memory produces identical mmap addresses across runs."""
        policy = Policy(no_randomize_memory=True)
        cmd = ["python3", "-c",
               "import ctypes; print(ctypes.addressof(ctypes.c_int()))"]
        r1 = Sandbox(policy).run(cmd)
        r2 = Sandbox(policy).run(cmd)
        assert r1.success and r2.success
        assert r1.stdout.strip() == r2.stdout.strip()

    def test_no_randomize_memory_call(self):
        """no_randomize_memory works with Sandbox.call."""
        def get_addr():
            import ctypes
            return ctypes.addressof(ctypes.c_int())

        policy = Policy(no_randomize_memory=True)
        r1 = Sandbox(policy).call(get_addr)
        r2 = Sandbox(policy).call(get_addr)
        assert r1.success and r2.success
        assert r1.value == r2.value

    def test_default_has_randomized_addresses(self):
        """Without no_randomize_memory, ASLR is active (addresses vary)."""
        policy = Policy()
        cmd = ["python3", "-c",
               "import ctypes; print(ctypes.addressof(ctypes.c_int()))"]
        results = [Sandbox(policy).run(cmd) for _ in range(5)]
        addrs = {r.stdout.strip() for r in results if r.success}
        # With ASLR, at least some runs should produce different addresses
        assert len(addrs) > 1, "ASLR seems inactive — all addresses identical"


# --- Deterministic randomness ---

class TestDeterministicRandom:
    def test_getrandom_deterministic(self):
        """Same random_seed produces same os.urandom() output."""
        policy = Policy(random_seed=42)
        r1 = Sandbox(policy).run(
            ["python3", "-c", "import os; print(os.urandom(16).hex())"]
        )
        r2 = Sandbox(policy).run(
            ["python3", "-c", "import os; print(os.urandom(16).hex())"]
        )
        assert r1.success and r2.success
        assert r1.stdout == r2.stdout

    def test_different_seeds_differ(self):
        """Different seeds produce different output."""
        r1 = Sandbox(Policy(random_seed=42)).run(
            ["python3", "-c", "import os; print(os.urandom(16).hex())"]
        )
        r2 = Sandbox(Policy(random_seed=99)).run(
            ["python3", "-c", "import os; print(os.urandom(16).hex())"]
        )
        assert r1.success and r2.success
        assert r1.stdout != r2.stdout

    def test_no_seed_is_nondeterministic(self):
        """Without random_seed, os.urandom() is real randomness."""
        r1 = Sandbox(Policy()).run(
            ["python3", "-c", "import os; print(os.urandom(16).hex())"]
        )
        r2 = Sandbox(Policy()).run(
            ["python3", "-c", "import os; print(os.urandom(16).hex())"]
        )
        assert r1.success and r2.success
        assert r1.stdout != r2.stdout

    def test_dev_urandom_deterministic(self):
        """/dev/urandom reads are deterministic with same seed."""
        policy = Policy(random_seed=42)
        r1 = Sandbox(policy).run(
            ["python3", "-c",
             "print(open('/dev/urandom','rb').read(16).hex())"]
        )
        r2 = Sandbox(policy).run(
            ["python3", "-c",
             "print(open('/dev/urandom','rb').read(16).hex())"]
        )
        assert r1.success and r2.success
        assert r1.stdout == r2.stdout

    def test_dev_urandom_multiple_reads(self):
        """/dev/urandom supports multiple reads (pipe-backed, no EOF)."""
        policy = Policy(random_seed=42)
        result = Sandbox(policy).run(
            ["python3", "-c",
             "f=open('/dev/urandom','rb')\n"
             "a=f.read(8).hex()\n"
             "b=f.read(8).hex()\n"
             "f.close()\n"
             "print(f'{a} {b}')"]
        )
        assert result.success
        parts = result.stdout.decode().strip().split()
        assert len(parts) == 2
        assert parts[0] != parts[1]  # sequential reads differ

    def test_getrandom_and_dev_urandom_independent(self):
        """getrandom() and /dev/urandom use separate PRNG streams."""
        policy = Policy(random_seed=42)
        result = Sandbox(policy).run(
            ["python3", "-c",
             "import os\n"
             "a=os.urandom(8).hex()\n"
             "b=open('/dev/urandom','rb').read(8).hex()\n"
             "print(f'{a} {b}')"]
        )
        assert result.success
        parts = result.stdout.decode().strip().split()
        assert len(parts) == 2
        assert parts[0] != parts[1]  # different streams

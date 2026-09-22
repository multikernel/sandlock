use sandlock_core::sandbox::ByteSize;
use sandlock_core::{Sandbox};

/// Test that num_cpus virtualizes both /proc/cpuinfo and sched_getaffinity.
#[tokio::test]
async fn test_num_cpus_virtualization() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(2)
        .build()
        .unwrap();

    // Verify /proc/cpuinfo shows 2 processors.
    let result = policy.clone().run(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"]).await.unwrap();
    assert!(result.success(), "grep /proc/cpuinfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2", "/proc/cpuinfo should show 2 processors, got: {:?}", stdout.trim());

    // Verify nproc (sched_getaffinity) also reports 2.
    let result = policy.clone().run(&["nproc"]).await.unwrap();
    assert!(result.success(), "nproc should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "2", "nproc should report 2 CPUs, got: {:?}", stdout.trim());
}

/// Test that max_memory virtualizes /proc/meminfo.
#[tokio::test]
async fn test_meminfo_virtualization() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .max_memory(ByteSize::mib(256))
        .build()
        .unwrap();

    // Read meminfo — should show virtualized values
    let result = policy.clone().run(&["cat", "/proc/meminfo"]).await.unwrap();
    assert!(result.success(), "cat /proc/meminfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // 256 MiB = 262144 kB
    assert!(
        stdout.contains("MemTotal:       262144 kB"),
        "Expected MemTotal of 262144 kB (256 MiB), got: {:?}", stdout
    );
}

/// Test that sensitive /proc paths are blocked.
#[tokio::test]
async fn test_sensitive_proc_blocked() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(1) // activate proc virtualization
        .build()
        .unwrap();

    // /proc/kcore should be denied
    let result = policy.clone().run(&["cat", "/proc/kcore"]).await.unwrap();
    assert!(!result.success(), "/proc/kcore should be denied");
}

/// The sensitive-path deny used to do a literal `path == "/proc/kcore"`
/// (and `starts_with("/proc/kcore/")`) match, which any non-canonical or
/// dirfd-relative spelling sidestepped. Exercise each known bypass shape
/// and assert the deny still fires.
#[tokio::test]
async fn test_sensitive_proc_resists_bypasses() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(1)
        .build()
        .unwrap();

    // EACCES (errno 13) is what the handler returns for sensitive paths.
    // Each branch prints OK if the open was denied, FAIL otherwise.
    let script = concat!(
        "import os, errno\n",
        "results = []\n",
        "def must_deny(label, fn):\n",
        "  try:\n",
        "    fd = fn()\n",
        "    os.close(fd)\n",
        "    results.append(f'{label}:LEAKED')\n",
        "  except OSError as e:\n",
        "    results.append(f'{label}:DENIED' if e.errno == errno.EACCES else f'{label}:errno={e.errno}')\n",
        // 1. dirfd-relative: open(/proc), then open 'kcore' relative to it
        "procfd = os.open('/proc', os.O_DIRECTORY | os.O_RDONLY)\n",
        "must_deny('dirfd', lambda: os.open('kcore', os.O_RDONLY, dir_fd=procfd))\n",
        "os.close(procfd)\n",
        // 2. non-canonical absolutes
        "must_deny('dotdot', lambda: os.open('/proc/../proc/kcore', os.O_RDONLY))\n",
        "must_deny('curdir', lambda: os.open('/proc/./kcore', os.O_RDONLY))\n",
        "must_deny('slash2', lambda: os.open('//proc/kcore', os.O_RDONLY))\n",
        "print('|'.join(results))\n",
    );

    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    for label in ["dirfd", "dotdot", "curdir", "slash2"] {
        let needle = format!("{label}:DENIED");
        assert!(
            stdout.contains(&needle),
            "{label}: /proc/kcore leaked via this spelling. stdout: {stdout}"
        );
    }
}

/// The /proc/cpuinfo virtualization used to do a literal
/// `path == "/proc/cpuinfo"` match, so non-canonical and dirfd-relative
/// spellings fell through to the host's real cpuinfo and leaked the host's
/// real CPU count.
#[tokio::test]
async fn test_proc_virt_resists_bypasses() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .num_cpus(2)
        .build()
        .unwrap();

    // Every spelling must see exactly 2 `^processor` lines, matching the
    // synthetic cpuinfo. A leak to the host file would show this host's
    // real CPU count (almost certainly != 2).
    let script = concat!(
        "import os\n",
        "results = {}\n",
        "procfd = os.open('/proc', os.O_DIRECTORY | os.O_RDONLY)\n",
        "fd = os.open('cpuinfo', os.O_RDONLY, dir_fd=procfd)\n",
        "results['dirfd']  = os.read(fd, 4096).decode().count('processor\\t')\n",
        "os.close(fd); os.close(procfd)\n",
        "results['dotdot'] = open('/proc/../proc/cpuinfo').read().count('processor\\t')\n",
        "results['curdir'] = open('/proc/./cpuinfo').read().count('processor\\t')\n",
        "results['slash2'] = open('//proc/cpuinfo').read().count('processor\\t')\n",
        "print(results)\n",
    );

    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    for label in ["dirfd", "dotdot", "curdir", "slash2"] {
        let needle = format!("'{label}': 2");
        assert!(
            stdout.contains(&needle),
            "{label}: host cpuinfo leaked (expected 2 processors, virtualized). stdout: {stdout}"
        );
    }
}

/// Test basic sandbox still works without /proc virtualization.
#[tokio::test]
async fn test_no_proc_virt_still_works() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();

    let result = policy.clone().run(&["cat", "/proc/version"]).await.unwrap();
    assert!(result.success(), "Should work without proc virtualization");
}

/// Test that /proc/net/tcp is filtered with port_remap — only shows sandbox's own ports.
#[tokio::test]
async fn test_proc_net_tcp_filtered() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procnet-{}",
        std::process::id()
    ));

    // Pick a free port to avoid conflicts with parallel tests.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .net_allow_bind_port(port)
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(concat!(
        "import socket\n",
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
        "s.bind(('127.0.0.1', {port}))\n",
        "s.listen(1)\n",
        "with open('/proc/net/tcp') as f:\n",
        "  lines = f.readlines()\n",
        "s.close()\n",
        "ports = []\n",
        "for line in lines[1:]:\n",
        "  parts = line.split()\n",
        "  if len(parts) >= 2:\n",
        "    port_hex = parts[1].split(':')[1]\n",
        "    ports.append(int(port_hex, 16))\n",
        "open('{out}', 'w').write(str(len(ports)))\n",
    ), port = port, out = out.display());

    let result = policy.clone().run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert!(count <= 2, "/proc/net/tcp should be filtered, got {} entries", count);

    let _ = std::fs::remove_file(&out);
}

/// Test that /proc/mounts is virtualized and only shows sandbox mounts.
#[tokio::test]
async fn test_proc_mounts_virtualized() {
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().run(&["cat", "/proc/mounts"]).await.unwrap();
    assert!(result.success(), "cat /proc/mounts should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // Should contain the root entry (no chroot → rootfs)
    assert!(stdout.contains("rootfs / rootfs rw 0 0"), "Should show root mount, got: {}", stdout);
    // Should NOT leak host mounts (e.g. /home, /boot, real device paths)
    assert!(!stdout.contains("/home"), "Should not leak host /home mount");
    assert!(!stdout.contains("nvme"), "Should not leak host disk device names");
}

/// Test that /proc/self/mountinfo is virtualized.
#[tokio::test]
async fn test_proc_self_mountinfo_virtualized() {
    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .build()
        .unwrap();

    let result = policy.clone().run(&["cat", "/proc/self/mountinfo"]).await.unwrap();
    assert!(result.success(), "cat /proc/self/mountinfo should succeed");
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    // Should contain root entry in mountinfo format
    assert!(stdout.contains("/ / rw - rootfs rootfs rw"), "Should show root in mountinfo, got: {}", stdout);
    assert!(!stdout.contains("/home"), "Should not leak host /home mount in mountinfo");
}

/// Test that /proc/{ppid}/ is blocked (non-sandbox PID isolation).
#[tokio::test]
async fn test_proc_parent_pid_blocked() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procparent-{}",
        std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap();

    let script = format!(concat!(
        "import os\n",
        "ppid = os.getppid()\n",
        "results = []\n",
        "for entry in ['cmdline', 'status']:\n",
        "  try:\n",
        "    open(f'/proc/{{ppid}}/{{entry}}').read()\n",
        "    results.append('LEAKED')\n",
        "  except PermissionError:\n",
        "    results.append('BLOCKED')\n",
        "  except Exception as e:\n",
        "    results.append(f'ERR:{{e}}')\n",
        "# Verify /proc/self still works\n",
        "try:\n",
        "  open('/proc/self/status').read()\n",
        "  results.append('SELF_OK')\n",
        "except Exception:\n",
        "  results.append('SELF_FAIL')\n",
        "open('{out}', 'w').write(','.join(results))\n",
    ), out = out.display());

    let result = policy.clone().run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "script should exit 0");
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let parts: Vec<&str> = content.split(',').collect();
    assert_eq!(parts.get(0), Some(&"BLOCKED"), "/proc/ppid/cmdline should be blocked, got: {}", content);
    assert_eq!(parts.get(1), Some(&"BLOCKED"), "/proc/ppid/status should be blocked, got: {}", content);
    assert_eq!(parts.get(2), Some(&"SELF_OK"), "/proc/self/status should still work, got: {}", content);
}

/// Test that /proc/net/tcp hides host ports when sandbox has no bindings.
#[tokio::test]
async fn test_proc_net_tcp_hides_host_ports() {
    let out = std::env::temp_dir().join(format!(
        "sandlock-test-procnet-hide-{}",
        std::process::id()
    ));

    let policy = Sandbox::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .port_remap(true)
        .build()
        .unwrap();

    let script = format!(concat!(
        "with open('/proc/net/tcp') as f:\n",
        "  lines = f.readlines()\n",
        "ports = []\n",
        "for line in lines[1:]:\n",
        "  parts = line.split()\n",
        "  if len(parts) >= 2:\n",
        "    port_hex = parts[1].split(':')[1]\n",
        "    ports.append(int(port_hex, 16))\n",
        "open('{out}', 'w').write(str(len(ports)))\n",
    ), out = out.display());

    let result = policy.clone().run_interactive(&["python3", "-c", &script]).await.unwrap();
    assert!(result.success(), "exit={:?}", result.code());
    let content = std::fs::read_to_string(&out).unwrap_or_default();
    let count: usize = content.parse().unwrap_or(999);
    assert_eq!(count, 0, "/proc/net/tcp should show 0 entries when sandbox has no bindings");

    let _ = std::fs::remove_file(&out);
}

/// /proc/net is a link to self/net, and every task directory has the same
/// tree: none of those spellings may show the host's interfaces.
#[tokio::test]
async fn test_proc_net_virt_covers_per_task_spellings() {
    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .build()
        .unwrap();

    let script = concat!(
        "for p in /proc/net/dev /proc/self/net/dev /proc/thread-self/net/dev ",
        "/proc/$$/net/dev /proc/$$/task/$$/net/dev; do ",
        "grep -c : $p; done",
    );
    let result = policy.clone().run(&["sh", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    let counts: Vec<&str> = stdout.lines().collect();
    assert_eq!(counts, ["1"; 5], "only loopback should be listed under every spelling");
}

fn proc_grant() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
}

async fn run_sh(policy: &Sandbox, script: &str) -> (bool, String) {
    let result = policy.clone().run(&["sh", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    (result.success(), stdout.trim().to_string())
}

/// Every task directory carries the mount files, so with /proc readable no
/// per-task spelling may show the host's table in place of the virtual one.
#[tokio::test]
async fn test_proc_mounts_virt_covers_per_task_spellings() {
    let policy = proc_grant().build().unwrap();
    let script = concat!(
        "for p in /proc/mounts /proc/self/mounts /proc/thread-self/mounts ",
        "/proc/$$/mounts /proc/self/task/$$/mounts /proc/self/mountinfo ",
        "/proc/thread-self/mountinfo /proc/$$/mountinfo /proc/$$/task/$$/mountinfo ",
        "/proc/self/mountstats /proc/$$/mountstats; do ",
        "wc -l < $p; done",
    );
    let (_, out) = run_sh(&policy, script).await;
    let counts: Vec<&str> = out.lines().map(str::trim).collect();
    assert_eq!(counts, ["1"; 11], "only the sandbox root should be listed under every spelling");
}

/// mountstats is generated from the same --fs-mount list as /proc/mounts.
#[tokio::test]
async fn test_proc_mountstats_lists_fs_mounts() {
    let host = std::env::temp_dir();
    let policy = proc_grant()
        .fs_mount("/work", &host)
        .fs_mount_ro("/data", &host)
        .build()
        .unwrap();
    // Threads have no mountstats, and a cat that stats its operand first
    // would see that, so name the process and let the shell do the open.
    let script = "cat < /proc/mounts; echo; cat < /proc/$$/mountstats";
    let (_, out) = run_sh(&policy, script).await;
    let (mounts, mountstats) = out.split_once("\n\n").expect("both files should print");

    let mounted_on: Vec<&str> = mounts.lines().filter_map(|l| l.split(' ').nth(1)).collect();
    let stats_on: Vec<&str> = mountstats.lines().filter_map(|l| l.split(' ').nth(4)).collect();
    assert_eq!(mounted_on, ["/", "/work", "/data"], "got: {}", mounts);
    assert_eq!(stats_on, mounted_on, "mountstats should name the mounts /proc/mounts does, got: {}", mountstats);
    assert!(!out.contains(host.to_str().unwrap()), "host paths should not appear, got: {}", out);
}

/// /proc/self/cgroup names the host's slice and scope, so every spelling
/// shows the root of a cgroup namespace instead.
#[tokio::test]
async fn test_proc_cgroup_is_virtualized() {
    let policy = proc_grant().build().unwrap();
    // task/$$ exists only under the shell, so the shell does the open.
    let script = concat!(
        "for p in /proc/self/cgroup /proc/thread-self/cgroup /proc/$$/cgroup ",
        "/proc/self/task/$$/cgroup; do cat < $p; done",
    );
    let (_, out) = run_sh(&policy, script).await;
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines, ["0::/"; 4], "the host's cgroup path should not be visible");
}

fn no_proc_grant() -> sandlock_core::SandboxBuilder {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
}

/// Prints 1 when the file can be opened, 0 otherwise. No pipeline and no
/// redirect to /dev/null: a first stage that is refused exits at once, which
/// can leave the last stage waiting forever until issue #235 is fixed, and
/// /dev/null is not writable in these sandboxes.
fn openable(path: &str) -> String {
    format!("if ( : < {} ); then echo 1; else echo 0; fi", path)
}

/// Issue #218: a Landlock rule for /proc/self/maps names the first pid, so a
/// forked child was denied the entry its parent could read.
#[tokio::test]
async fn test_listed_proc_self_entry_covers_every_process() {
    let policy = no_proc_grant().fs_read("/proc/self/maps").build().unwrap();

    let (ok, out) = run_sh(&policy, "exec grep -c . /proc/self/maps").await;
    assert!(ok, "the first process should read its maps, got: {:?}", out);

    // `; true` keeps sh from exec'ing grep in place of forking it.
    let (ok, out) = run_sh(&policy, "grep -c . /proc/self/maps; true").await;
    assert!(ok);
    assert!(out.parse::<u32>().unwrap_or(0) > 0, "a forked child should read its maps, got: {:?}", out);
}

#[tokio::test]
async fn test_unlisted_proc_self_entry_is_refused() {
    let policy = no_proc_grant().fs_read("/proc/self/maps").build().unwrap();
    let script = format!("{}; {}", openable("/proc/self/status"), openable("/proc/self/maps"));
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "0\n1", "only the listed entry should be served");

    let policy = no_proc_grant().build().unwrap();
    let script = format!("{}; {}", openable("/proc/self/maps"), openable("/etc/passwd"));
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "0\n1", "nothing under /proc/self should be served without a grant");
}

/// The fd a child gets has to describe the child, not the first process.
#[tokio::test]
async fn test_own_proc_self_resolves_to_the_caller() {
    let policy = no_proc_grant().fs_read("/proc/self/stat").build().unwrap();
    let inner = r#"read -r line < /proc/self/stat; echo "${line%% *} $$""#;
    let (ok, out) = run_sh(&policy, &format!("sh -c '{}'; true", inner)).await;
    assert!(ok);
    let (from_stat, own_pid) = out.split_once(' ').unwrap_or_default();
    assert!(!own_pid.is_empty() && from_stat == own_pid, "stat should name the caller, got: {:?}", out);
}

#[tokio::test]
async fn test_own_proc_self_is_read_only() {
    let policy = no_proc_grant().fs_read("/proc/self/comm").build().unwrap();
    let script = "echo renamed > /proc/self/comm; read -r comm < /proc/self/comm; echo \"$comm\"";
    let (_, out) = run_sh(&policy, script).await;
    assert_eq!(out, "sh", "a read grant should not extend to writing");
}

/// `root`, `cwd` and `fd/N` lead out of /proc; their targets stay under the policy.
#[tokio::test]
async fn test_own_proc_self_does_not_follow_links_out() {
    let secret = std::env::temp_dir().join(format!("sandlock-test-procself-{}", std::process::id()));
    std::fs::write(&secret, "secret").unwrap();

    let policy = no_proc_grant().fs_read("/proc/self").build().unwrap();
    let script = format!("{}; {}", openable(&format!("/proc/self/root{}", secret.display())), openable("/proc/self/status"));
    let (_, out) = run_sh(&policy, &script).await;
    let _ = std::fs::remove_file(&secret);
    assert_eq!(out, "0\n1", "only the link's target should be refused");
}

/// /proc/self/net is the host's network namespace, not the task's own data.
#[tokio::test]
async fn test_own_proc_self_excludes_net() {
    let policy = no_proc_grant().fs_read("/proc/self").build().unwrap();
    let script = format!("{}; {}", openable("/proc/self/net/arp"), openable("/proc/self/status"));
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "0\n1", "a /proc/self grant should not reach the net subtree");
}

/// The supervisor may hold capabilities the task lacks, and these files show
/// more to a privileged opener.
#[tokio::test]
async fn test_own_proc_self_excludes_opener_privileged_files() {
    let policy = no_proc_grant().fs_read("/proc/self").build().unwrap();
    let script = [openable("/proc/self/pagemap"), openable("/proc/self/stack"), openable("/proc/self/status")].join("; ");
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "0\n0\n1", "pagemap and stack should not be opened on the task's behalf");
}

#[tokio::test]
async fn test_own_proc_self_honors_fs_deny() {
    let policy = no_proc_grant().fs_read("/proc/self").fs_deny("/proc/self/maps").build().unwrap();
    // The shell reads the numeric path itself: for a forked reader, $$ would
    // name its parent rather than its own directory.
    let own_numeric = "if read -r line < /proc/$$/maps; then echo 1; else echo 0; fi";
    let script = [&openable("/proc/self/maps"), own_numeric, &openable("/proc/self/status")].join("; ");
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "0\n0\n1", "the deny should hold under both spellings and nothing else");
}

/// /proc/self names the thread group, /proc/thread-self the calling thread,
/// and a grant on the former reaches the latter as it does under Landlock.
#[tokio::test]
async fn test_own_proc_self_from_a_thread() {
    let policy = no_proc_grant().fs_read("/proc/self").build().unwrap();
    let script = concat!(
        "import os, threading\n",
        "def pid_of(path):\n",
        "  return int(open(path).read().split()[0])\n",
        "def work():\n",
        "  print(pid_of('/proc/self/stat') == os.getpid(),\n",
        "        pid_of('/proc/thread-self/stat') == threading.get_native_id())\n",
        "t = threading.Thread(target=work)\n",
        "t.start()\n",
        "t.join()\n",
    );
    let result = policy.clone().run(&["python3", "-c", script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(stdout.trim(), "True True", "stderr: {}", String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default()));
}

/// With a deny active, opens the handlers pass on are resolved by the
/// supervisor, where /proc/self would be the supervisor's own directory.
#[tokio::test]
async fn test_own_proc_self_is_the_caller_with_a_deny_active() {
    let policy = proc_grant().fs_deny("/tmp/sandlock-test-no-such-file").build().unwrap();
    let (_, out) = run_sh(&policy, "cat /proc/self/comm; true").await;
    assert_eq!(out, "cat");
}

/// Without a supervisor nothing serves /proc/self, so a listed entry has to
/// remain a Landlock rule, first pid only as that is.
#[tokio::test]
async fn test_listed_proc_self_entry_survives_no_supervisor() {
    let policy = no_proc_grant().fs_read("/proc/self/maps").no_supervisor(true).build().unwrap();
    let (ok, out) = run_sh(&policy, "exec grep -c . /proc/self/maps").await;
    assert!(ok);
    assert!(out.parse::<u32>().unwrap_or(0) > 0, "got: {:?}", out);
}

/// A directory of links for the sandbox to open, removed on drop.
struct LinkDir(std::path::PathBuf);

impl LinkDir {
    fn new(tag: &str, links: &[(&str, &str)]) -> Self {
        let dir = std::env::temp_dir().join(format!("sandlock-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, target) in links {
            std::os::unix::fs::symlink(target, dir.join(name)).unwrap();
        }
        Self(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

impl Drop for LinkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// With a deny active the supervisor performs the open, and it could open what
/// the /proc handlers refuse: they only judged the string the child wrote.
#[tokio::test]
async fn test_deny_active_hides_proc_targets_behind_links() {
    let links = LinkDir::new("proclinks", &[("init", "/proc/1"), ("syms", "/proc/kallsyms"), ("passwd", "/etc/passwd")]);
    let policy = proc_grant()
        .fs_read(&links.0)
        .fs_deny("/tmp/sandlock-test-no-such-file")
        .build()
        .unwrap();
    // No pipelines here: a first stage that is refused exits at once, and
    // until issue #235 is fixed that can leave the last stage waiting forever.
    let script = [
        openable(&format!("{}/cmdline", links.path("init"))),
        openable(&links.path("syms")),
        openable(&links.path("passwd")),
    ]
    .join("; ");
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "0\n0\n1", "a link should not reach a /proc entry the direct path is refused");
}

/// Issue #246: the supervisor walks the path when a deny is active, so
/// /proc/self would name the supervisor, and /dev/stdin, a link to
/// /proc/self/fd/0, would be refused as a magic link.
#[tokio::test]
async fn test_deny_active_reads_proc_self_as_the_caller() {
    let links = LinkDir::new("selflinks", &[("self", "/proc/self"), ("thread", "/proc/thread-self")]);
    let policy = proc_grant()
        .fs_read("/dev")
        .fs_read(&links.0)
        .fs_deny("/tmp/sandlock-test-no-such-file")
        .build()
        .unwrap();
    // The pipes are made in the process itself: a shell pipeline whose first
    // stage exits at once can hang until issue #235 is fixed.
    let script = format!(
        concat!(
            "import os\n",
            "def piped(path_of, text):\n",
            "    r, w = os.pipe(); os.write(w, text); os.close(w)\n",
            "    return open(path_of(r)).read()\n",
            "print(open('{}/comm').read().strip(), open('{}/comm').read().strip())\n",
            "print(piped(lambda fd: '/proc/self/fd/%d' % fd, b'proc-fd'))\n",
            "print(piped(lambda fd: '/dev/fd/%d' % fd, b'dev-fd'))\n",
            "os.dup2(os.pipe()[0], 0)\n",
            "print('stdin', open('/dev/stdin').closed, flush=True)\n",
            "open('/dev/stdout', 'w').write('stdout\\n')\n",
        ),
        links.path("self"),
        links.path("thread"),
    );
    let result = policy.clone().run(&["python3", "-c", &script]).await.unwrap();
    let stdout = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert_eq!(
        stdout.trim(),
        "python3 python3\nproc-fd\ndev-fd\nstdin False\nstdout",
        "stderr: {}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
}

/// A grant on /proc/self has to cover the caller's entry when the supervisor
/// reaches it under its numeric name, and a deny on it has to hold there too.
#[tokio::test]
async fn test_deny_active_matches_proc_self_under_its_pid() {
    let links = LinkDir::new("selfforms", &[("self", "/proc/self")]);
    let policy = no_proc_grant()
        .fs_read("/proc/self")
        .fs_read(&links.0)
        .fs_deny("/tmp/sandlock-test-no-such-file")
        .build()
        .unwrap();
    let (_, out) = run_sh(&policy, &format!("cat {}/comm; true", links.path("self"))).await;
    assert_eq!(out, "cat", "a /proc/self grant should cover the entry behind a link");

    let policy = proc_grant().fs_deny("/proc/self/maps").build().unwrap();
    let own_numeric = "if read -r line < /proc/$$/maps; then echo 1; else echo 0; fi";
    let script = [own_numeric, &openable("/proc/self/status")].join("; ");
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "0\n1", "the deny should hold under the numeric spelling with /proc readable");
}

/// A link to a magic link stays refused: only the kernel could say whose fd
/// it means.
#[tokio::test]
async fn test_deny_active_refuses_what_it_cannot_resolve_for_the_caller() {
    let links = LinkDir::new("nslinks", &[("self", "/proc/self"), ("chain", "/proc/self/fd/0")]);
    let policy = proc_grant()
        .fs_read(&links.0)
        .fs_deny("/tmp/sandlock-test-no-such-file")
        .build()
        .unwrap();
    let script = [openable(&links.path("chain")), openable(&format!("{}/status", links.path("self")))].join("; ");
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "0\n1");
}

/// Issue #236: Landlock granted all of /proc, so a link or /proc/self/root
/// took the kernel to entries the handlers refuse by name.
#[tokio::test]
async fn test_links_into_proc_cannot_reach_hidden_entries() {
    let links = LinkDir::new("proc236", &[("init", "/proc/1"), ("syms", "/proc/kallsyms"), ("self", "/proc/self")]);
    let policy = proc_grant().fs_read(&links.0).build().unwrap();
    let script = [
        openable(&format!("{}/cmdline", links.path("init"))),
        openable(&links.path("syms")),
        openable("/proc/self/root/proc/1/cmdline"),
        openable(&format!("{}/comm", links.path("self"))),
        openable("/proc/$$/status"),
        openable("/proc/sys/kernel/pid_max"),
        "ls /proc | grep -c '^cpuinfo$'".to_string(),
    ]
    .join("; ");
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "0\n0\n0\n1\n1\n1\n1");
}

/// A /proc grant covers the net entries that have no virtual form, and the
/// supervisor shares the network namespace, so it can serve them.
#[tokio::test]
async fn test_proc_grant_serves_unvirtualized_net_entries() {
    let policy = proc_grant().build().unwrap();
    let script = [
        openable("/proc/net/unix"),
        openable("/proc/self/net/route"),
        openable("/proc/$$/net/arp"),
        "grep -c : /proc/net/dev".to_string(),
    ]
    .join("; ");
    let (_, out) = run_sh(&policy, &script).await;
    assert_eq!(out, "1\n1\n1\n1");
}

/// A link reaches the real file behind a virtual one, and the on-behalf open
/// used to hand that file out; the generated content is the only right answer.
#[tokio::test]
async fn test_links_to_virtual_files_show_the_virtual_content() {
    let links = LinkDir::new(
        "virtlinks",
        &[("cpu", "/proc/cpuinfo"), ("self", "/proc/self"), ("host", "/etc/hostname"), ("hosts", "/etc/hosts")],
    );
    let script = format!(
        concat!(
            "grep -c ^processor {cpu}; wc -l < {self}/mounts; ",
            "[ \"$(cat /etc/hostname)\" = \"$(cat {host})\" ] && echo same-hostname; ",
            "[ \"$(cat /etc/hosts)\" = \"$(cat {hosts})\" ] && echo same-hosts"
        ),
        cpu = links.path("cpu"),
        self = links.path("self"),
        host = links.path("host"),
        hosts = links.path("hosts"),
    );
    for deny_active in [false, true] {
        let mut policy = proc_grant().fs_read(&links.0).num_cpus(2);
        if deny_active {
            policy = policy.fs_deny("/tmp/sandlock-test-no-such-file");
        }
        let (_, out) = run_sh(&policy.build().unwrap(), &script).await;
        assert_eq!(out, "2\n1\nsame-hostname\nsame-hosts", "deny active: {}", deny_active);
    }
}

/// The real /etc/hostname keeps no Landlock grant: a spelling the supervisor
/// cannot resolve, such as a magic link, goes to the kernel and must not
/// reach it. The rest of /etc stays readable and listable.
#[tokio::test]
async fn test_virtualized_etc_file_has_no_grant_on_its_real_inode() {
    let Ok(real) = std::fs::read_to_string("/etc/hostname") else { return };
    let policy = proc_grant().build().unwrap();
    let script = concat!(
        "cd /etc && printf 'cwd:%s\n' \"$(cat /proc/self/cwd/hostname 2>&1)\"; ",
        "set -- /etc/pass*; echo $1; cat /etc/hostname"
    );
    let (_, out) = run_sh(&policy, script).await;
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{:?}", out);
    assert!(!lines[0].contains(real.trim()), "the real hostname leaked through a magic link: {:?}", out);
    assert_eq!(lines[1], "/etc/passwd");
    assert!(lines[2].starts_with("sandbox-"), "{:?}", out);
}

/// /proc/self/root is / for a sandbox without a chroot and cwd is where the
/// task is, so a spelling through them names the same file, virtual or hidden.
#[tokio::test]
async fn test_root_and_cwd_magic_links_name_the_virtual_file() {
    let policy = proc_grant().build().unwrap();
    let script = concat!(
        "[ \"$(cat /proc/self/root/etc/hostname)\" = \"$(cat /etc/hostname)\" ] && echo root-hostname; ",
        "grep -c : /proc/self/root/proc/net/dev; ",
        "cd /etc && [ \"$(cat /proc/self/cwd/hostname)\" = \"$(cat /etc/hostname)\" ] && echo cwd-hostname; ",
        "[ \"$(cat /proc/$$/root/etc/hosts)\" = \"$(cat /etc/hosts)\" ] && echo pid-root-hosts"
    );
    let (_, out) = run_sh(&policy, script).await;
    assert_eq!(out, "root-hostname\n1\ncwd-hostname\npid-root-hosts");
}

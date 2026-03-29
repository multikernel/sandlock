#!/usr/bin/env python3
"""Demo: prove COW memory sharing works.

1. init() allocates a large buffer and stamps it with a unique ID
2. work() reads the buffer — proves data survived fork (not re-init'd)
3. Parent checks /proc/pid/smaps — proves pages are physically shared

Usage:
    python3 examples/fork.py
"""

import os
import sys
import time
import ctypes
from sandlock import Sandbox, Policy

# Unique token set by init(), never re-set
_TOKEN = None
_BUF_ADDR = None
_BUF_SIZE = 10 * 1024 * 1024  # 10 MB


def init():
    """Allocate 10 MB, fill with a unique token. Runs once."""
    global _TOKEN, _BUF_ADDR

    _TOKEN = os.getpid()  # unique per-process — proves it's from init's PID

    # Allocate 10 MB via mmap (anonymous, private)
    libc = ctypes.CDLL("libc.so.6")
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, ctypes.c_long,
    ]
    addr = libc.mmap(None, _BUF_SIZE, 0x3, 0x22, -1, 0)  # RW, PRIVATE|ANON
    _BUF_ADDR = addr

    # Fill with pattern: each 4KB page starts with the token
    buf = (ctypes.c_char * _BUF_SIZE).from_address(addr)
    import struct
    for offset in range(0, _BUF_SIZE, 4096):
        struct.pack_into("<Q", buf, offset, _TOKEN)


def work(clone_id):
    """Read the buffer. Proves COW — data is from init()'s process."""
    import struct

    my_pid = os.getpid()

    # Read token from first page
    buf = (ctypes.c_char * 8).from_address(_BUF_ADDR)
    token = struct.unpack_from("<Q", buf, 0)[0]

    # Verify ALL pages have the same token (no corruption)
    full_buf = (ctypes.c_char * _BUF_SIZE).from_address(_BUF_ADDR)
    all_match = True
    for offset in range(0, _BUF_SIZE, 4096):
        page_token = struct.unpack_from("<Q", full_buf, offset)[0]
        if page_token != token:
            all_match = False
            break

    with open(f"/tmp/sandlock_cow_{clone_id}", "w") as f:
        f.write(f"clone_pid={my_pid} init_pid={token} "
                f"pages_ok={all_match} buf_addr=0x{_BUF_ADDR:x}")


def get_shared_pages(pid):
    """Read Shared_Clean + Shared_Dirty from /proc/pid/smaps."""
    shared = 0
    private = 0
    try:
        with open(f"/proc/{pid}/smaps") as f:
            for line in f:
                if line.startswith("Shared_Clean:") or line.startswith("Shared_Dirty:"):
                    shared += int(line.split()[1])
                elif line.startswith("Private_Clean:") or line.startswith("Private_Dirty:"):
                    private += int(line.split()[1])
    except OSError:
        pass
    return shared, private


def main():
    policy = Policy(
        fs_writable=["/tmp"],
        fs_readable=[sys.prefix, "/usr", "/lib", "/etc", "/proc", "/dev"],
    )

    print("=== COW Clone Proof ===\n", flush=True)

    with Sandbox(policy, init_fn=init, work_fn=work) as sb:
        # Fork 3 clones
        fork_result = sb.fork(3)

        # Give clones time to run
        time.sleep(1)

        # Check shared pages for each clone
        for i, pid in enumerate(fork_result.pids):
            if pid:
                shared_kb, private_kb = get_shared_pages(pid)
                print(f"  Clone {i} (PID {pid}): "
                      f"shared={shared_kb} KB, private={private_kb} KB",
                      flush=True)

    # Read results
    print(flush=True)
    for seed in range(3):
        f = f"/tmp/sandlock_cow_{seed}"
        if os.path.exists(f):
            print(f"  Clone {seed}: {open(f).read()}", flush=True)
            os.unlink(f)
        else:
            print(f"  Clone {seed}: no output", flush=True)

    print(f"\n  10 MB buffer allocated once in init().", flush=True)
    print(f"  If shared > 0 KB, pages are physically shared (COW).", flush=True)
    print(f"  If init_pid matches across clones, data survived fork.", flush=True)
    print("\nDone.", flush=True)


if __name__ == "__main__":
    main()

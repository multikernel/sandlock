# SPDX-License-Identifier: Apache-2.0
"""vDSO patching — force clock syscalls through the kernel.

The vDSO (virtual dynamic shared object) lets userspace call
clock_gettime/gettimeofday without a real syscall, bypassing seccomp.
This module patches the vDSO function code to do real syscalls instead,
so seccomp can intercept them for time virtualization.

For Sandbox.call (no exec): patches in-process via mprotect + write.
For Sandbox.run (after exec): patches via /proc/pid/mem with retries,
since writes only take effect when the child is not in seccomp-stop.
"""

from __future__ import annotations

import ctypes
import os
import struct

# Simple stubs that just force a real syscall (no offset).
# Used for gettimeofday and when no monotonic offset is needed.
_SIMPLE_STUB_X86_64 = b"\xb8{nr}\x0f\x05\xc3"   # mov eax,<nr>; syscall; ret (8 bytes)
_SIMPLE_STUB_AARCH64 = b"\x01\x00\x00\xd4\xc0\x03\x5f\xd6"  # svc #0; ret (8 bytes)


def _clock_gettime_stub_x86_64(mono_offset_s: int = 0) -> bytes:
    """Build a clock_gettime vDSO stub for x86_64.

    If mono_offset_s == 0, returns a simple syscall stub (8 bytes).
    If mono_offset_s != 0, returns a 35-byte stub that:
      1. Does a real syscall (so seccomp can intercept REALTIME)
      2. For non-REALTIME clocks, adds mono_offset_s to tv_sec
    """
    if mono_offset_s == 0:
        return b"\xb8\xe4\x00\x00\x00\x0f\x05\xc3"  # nr=228

    # push rdi;  push rsi;  mov eax,228;  syscall;  pop rsi;  pop rdi
    # cmp edi,0;  je done;  cmp edi,5;  je done
    # movabs rcx,<offset>;  add [rsi],rcx;  done: ret
    return (
        b"\x57"                           # push rdi
        b"\x56"                           # push rsi
        b"\xb8\xe4\x00\x00\x00"           # mov eax, 228
        b"\x0f\x05"                       # syscall
        b"\x5e"                           # pop rsi
        b"\x5f"                           # pop rdi
        b"\x83\xff\x00"                   # cmp edi, 0  (CLOCK_REALTIME)
        b"\x74\x12"                       # je +18 → ret
        b"\x83\xff\x05"                   # cmp edi, 5  (CLOCK_REALTIME_COARSE)
        b"\x74\x0d"                       # je +13 → ret
        b"\x48\xb9" + struct.pack("<q", mono_offset_s) +  # movabs rcx, <offset>
        b"\x48\x01\x0e"                   # add [rsi], rcx
        b"\xc3"                           # ret
    )


def _clock_gettime_stub_aarch64(mono_offset_s: int = 0) -> bytes:
    """Build a clock_gettime vDSO stub for aarch64.

    If mono_offset_s == 0, returns a simple syscall stub (8 bytes).
    If mono_offset_s != 0, returns a stub that:
      1. Does a real syscall (svc #0)
      2. For non-REALTIME clocks, adds mono_offset_s to tv_sec
    """
    if mono_offset_s == 0:
        return _SIMPLE_STUB_AARCH64

    # On entry: x0 = clockid, x1 = timespec*
    # svc #0                 ; real syscall (x8 already has NR)
    # cmp w0, #0             ; CLOCK_REALTIME?     -- wait, x0 is return value after svc
    # Actually after svc, x0 = return value, original x0 (clockid) is lost.
    # Need to save it first.
    #
    # stp x0, x1, [sp, #-16]!  ; save clockid, timespec*
    # svc #0                    ; syscall
    # ldp x2, x1, [sp], #16    ; x2=clockid, x1=timespec*
    # cmp w2, #0                ; CLOCK_REALTIME?
    # b.eq done
    # cmp w2, #5                ; CLOCK_REALTIME_COARSE?
    # b.eq done
    # ldr x3, [x1]              ; tv_sec
    # ldr x4, offset_val        ; load offset
    # add x3, x3, x4
    # str x3, [x1]              ; store tv_sec
    # ret                       ; done:
    # offset_val: .quad <offset>

    off_bytes = struct.pack("<q", mono_offset_s)
    return (
        b"\xe0\x07\xbf\xa9"    # stp x0, x1, [sp, #-16]!
        b"\x01\x00\x00\xd4"    # svc #0
        b"\xe2\x07\xc1\xa8"    # ldp x2, x1, [sp], #16
        b"\x5f\x00\x00\x71"    # cmp w2, #0
        b"\x80\x00\x00\x54"    # b.eq +16 → ret
        b"\x5f\x14\x00\x71"    # cmp w2, #5
        b"\x60\x00\x00\x54"    # b.eq +12 → ret
        b"\x23\x00\x40\xf9"    # ldr x3, [x1]
        b"\x64\x00\x00\x58"    # ldr x4, +12 (offset_val)
        b"\x63\x00\x04\x8b"    # add x3, x3, x4
        b"\x23\x00\x00\xf9"    # str x3, [x1]
        b"\xc0\x03\x5f\xd6"    # ret
        + off_bytes            # offset_val: .quad <offset>
    )


def _build_stubs(mono_offset_s: int = 0) -> dict[bytes, bytes] | None:
    """Build stub map for the current architecture."""
    import platform
    arch = platform.machine()

    if arch == "x86_64":
        cgt = _clock_gettime_stub_x86_64(mono_offset_s)
        gtod = b"\xb8\x60\x00\x00\x00\x0f\x05\xc3"  # nr=96 simple stub
        tm = b"\xb8\xc9\x00\x00\x00\x0f\x05\xc3"     # nr=201 simple stub
        return {
            b"clock_gettime": cgt,
            b"__vdso_clock_gettime": cgt,
            b"gettimeofday": gtod,
            b"__vdso_gettimeofday": gtod,
            b"time": tm,
            b"__vdso_time": tm,
        }
    elif arch == "aarch64":
        cgt = _clock_gettime_stub_aarch64(mono_offset_s)
        # aarch64 has no time() in vDSO
        return {
            b"clock_gettime": cgt,
            b"__kernel_clock_gettime": cgt,
            b"gettimeofday": _SIMPLE_STUB_AARCH64,
            b"__kernel_gettimeofday": _SIMPLE_STUB_AARCH64,
        }
    return None

_libc = ctypes.CDLL(None, use_errno=True)


def _find_vdso(pid: int | None = None) -> tuple[int, int] | None:
    """Find the vDSO mapping address and size from /proc/[pid]/maps."""
    maps = f"/proc/{pid}/maps" if pid else "/proc/self/maps"
    try:
        with open(maps) as f:
            for line in f:
                if "[vdso]" in line:
                    addr_range = line.split()[0]
                    start, end = addr_range.split("-")
                    return int(start, 16), int(end, 16) - int(start, 16)
    except OSError:
        pass
    return None


def _parse_vdso_symbols(data: bytes) -> list[tuple[bytes, int]]:
    """Parse ELF to find exported function names and offsets in the vDSO.

    Returns list of (name, offset) for time-related functions.
    """
    if data[:4] != b"\x7fELF" or data[4] != 2:  # ELFCLASS64
        return []

    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]

    dt_symtab = 0
    dt_strtab = 0
    dt_syment = 24  # sizeof(Elf64_Sym)

    dynamic_off = 0
    dynamic_sz = 0
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, ph)[0]
        if p_type == 2:  # PT_DYNAMIC
            dynamic_off = struct.unpack_from("<Q", data, ph + 8)[0]
            dynamic_sz = struct.unpack_from("<Q", data, ph + 32)[0]
            break

    if dynamic_off == 0:
        return []

    i = 0
    while i < dynamic_sz:
        d_tag = struct.unpack_from("<q", data, dynamic_off + i)[0]
        d_val = struct.unpack_from("<Q", data, dynamic_off + i + 8)[0]
        if d_tag == 0:     break  # DT_NULL
        elif d_tag == 6:   dt_symtab = d_val   # DT_SYMTAB
        elif d_tag == 5:   dt_strtab = d_val   # DT_STRTAB
        elif d_tag == 11:  dt_syment = d_val   # DT_SYMENT
        i += 16

    if dt_symtab == 0 or dt_strtab == 0:
        return []

    # Find load bias from first PT_LOAD
    load_bias = 0
    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, ph)[0]
        if p_type == 1:  # PT_LOAD
            p_offset = struct.unpack_from("<Q", data, ph + 8)[0]
            p_vaddr = struct.unpack_from("<Q", data, ph + 16)[0]
            load_bias = p_vaddr - p_offset
            break

    symtab_off = dt_symtab - load_bias
    strtab_off = dt_strtab - load_bias

    target_names = {
        b"clock_gettime", b"__vdso_clock_gettime",
        b"__kernel_clock_gettime",
        b"gettimeofday", b"__vdso_gettimeofday",
        b"__kernel_gettimeofday",
        b"time", b"__vdso_time",
    }

    results = []
    idx = 0
    while symtab_off + idx + dt_syment <= len(data):
        sym = symtab_off + idx
        st_name = struct.unpack_from("<I", data, sym)[0]
        st_info = data[sym + 4]
        st_value = struct.unpack_from("<Q", data, sym + 8)[0]

        if st_value != 0 and (st_info & 0xf) == 2:  # STT_FUNC
            name_off = strtab_off + st_name
            end = data.find(b"\x00", name_off)
            if end >= 0:
                name = data[name_off:end]
                if name in target_names:
                    results.append((name, st_value - load_bias))

        idx += dt_syment
        if symtab_off + idx >= strtab_off:
            break

    return results


def disable_vdso_local(mono_offset_s: int = 0) -> None:
    """Patch the vDSO in the current process to force real syscalls.

    Replaces vDSO clock_gettime/gettimeofday code with stubs that
    do real syscalls. If mono_offset_s is nonzero, the clock_gettime
    stub also applies a monotonic/boottime offset inline (no namespace
    or extra seccomp interception needed).

    Call this in the sandbox child before running user code.
    Only works for Sandbox.call() (no exec). For Sandbox.run(),
    exec creates a fresh vDSO that needs separate handling.
    """
    stubs = _build_stubs(mono_offset_s)
    if stubs is None:
        return

    info = _find_vdso()
    if info is None:
        return
    vdso_addr, vdso_size = info

    buf = (ctypes.c_char * vdso_size).from_address(vdso_addr)
    data = bytes(buf)

    symbols = _parse_vdso_symbols(data)
    if not symbols:
        return

    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4
    ret = _libc.mprotect(
        ctypes.c_void_p(vdso_addr), vdso_size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    )
    if ret != 0:
        return

    for name, off in symbols:
        stub = stubs.get(name)
        if stub is not None:
            ctypes.memmove(vdso_addr + off, stub, len(stub))

    _libc.mprotect(
        ctypes.c_void_p(vdso_addr), vdso_size,
        PROT_READ | PROT_EXEC,
    )


def _get_stubs(mono_offset_s: int = 0) -> dict[bytes, bytes] | None:
    """Return the per-function stub map for the current architecture."""
    return _build_stubs(mono_offset_s)

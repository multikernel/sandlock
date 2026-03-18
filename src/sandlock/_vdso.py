# SPDX-License-Identifier: Apache-2.0
"""vDSO patching — force clock syscalls through the kernel.

The vDSO (virtual dynamic shared object) lets userspace call
clock_gettime/gettimeofday without a real syscall, bypassing seccomp.
This module patches the vDSO function code to do real syscalls instead,
so seccomp can intercept them for time virtualization.

Currently only supports in-process patching (Sandbox.call). Patching
after exec (Sandbox.run) requires a vDSO remapping solution — TBD.
"""

from __future__ import annotations

import ctypes
import struct

# x86_64: per-function stubs that do real syscalls.
# Each stub: mov eax, <nr>; syscall; ret  — 8 bytes
_STUBS_X86_64 = {
    b"clock_gettime": b"\xb8\xe4\x00\x00\x00\x0f\x05\xc3",       # nr=228
    b"__vdso_clock_gettime": b"\xb8\xe4\x00\x00\x00\x0f\x05\xc3",
    b"gettimeofday": b"\xb8\x60\x00\x00\x00\x0f\x05\xc3",        # nr=96
    b"__vdso_gettimeofday": b"\xb8\x60\x00\x00\x00\x0f\x05\xc3",
}

# aarch64: svc #0; ret  — 8 bytes
# The caller already has the syscall number in x8.
_STUBS_AARCH64 = {
    b"clock_gettime": b"\x01\x00\x00\xd4\xc0\x03\x5f\xd6",
    b"__kernel_clock_gettime": b"\x01\x00\x00\xd4\xc0\x03\x5f\xd6",
    b"gettimeofday": b"\x01\x00\x00\xd4\xc0\x03\x5f\xd6",
    b"__kernel_gettimeofday": b"\x01\x00\x00\xd4\xc0\x03\x5f\xd6",
}

_libc = ctypes.CDLL(None, use_errno=True)


def _find_vdso() -> tuple[int, int] | None:
    """Find the vDSO mapping address and size from /proc/self/maps."""
    try:
        with open("/proc/self/maps") as f:
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


def disable_vdso_local() -> None:
    """Patch the vDSO in the current process to force real syscalls.

    Replaces vDSO clock_gettime/gettimeofday code with stubs that
    do real syscalls (mov eax, NR; syscall; ret). This forces all
    time calls through the kernel where seccomp can intercept them.

    Call this in the sandbox child before running user code.
    Only works for Sandbox.call() (no exec). For Sandbox.run(),
    exec creates a fresh vDSO that needs separate handling.
    """
    import platform

    arch = platform.machine()
    if arch == "x86_64":
        stubs = _STUBS_X86_64
    elif arch == "aarch64":
        stubs = _STUBS_AARCH64
    else:
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

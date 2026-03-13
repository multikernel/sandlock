# SPDX-License-Identifier: Apache-2.0
"""ctypes bindings for mprotect(2).

Provides memory protection manipulation for enforcing read-only
invariants on parent memory regions after fork.
"""

import ctypes
import ctypes.util
import os
from dataclasses import dataclass, field

from .exceptions import MemoryProtectError

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# Protection flags for mprotect(2)
PROT_NONE = 0x0
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4


def mprotect(addr: int, size: int, prot: int) -> None:
    """Call mprotect(2) to change memory protection.

    Args:
        addr: Page-aligned start address of the region.
        size: Size of the region in bytes.
        prot: New protection flags (PROT_READ, PROT_WRITE, etc.).

    Raises:
        MemoryProtectError: If the syscall fails.
    """
    ret = _libc.mprotect(ctypes.c_void_p(addr), ctypes.c_size_t(size), ctypes.c_int(prot))
    if ret != 0:
        err = ctypes.get_errno()
        raise MemoryProtectError(
            f"mprotect(0x{addr:x}, {size}, 0x{prot:x}): {os.strerror(err)}"
        )


@dataclass
class MemoryRegion:
    """A memory region tracked for protection changes."""
    addr: int
    size: int
    original_prot: int = field(default=PROT_READ | PROT_WRITE)


def protect_regions(regions: list[MemoryRegion], prot: int = PROT_READ) -> None:
    """Apply memory protection to a list of regions."""
    for region in regions:
        mprotect(region.addr, region.size, prot)


def restore_regions(regions: list[MemoryRegion]) -> None:
    """Restore each region to its original protection."""
    for region in regions:
        mprotect(region.addr, region.size, region.original_prot)

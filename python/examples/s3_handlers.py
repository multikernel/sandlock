#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serve a read-only object store to a sandbox via seccomp-notif handlers.

Maps the /s3/<key> namespace onto an object store. Three handlers
cooperate so the sandboxed process sees /s3 paths as ordinary files:

  * openat     fetches the object body (S3 GetObject) into a memfd and
               injects it as the opened fd, so read() returns the bytes.
  * newfstatat fills a struct stat from object metadata (S3 HeadObject),
               for the older glibc stat() path.
  * statx      fills a struct statx from object metadata (HeadObject),
               for the newer glibc stat() path.

With all three, os.stat("/s3/x"), os.path.exists("/s3/x"), and
open("/s3/x").read() all work. Nothing is mounted: the /s3 namespace is
synthesized per syscall by the handlers, not by a kernel filesystem.

The backend models S3 semantics faithfully, with no AWS dependencies:

  * Flat namespace. Keys are opaque, case-sensitive strings. "docs/x" is
    a single key; no "docs/" directory exists or is required. Unlike a
    filesystem, "a/b" and "a/b/c" can both be objects at once.
  * Two operations. head(key) returns metadata only (size, last-modified);
    get(key) returns the full body. A stat does NOT download the object.
  * NoSuchKey. head/get on an absent key raise ObjectNotFound, surfaced
    to the child as ENOENT (an S3 404, not a directory).
  * Read-only. The handlers serve GET/HEAD only; writes return EROFS.

FakeS3 is an in-process implementation of that contract. A real client
(boto3, an HTTP S3 client, MinIO, etc.) would implement the same
head()/get() Backend protocol and drop in unchanged.

Run it (objects are seeded in main, so no setup is needed):

    python s3_handlers.py cat /s3/hello.txt
    python s3_handlers.py cat /s3/docs/readme.md     # nested key, no directory
    python s3_handlers.py python3 -c 'import os; print(os.stat("/s3/hello.txt"))'

Caveats (this example is deliberately minimal):

  * Directory listings (getdents64) are not served, so ls /s3 is empty.
  * open fetches the whole object body (no range reads).
  * The handlers are async (`async def handle`), so a real (network)
    backend's head/get runs on a worker thread off the supervisor loop
    rather than blocking it (CPython releases the GIL during socket I/O,
    so concurrent fetches overlap). FakeS3 is in-memory and instant, so
    being async is a no-op here but is what makes a real backend viable.
  * _pack_stat uses the x86_64 struct stat layout. statx is
    architecture-independent by design, so _pack_statx is portable.
"""

import errno
import os
import struct
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from sandlock import Sandbox, Handler, NotifAction, HandlerCtx, ExceptionPolicy

PREFIX = "/s3/"
O_ACCMODE = 0o3              # access-mode bits of openat flags
S_IFREG = 0o100000          # regular-file bit for st_mode
FILE_MODE = S_IFREG | 0o444  # regular file, read-only


# --------------------------------------------------------------------------
# Backend: the S3 object contract (HeadObject / GetObject)
# --------------------------------------------------------------------------
class ObjectNotFound(Exception):
    """S3 NoSuchKey: the key has no object. Surfaced to the child as ENOENT."""


@dataclass(frozen=True)
class ObjectMeta:
    """Metadata returned by HeadObject."""
    size: int
    last_modified: int  # epoch seconds (S3 LastModified)


class Backend(Protocol):
    def head(self, key: str) -> ObjectMeta:
        """S3 HeadObject: metadata only, no body. Raise ObjectNotFound."""
        ...

    def get(self, key: str) -> bytes:
        """S3 GetObject: the full object body. Raise ObjectNotFound."""
        ...


class FakeS3:
    """In-process object store with S3 semantics.

    A flat, case-sensitive key -> bytes namespace. Keys are opaque: a "/"
    is just a character, so "docs/readme.md" is one key with no directory
    behind it, and a key and a longer key sharing its prefix can coexist.
    head/get raise ObjectNotFound (S3 NoSuchKey) for any absent key.
    """

    def __init__(self, objects: dict[str, bytes] | None = None):
        now = int(time.time())
        # key -> (body, last_modified)
        self._obj: dict[str, tuple[bytes, int]] = {
            k: (bytes(v), now) for k, v in (objects or {}).items()
        }

    def put(self, key: str, body: bytes, last_modified: int | None = None) -> None:
        when = int(last_modified if last_modified is not None else time.time())
        self._obj[key] = (bytes(body), when)

    def head(self, key: str) -> ObjectMeta:
        try:
            body, when = self._obj[key]
        except KeyError:
            raise ObjectNotFound(key)
        return ObjectMeta(size=len(body), last_modified=when)

    def get(self, key: str) -> bytes:
        try:
            return self._obj[key][0]
        except KeyError:
            raise ObjectNotFound(key)

    @classmethod
    def from_dir(cls, root: str) -> "FakeS3":
        """Seed objects from a directory tree. Each file becomes an object
        keyed by its path relative to root, with POSIX '/' separators (the
        flat S3 key, not a nested directory). The directory layout is only
        a loader; lookups afterward use flat S3 key semantics."""
        store = cls()
        root = os.path.realpath(root)
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                full = os.path.join(dirpath, name)
                key = os.path.relpath(full, root).replace(os.sep, "/")
                with open(full, "rb") as f:
                    store.put(key, f.read(), int(os.stat(full).st_mtime))
        return store


# --------------------------------------------------------------------------
# Namespace: shared backend + body cache, used by every handler
# --------------------------------------------------------------------------
class Namespace:
    """The /s3 namespace: a backend plus a body cache, shared by handlers.

    head() goes straight to the backend (HeadObject is cheap). get()
    caches the body so repeated opens of one key hit the backend once;
    this matters for a remote backend, not for FakeS3.
    """

    def __init__(self, backend: Backend):
        self._backend = backend
        self._lock = threading.Lock()
        self._body_cache: dict[str, bytes] = {}

    @staticmethod
    def key_for(path: str | None) -> str | None:
        """Return the object key for a /s3 path, or None to pass through.

        Strips the prefix only; the remainder is the literal S3 key
        (slashes kept, no normalization), matching S3's opaque keys.
        """
        if path is None or not path.startswith(PREFIX):
            return None
        return path[len(PREFIX):]

    # head()/get() are async: the handlers `await` them, which is what runs
    # the handler off the supervisor loop. FakeS3's backend is synchronous
    # and instant, so we call it directly; a real client (boto3's async
    # variant, an aiohttp S3 client) would `await` its network call here.
    async def head(self, key: str) -> ObjectMeta:
        return self._backend.head(key)

    async def get(self, key: str) -> bytes:
        with self._lock:
            if key in self._body_cache:
                return self._body_cache[key]
        data = self._backend.get(key)
        with self._lock:
            self._body_cache[key] = data
        return data


def _errno_for(exc: BaseException) -> int:
    return errno.ENOENT if isinstance(exc, ObjectNotFound) else errno.EIO


# --------------------------------------------------------------------------
# stat / statx buffer packing
# --------------------------------------------------------------------------
def _pack_stat(meta: ObjectMeta) -> bytes:
    """Build a struct stat (x86_64 layout, 144 bytes) for a regular file."""
    buf = bytearray(144)
    struct.pack_into("<Q", buf, 0, 1)                 # st_dev (nonzero)
    struct.pack_into("<Q", buf, 8, 1)                 # st_ino
    struct.pack_into("<Q", buf, 16, 1)                # st_nlink
    struct.pack_into("<I", buf, 24, FILE_MODE)        # st_mode
    struct.pack_into("<I", buf, 28, os.getuid())      # st_uid
    struct.pack_into("<I", buf, 32, os.getgid())      # st_gid
    struct.pack_into("<q", buf, 48, meta.size)        # st_size
    struct.pack_into("<q", buf, 56, 4096)             # st_blksize
    struct.pack_into("<q", buf, 64, (meta.size + 511) // 512)  # st_blocks
    struct.pack_into("<q", buf, 72, meta.last_modified)   # st_atime sec
    struct.pack_into("<q", buf, 88, meta.last_modified)   # st_mtime sec
    struct.pack_into("<q", buf, 104, meta.last_modified)  # st_ctime sec
    return bytes(buf)


# statx field mask bits (uapi/linux/stat.h); set the ones we populate.
_STATX_TYPE = 0x0001
_STATX_MODE = 0x0002
_STATX_NLINK = 0x0004
_STATX_UID = 0x0008
_STATX_GID = 0x0010
_STATX_ATIME = 0x0020
_STATX_MTIME = 0x0040
_STATX_CTIME = 0x0080
_STATX_INO = 0x0100
_STATX_SIZE = 0x0200
_STATX_BLOCKS = 0x0400
_STATX_BTIME = 0x0800
_STATX_FILLED = (
    _STATX_TYPE | _STATX_MODE | _STATX_NLINK | _STATX_UID | _STATX_GID
    | _STATX_ATIME | _STATX_MTIME | _STATX_CTIME | _STATX_INO
    | _STATX_SIZE | _STATX_BLOCKS | _STATX_BTIME
)


def _pack_statx(meta: ObjectMeta) -> bytes:
    """Build a struct statx (256 bytes, architecture-independent)."""
    buf = bytearray(256)
    struct.pack_into("<I", buf, 0, _STATX_FILLED)     # stx_mask
    struct.pack_into("<I", buf, 4, 4096)              # stx_blksize
    struct.pack_into("<I", buf, 16, 1)               # stx_nlink
    struct.pack_into("<I", buf, 20, os.getuid())     # stx_uid
    struct.pack_into("<I", buf, 24, os.getgid())     # stx_gid
    struct.pack_into("<H", buf, 28, FILE_MODE)       # stx_mode
    struct.pack_into("<Q", buf, 32, 1)               # stx_ino
    struct.pack_into("<Q", buf, 40, meta.size)       # stx_size
    struct.pack_into("<Q", buf, 48, (meta.size + 511) // 512)  # stx_blocks
    # statx_timestamp is { s64 tv_sec; u32 tv_nsec; s32 __reserved; }.
    struct.pack_into("<q", buf, 64, meta.last_modified)   # stx_atime.tv_sec
    struct.pack_into("<q", buf, 80, meta.last_modified)   # stx_btime.tv_sec
    struct.pack_into("<q", buf, 96, meta.last_modified)   # stx_ctime.tv_sec
    struct.pack_into("<q", buf, 112, meta.last_modified)  # stx_mtime.tv_sec
    return bytes(buf)


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------
class _NamespaceHandler(Handler):
    """Base: holds the shared Namespace. handle() maps its own errors to
    errno, so the KILL default never fires; DENY_EIO is a last-resort
    backstop.

    handle() is an `async def`, which runs it off the supervisor's
    notification loop. A real backend's head()/get() is a network
    round-trip; run inline it would block the single supervisor task (and
    hold the GIL) for its full duration, stalling every other trapped
    syscall. As an async handler it runs on a worker and `await`s the
    fetch, so the loop stays free and concurrent fetches overlap. FakeS3
    is instant so this changes nothing here, but it is what makes a real
    backend viable beyond a demo."""

    on_exception = ExceptionPolicy.DENY_EIO

    def __init__(self, ns: Namespace):
        self._ns = ns


class OpenatHandler(_NamespaceHandler):
    """openat(dirfd, pathname, flags, mode): inject a memfd of the object."""

    async def handle(self, ctx: HandlerCtx) -> NotifAction:
        key = self._ns.key_for(ctx.read_path())  # openat path arg inferred
        if key is None:
            return NotifAction.continue_()        # not ours: kernel handles it

        flags = ctx.args[2]
        if (flags & O_ACCMODE) != os.O_RDONLY:
            return NotifAction.errno(errno.EROFS)  # read-only, no writes

        try:
            data = await self._ns.get(key)         # S3 GetObject (off-loop)
        except Exception as e:
            return NotifAction.errno(_errno_for(e))

        # inject_bytes builds the (sealed, read-only) memfd, rewinds it, and
        # transfers fd ownership to the supervisor — no manual memfd dance.
        try:
            return NotifAction.inject_bytes(data, cloexec=bool(flags & os.O_CLOEXEC))
        except OSError:
            return NotifAction.errno(errno.EIO)


class NewfstatatHandler(_NamespaceHandler):
    """newfstatat(dirfd, pathname, statbuf, flags): write a struct stat."""

    async def handle(self, ctx: HandlerCtx) -> NotifAction:
        key = self._ns.key_for(ctx.read_path(arg=1))
        if key is None:
            return NotifAction.continue_()
        try:
            meta = await self._ns.head(key)        # S3 HeadObject (off-loop)
        except Exception as e:
            return NotifAction.errno(_errno_for(e))
        if not ctx.write(ctx.args[2], _pack_stat(meta)):  # args[2] = statbuf
            return NotifAction.errno(errno.EIO)
        return NotifAction.returns(0)


class StatxHandler(_NamespaceHandler):
    """statx(dirfd, pathname, flags, mask, statxbuf): write a struct statx."""

    async def handle(self, ctx: HandlerCtx) -> NotifAction:
        key = self._ns.key_for(ctx.read_path(arg=1))
        if key is None:
            return NotifAction.continue_()
        try:
            meta = await self._ns.head(key)        # S3 HeadObject (off-loop)
        except Exception as e:
            return NotifAction.errno(_errno_for(e))
        if not ctx.write(ctx.args[4], _pack_statx(meta)):  # args[4] = statxbuf
            return NotifAction.errno(errno.EIO)
        return NotifAction.returns(0)


# --------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    cmd = sys.argv[1:] or ["cat", "/s3/hello.txt"]

    # A faithful in-process S3: flat key -> bytes. Note "docs/readme.md" is
    # a single key with no "docs/" directory behind it.
    backend: Backend = FakeS3({
        "hello.txt": b"hello from the simulated object store\n",
        "docs/readme.md": b"# readme\n\nnested key, no directory needed\n",
    })
    # Or seed from a directory tree (files become flat keys):
    #   backend = FakeS3.from_dir("/tmp/store")
    # A real client implementing head()/get() drops in here unchanged.

    ns = Namespace(backend)
    sandbox = Sandbox(fs_readable=["/usr", "/lib", "/lib64", "/etc", "/bin"])
    result = sandbox.run_with_handlers(
        cmd,
        [
            ("openat", OpenatHandler(ns)),
            ("newfstatat", NewfstatatHandler(ns)),
            ("statx", StatxHandler(ns)),
        ],
        name="s3-handlers",
    )
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    sys.exit(result.exit_code)

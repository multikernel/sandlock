# SPDX-License-Identifier: Apache-2.0
"""Internal trampoline bridging the C Handler ABI to Python ``Handler``.

Not part of the public API — see ``handler.py`` for the public surface
and ``_sdk.py`` for the raw ctypes bindings.

GIL and interpreter safety
--------------------------
- ctypes' ``CFUNCTYPE`` callback wrappers acquire the GIL automatically
  (via ``PyGILState_Ensure``) before invoking the Python callback, even
  when the call originates on a thread the interpreter has never seen.
  The supervisor dispatches handler callbacks from its own worker
  threads, so this implicit acquisition is what makes the trampoline
  safe; no manual ``PyGILState_Ensure`` is needed.
- We additionally check ``Py_IsInitialized()`` before touching any
  Python state, in case the interpreter is being finalized while the
  supervisor is mid-dispatch. On false, the trampoline returns ``-1``
  (rc != 0), routing the notification through the configured exception
  policy.
- Native crashes (SIGSEGV) inside a handler are NOT recoverable; that is
  documented as caller responsibility.

Handler dispatch
----------------
Each registered ``Handler`` is stored in a process-global registry keyed
by an integer id. The ``ud`` slot handed to the C ABI is that id cast to
``c_void_p`` — never a raw ``PyObject*``. When the supervisor frees a
handler container it invokes the ``ud_drop`` callback, which removes the
registry entry.
"""

from __future__ import annotations

import ctypes
import threading
from typing import Dict

from . import _sdk
from .handler import Handler, HandlerCtx, NotifAction, _ActionKind, _MemHandle


# ``ctypes.pythonapi`` is a process-global ``PyDLL``; its function
# objects are shared with every other module in the process. Pin
# ``Py_IsInitialized``'s restype explicitly so dispatch never relies on
# the default (``c_int``) that another module could overwrite.
ctypes.pythonapi.Py_IsInitialized.restype = ctypes.c_int


# ----------------------------------------------------------------
# Handler registry
# ----------------------------------------------------------------

# Strong references to every registered Handler, keyed by integer id.
# The C ABI's ``ud`` pointer is this id; ``ud_drop`` removes the entry.
_HANDLERS: Dict[int, Handler] = {}
_REGISTRY_LOCK = threading.Lock()

# Monotonic registration counter — never reset or recycled. A fresh id
# per registration is the simplest guarantee that every concurrently
# live handler has a distinct ``ud``. Unbounded growth is not a
# concern: it is a Python int (no fixed width), and the registry is
# emptied after every run (see ``Sandbox.run_with_handlers``), so only
# the counter advances, never memory. The sole hard ceiling is the C
# ABI's ``ud`` slot — a pointer-width ``c_void_p`` (2**64 on 64-bit
# hosts) — astronomically beyond any realistic process lifetime.
_NEXT_ID = 1


def _register_handler(handler: Handler) -> int:
    """Insert ``handler`` into the registry and return its integer id."""
    global _NEXT_ID
    with _REGISTRY_LOCK:
        hid = _NEXT_ID
        _NEXT_ID += 1
        _HANDLERS[hid] = handler
        return hid


def _unregister_handler(hid: int) -> None:
    """Remove the handler with id ``hid`` from the registry, if present."""
    with _REGISTRY_LOCK:
        _HANDLERS.pop(hid, None)


# ----------------------------------------------------------------
# Trampoline + ud_drop
# ----------------------------------------------------------------

def _trampoline_impl(ud, notif_ptr, mem_ptr, out_ptr) -> int:
    """C-ABI handler callback. Returns 0 on success, -1 on any failure.

    A -1 return routes the notification through the handler's configured
    ``on_exception`` policy (the supervisor owns that decision).
    """
    # The interpreter may be finalizing while the supervisor dispatches.
    if not ctypes.pythonapi.Py_IsInitialized():
        return -1

    # ``ud`` arrives as a Python int (or None for a null pointer).
    if ud is None:
        return -1
    with _REGISTRY_LOCK:
        handler = _HANDLERS.get(int(ud))
    if handler is None:
        return -1  # registration gone — race with sandbox teardown

    notif = notif_ptr.contents
    # ``mem_ptr`` is a raw sandlock_mem_handle_t* pointing at a stack
    # local in the supervisor — valid ONLY while handle() is running.
    # Wrap it in a fresh liveness cell and invalidate that cell in the
    # finally below, so a HandlerCtx that escapes the callback fails
    # safe instead of dereferencing a dangling pointer.
    mem_cell = _MemHandle(mem_ptr)
    ctx = HandlerCtx(
        id=notif.id,
        pid=notif.pid,
        flags=notif.flags,
        syscall_nr=notif.syscall_nr,
        arch=notif.arch,
        instruction_pointer=notif.instruction_pointer,
        args=tuple(notif.args),
        _mem_handle=mem_cell,
    )

    try:
        try:
            action = handler.handle(ctx)
        except BaseException:
            # Any exception → defer to the configured on_exception policy.
            return -1

        if not isinstance(action, NotifAction):
            return -1  # contract violation: handle() must return a NotifAction

        kind = action.kind
        if kind == int(_ActionKind.CONTINUE):
            _sdk._lib.sandlock_action_set_continue(out_ptr)
        elif kind == int(_ActionKind.ERRNO):
            _sdk._lib.sandlock_action_set_errno(out_ptr, action.errno_value)
        elif kind == int(_ActionKind.RETURN_VALUE):
            _sdk._lib.sandlock_action_set_return_value(out_ptr, action.return_value)
        elif kind == int(_ActionKind.HOLD):
            _sdk._lib.sandlock_action_set_hold(out_ptr)
        elif kind == int(_ActionKind.KILL):
            _sdk._lib.sandlock_action_set_kill(out_ptr, action.sig, action.pgid)
        elif kind == int(_ActionKind.INJECT_FD_SEND):
            _sdk._lib.sandlock_action_set_inject_fd_send(
                out_ptr, action.srcfd, action.newfd_flags,
            )
        else:
            # UNSET, INJECT_FD_SEND_TRACKED (no setter), or an unknown tag.
            return -1
        return 0
    finally:
        # The mem handle is dead the instant the callback returns.
        # Runs on every exit path — exception, normal return, all of
        # it — so any HandlerCtx the handler stashed becomes inert.
        mem_cell.invalidate()


def _ud_drop_impl(ud) -> None:
    """C-ABI destructor: drop the handler's registry entry on free.

    Fires exactly once per container — including when ``ud`` is null
    (the C ABI guarantees this).
    """
    if not ctypes.pythonapi.Py_IsInitialized():
        return
    if ud is None:
        return
    _unregister_handler(int(ud))


# A single trampoline and ud_drop pair is reused across every handler
# registration — dispatch is by the ``ud`` integer-id lookup. These
# ctypes callback objects MUST stay alive for as long as the C side may
# invoke them, so they are bound at module scope (the supervisor only
# touches them between sandlock_run_with_handlers entry and return).
_TRAMPOLINE = _sdk._HANDLER_FN_TYPE(_trampoline_impl)
_UD_DROP = _sdk._UD_DROP_FN_TYPE(_ud_drop_impl)


def _make_trampoline():
    """Return the shared C-callable handler trampoline."""
    return _TRAMPOLINE


def _make_ud_drop():
    """Return the shared C-callable ud_drop destructor."""
    return _UD_DROP


# ----------------------------------------------------------------
# Child-memory accessors (back HandlerCtx.read_cstr / read / write)
# ----------------------------------------------------------------

def mem_read_cstr(mem_handle, addr: int, max_len: int) -> str | None:
    """Read a NUL-terminated string from the child at ``addr``.

    Returns the decoded string on success, or None on failure.
    """
    if mem_handle is None or max_len < 1:
        return None
    buf = (ctypes.c_uint8 * max_len)()
    out_len = ctypes.c_size_t(0)
    rc = _sdk._lib.sandlock_mem_read_cstr(
        mem_handle, addr, buf, max_len, ctypes.byref(out_len),
    )
    if rc != 0:
        return None
    return bytes(buf[:out_len.value]).decode("utf-8", errors="replace")


def mem_read(mem_handle, addr: int, length: int) -> bytes | None:
    """Read ``length`` raw bytes from the child at ``addr``.

    Returns the bytes copied on success, or None on failure. A null
    handle always fails (returns None), mirroring ``mem_write`` — a
    dead/absent context yields no child-memory access regardless of
    the requested length. A zero-length read on a live handle is the
    trivial success ``b""``.
    """
    if mem_handle is None:
        return None
    if length < 1:
        return b"" if length == 0 else None
    buf = (ctypes.c_uint8 * length)()
    out_len = ctypes.c_size_t(0)
    rc = _sdk._lib.sandlock_mem_read(
        mem_handle, addr, buf, length, ctypes.byref(out_len),
    )
    if rc != 0:
        return None
    return bytes(buf[:out_len.value])


def mem_write(mem_handle, addr: int, data: bytes) -> bool:
    """Write ``data`` into the child at ``addr``. Returns True on success."""
    if mem_handle is None:
        return False
    if len(data) == 0:
        return True
    buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    rc = _sdk._lib.sandlock_mem_write(mem_handle, addr, buf, len(data))
    return rc == 0

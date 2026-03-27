# SPDX-License-Identifier: Apache-2.0
"""Policy context for dynamic policy coroutines.

Provides ``grant()`` and ``restrict()`` methods that adjust the
notification supervisor's live policy.  ``grant()`` expands permissions
within the Landlock ceiling (reversible).  ``restrict()`` permanently
shrinks permissions (cannot be granted back).
"""

from __future__ import annotations

import dataclasses
import threading
from typing import Any, TYPE_CHECKING

from .exceptions import PolicyError

if TYPE_CHECKING:
    from ._notif import NotifSupervisor
    from ._notif_policy import NotifPolicy


# Fields on NotifPolicy that the policy coroutine can adjust.
_GRANTABLE_FIELDS = frozenset({
    "allowed_ips",
    "max_memory_bytes",
    "max_processes",
})

# Fields that can be overridden per-PID.  Must match what _dispatch()
# actually checks in _pid_policies (currently only network enforcement).
_PID_FIELDS = frozenset({
    "allowed_ips",
})


class PolicyContext:
    """Context object passed to a ``policy_fn`` coroutine.

    Provides two operations:

    - ``grant(**kw)`` — expand permissions within the Landlock ceiling.
      Reversible: a later ``grant()`` can change the value again.
    - ``restrict(**kw)`` — permanently shrink permissions.  A restricted
      field cannot be granted back.

    All mutations are thread-safe and take effect on the next
    intercepted syscall (the current syscall has already been responded
    to before the event was emitted).
    """

    def __init__(
        self,
        supervisor: NotifSupervisor,
        ceiling: NotifPolicy,
    ) -> None:
        self._supervisor = supervisor
        self._ceiling = ceiling
        self._restricted: dict[str, Any] = {}
        self._lock = threading.Lock()

    @property
    def permissions(self) -> NotifPolicy:
        """Current effective policy (read-only snapshot)."""
        return self._supervisor._policy

    @property
    def ceiling(self) -> NotifPolicy:
        """Maximum permissions (Landlock ceiling, immutable)."""
        return self._ceiling

    def grant(self, **kwargs: Any) -> None:
        """Expand permissions within the ceiling.

        Only fields in ``_GRANTABLE_FIELDS`` can be granted.  Values
        that exceed the ceiling are silently capped.  Fields that have
        been ``restrict()``-ed raise :class:`PolicyError`.
        """
        with self._lock:
            for key in kwargs:
                if key not in _GRANTABLE_FIELDS:
                    raise PolicyError(
                        f"Cannot grant non-grantable field: {key!r}"
                    )
                if key in self._restricted:
                    raise PolicyError(
                        f"Cannot grant restricted field: {key!r}"
                    )
            new_values = {}
            for key, value in kwargs.items():
                capped = self._cap_to_ceiling(key, value)
                new_values[key] = capped
            self._swap_policy(new_values)

    def restrict(self, **kwargs: Any) -> None:
        """Permanently shrink permissions.

        Restricted fields cannot be granted back.  Only fields in
        ``_GRANTABLE_FIELDS`` can be restricted.
        """
        with self._lock:
            for key in kwargs:
                if key not in _GRANTABLE_FIELDS:
                    raise PolicyError(
                        f"Cannot restrict non-grantable field: {key!r}"
                    )
            new_values = {}
            for key, value in kwargs.items():
                self._restricted[key] = value
                new_values[key] = value
            self._swap_policy(new_values)

    def restrict_pid(self, pid: int, **kwargs: Any) -> None:
        """Apply per-PID policy override (tighter than global).

        Only ``allowed_ips`` can be overridden per-PID (the supervisor
        checks per-PID overrides only in network enforcement).  Use
        ``net_allow_hosts`` as a convenience key to resolve domain names
        to IPs.
        """
        # Normalise net_allow_hosts → allowed_ips
        if "net_allow_hosts" in kwargs:
            from ._notif_policy import resolve_hosts
            _, ips = resolve_hosts(list(kwargs.pop("net_allow_hosts")))
            kwargs["allowed_ips"] = ips

        with self._lock:
            for key in kwargs:
                if key not in _PID_FIELDS:
                    raise PolicyError(
                        f"Cannot override field per-PID: {key!r} "
                        f"(supported: {sorted(_PID_FIELDS)})"
                    )
            current = self._supervisor._pid_policies.get(
                pid, self._supervisor._policy
            )
            updates = {}
            for key, value in kwargs.items():
                if key == "allowed_ips" and isinstance(value, (set, frozenset)):
                    updates[key] = frozenset(value)
                else:
                    updates[key] = value
            new_policy = dataclasses.replace(current, **updates)
            self._supervisor._pid_policies[pid] = new_policy

    def _cap_to_ceiling(self, key: str, value: Any) -> Any:
        """Cap a value to the ceiling's limit."""
        ceiling_val = getattr(self._ceiling, key)

        if key == "allowed_ips":
            # allowed_ips: grant value is union, but cap to ceiling
            if isinstance(value, (set, frozenset)):
                if ceiling_val:
                    return frozenset(value) & ceiling_val
                return frozenset(value)
            return value

        if key in ("max_memory_bytes", "max_processes"):
            # Numeric limits: can't exceed ceiling
            if ceiling_val > 0 and value > ceiling_val:
                return ceiling_val
            return value

        return value

    def _swap_policy(self, updates: dict[str, Any]) -> None:
        """Atomically swap the supervisor's policy reference."""
        current = self._supervisor._policy
        new_policy = dataclasses.replace(current, **updates)
        # CPython GIL makes reference assignment atomic
        self._supervisor._policy = new_policy

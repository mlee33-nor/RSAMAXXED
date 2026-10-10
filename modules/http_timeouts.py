"""A default timeout for HTTP calls made inside third-party broker libraries.

robin_stocks, fennel_invest_api and schwab_api all call `requests` with no `timeout`, and requests waits forever by
default. One stalled socket then holds a broker slot (and, for Robinhood, the
input-patch lock) for the rest of the session.

Nothing here touches the global `requests` module. Each library gets either a
proxy in place of its own module-level `requests` name, or a wrapped
`request` on its own Session instance. A call that already passes `timeout`
keeps it untouched.

A read timeout on an order POST is NOT "nothing was sent" -- the request went
out. Callers that place orders already report exceptions after the send with
"submitted ... verify" wording; this only turns an infinite hang into one.
"""

from __future__ import annotations

from typing import Any

#: (connect, read) seconds. Long enough for a slow broker, short enough that a
#: dead socket ends inside one trade's time budget.
DEFAULT_TIMEOUT = (10, 60)

_VERBS = ("get", "post", "put", "patch", "delete", "head", "options", "request")


class _RequestsProxy:
    """Stands in for the `requests` module inside one library module."""

    def __init__(self, real: Any, timeout: Any):
        self._real = real
        self._timeout = timeout

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._real, name)
        if name in _VERBS and callable(attr):
            def _call(*args: Any, **kwargs: Any) -> Any:
                if kwargs.get("timeout") is None:
                    kwargs["timeout"] = self._timeout
                return attr(*args, **kwargs)
            return _call
        return attr


def patch_module_requests(module: Any, timeout: Any = DEFAULT_TIMEOUT) -> bool:
    """Give every `requests.<verb>(...)` in `module` a default timeout.

    Idempotent. Returns False when the module has no `requests` name."""
    real = getattr(module, "requests", None)
    if real is None:
        return False
    if isinstance(real, _RequestsProxy):
        return True
    module.requests = _RequestsProxy(real, timeout)
    return True


def patch_session(session: Any, timeout: Any = DEFAULT_TIMEOUT) -> bool:
    """Give every request through this Session instance a default timeout.

    Session.get/post/... all funnel through `self.request`, so wrapping the
    instance's `request` covers them. Idempotent. Returns False for anything
    without a callable `request`."""
    if session is None:
        return False
    if getattr(session, "_rsa_default_timeout", None) is not None:
        return True
    inner = getattr(session, "request", None)
    if not callable(inner):
        return False

    def request(*args: Any, **kwargs: Any) -> Any:
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = timeout
        return inner(*args, **kwargs)

    try:
        session.request = request
        session._rsa_default_timeout = timeout
    except Exception:
        return False
    return True

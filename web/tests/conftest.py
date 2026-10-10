"""Shared fixtures for the web tests."""

from __future__ import annotations

import socket

import pytest


# No web test may reach the outside world (the live site, Postgres, a feed).
# The app runs in-process through TestClient; loopback stays open.
@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    real_connect = socket.socket.connect

    def guard(self, address, _real=real_connect):
        host = address[0] if isinstance(address, tuple) and address else address
        if (host not in ("127.0.0.1", "::1", "localhost")
                and self.family in (socket.AF_INET, socket.AF_INET6)):
            raise OSError(f"tests may not open network connections (to {address!r})")
        return _real(self, address)

    monkeypatch.setattr(socket.socket, "connect", guard)
    yield

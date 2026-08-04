"""Drives the real desktop client (cloud_sync.py) against the real server.

The two are developed in different files and could drift — a renamed JSON key
would break pairing in the field but pass both unit suites. Here we shim
`requests` so cloud_sync's own code paths hit an in-process TestClient.

Also pins the promise the GUI relies on: cloud failures raise CloudError and
never escape as something the app would crash on.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import tempfile

import pytest

WEB_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = WEB_ROOT.parent

# Order matters. The repo root holds app.py (the tkinter GUI) and the web
# package is also named `app`. WEB_ROOT must come first or `import app` pulls in
# the desktop GUI — which drags in customtkinter and has no `.db` submodule.
sys.path.insert(0, str(REPO_ROOT))   # for `import cloud_sync`
sys.path.insert(0, str(WEB_ROOT))    # for `import app.*` — must win

_TMP_DB = pathlib.Path(tempfile.gettempdir()) / "rsamaxxed_contract.sqlite3"
_TMP_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["ENV"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

import cloud_sync  # noqa: E402  (the desktop client, from the repo root)
from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _schema():
    init_db()
    yield
    engine.dispose()
    _TMP_DB.unlink(missing_ok=True)


@pytest.fixture()
def wired(tmp_path, monkeypatch):
    """Point cloud_sync's `requests` at the app, and its state file at tmp.

    Redirecting _STATE_FILE matters: without it the test would overwrite the
    developer's real cloud_state.json and log their machine out.
    """
    client = TestClient(app)

    class _Resp:
        def __init__(self, r):
            self._r = r
            self.status_code = r.status_code
            self.text = r.text

        def json(self):
            return self._r.json()

    def _path(url: str) -> str:
        return url.replace("http://testserver", "")

    monkeypatch.setattr(cloud_sync.requests, "post",
                        lambda url, json=None, headers=None, timeout=None:
                            _Resp(client.post(_path(url), json=json, headers=headers)))
    monkeypatch.setattr(cloud_sync.requests, "get",
                        lambda url, headers=None, timeout=None:
                            _Resp(client.get(_path(url), headers=headers)))
    monkeypatch.setattr(cloud_sync, "_STATE_FILE", tmp_path / "cloud_state.json")
    monkeypatch.setattr(cloud_sync, "_TRADES_FILE", REPO_ROOT / "trades.json")

    sync = cloud_sync.CloudSync(base_url="http://testserver")
    return sync, client


def _csrf(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _signup_browser(email: str) -> TestClient:
    browser = TestClient(app)
    # Signup now requires a chosen plan; automation includes the terminal these
    # contract tests pair against.
    page = browser.get("/signup?plan=automation")
    browser.post("/signup", data={"email": email, "password": "correct-horse-battery",
                                  "plan": "automation",
                                  "csrf_token": _csrf(page.text)})
    return browser


def test_full_pairing_and_push_through_the_real_client(wired):
    sync, _client = wired
    assert not sync.is_linked

    pending = sync.begin_pairing()
    assert len(pending.code) == 6
    assert sync.poll_pairing(pending) == "pending"

    browser = _signup_browser("contract@example.com")
    page = browser.get("/app/devices").text
    browser.post("/app/devices/claim",
                 data={"code": pending.code, "csrf_token": _csrf(page)})

    assert sync.poll_pairing(pending) == "claimed"
    assert sync.is_linked
    assert sync.linked_email == "contract@example.com"

    trades = json.loads((REPO_ROOT / "trades.json").read_text("utf-8"))
    result = sync.push_trades()
    assert result["inserted"] == len(trades), result

    # Second push sends nothing: the local synced_ids cache short-circuits it.
    assert sync.push_trades()["sent"] == 0

    # force=True re-sends, and the server still inserts nothing (idempotent).
    forced = sync.push_trades(force=True)
    assert forced["sent"] == len(trades) and forced["inserted"] == 0

    # And the dashboard agrees with app.py.
    from app import analytics
    expected = analytics.summarize(analytics.to_tradelike(trades)).realized
    assert f"${expected:+,.2f}" in browser.get("/app").text


def test_push_whitelists_fields(wired):
    """A field added to trades.json must not silently start uploading."""
    sync, _ = wired
    dirty = {"id": "x", "timestamp": "2026-01-01T00:00:00+00:00", "broker": "b",
             "account_id": "a", "side": "buy", "symbol": "S", "qty": 1,
             "fill_price": 1.0, "broker_password": "hunter2", "session_cookie": "abc"}
    cleaned = cloud_sync._clean(dirty)
    assert "broker_password" not in cleaned
    assert "session_cookie" not in cleaned
    assert set(cleaned) == set(cloud_sync._ALLOWED)


def test_holdings_push_accepts_broker_objects(wired):
    """get_holdings() returns AccountOutput-ish objects, not dicts."""
    sync, _client = wired
    pending = sync.begin_pairing()
    browser = _signup_browser("holdings@example.com")
    page = browser.get("/app/devices").text
    browser.post("/app/devices/claim", data={"code": pending.code, "csrf_token": _csrf(page)})
    assert sync.poll_pairing(pending) == "claimed"

    class H:
        def __init__(self, sym, q, v):
            self.symbol, self.quantity, self.value = sym, q, v

    class Acct:
        broker = "fidelity"
        account_id = "Fidelity 1"
        holdings = [H("HERZ", 1, 2.10), H("AIFA", 3, None)]

    out = sync.push_holdings([Acct()])
    assert out["rows"] == 2
    page = browser.get("/app/holdings").text
    assert "HERZ" in page and "AIFA" in page


def test_unlinked_push_raises_cloud_error(wired):
    sync, _ = wired
    with pytest.raises(cloud_sync.CloudError):
        sync.push_trades()


def test_revoked_token_unlinks_locally(wired):
    """When the website revokes a device, the app must forget its token rather
    than retry forever — that's what lets the user simply re-pair."""
    sync, _client = wired
    pending = sync.begin_pairing()
    browser = _signup_browser("revoked@example.com")
    page = browser.get("/app/devices").text
    browser.post("/app/devices/claim", data={"code": pending.code, "csrf_token": _csrf(page)})
    assert sync.poll_pairing(pending) == "claimed"

    page = browser.get("/app/devices").text
    did = re.search(r"/app/devices/(\d+)/revoke", page).group(1)
    browser.post(f"/app/devices/{did}/revoke", data={"csrf_token": _csrf(page)})

    with pytest.raises(cloud_sync.CloudError, match="unlinked"):
        sync.push_trades(force=True)
    assert not sync.is_linked, "app kept a dead token"


def test_unreachable_cloud_raises_cloud_error_not_a_crash():
    """The GUI catches CloudError. Anything else would surface as a traceback."""
    sync = cloud_sync.CloudSync(base_url="http://127.0.0.1:9")  # nothing listens on :9
    with pytest.raises(cloud_sync.CloudError):
        sync.begin_pairing()

"""End-to-end: signup -> pair a device -> push the real trade journal ->
assert the dashboard shows exactly what the desktop app computes.

Runs entirely in-process against a throwaway SQLite file. The two checks worth
losing sleep over are `test_tenant_isolation` (customer B must never see
customer A's trades) and `test_revoke_kills_token`.
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
sys.path.insert(0, str(WEB_ROOT))

# Must be set before `app.config` is imported, since it reads the environment
# once at module import time.
_TMP_DB = pathlib.Path(tempfile.gettempdir()) / "rsamaxxed_e2e.sqlite3"
_TMP_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-not-used-in-prod"
os.environ["ENV"] = "development"
os.environ["OPEN_SIGNUP"] = "1"

from fastapi.testclient import TestClient  # noqa: E402

from app import analytics  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402

TRADES_JSON = REPO_ROOT / "trades.json"
UPLOAD_FIELDS = ("id", "timestamp", "broker", "account_id", "side", "symbol", "qty", "fill_price")


@pytest.fixture(scope="module", autouse=True)
def _schema():
    init_db()
    yield
    # Windows won't unlink a file the engine still has open.
    engine.dispose()
    _TMP_DB.unlink(missing_ok=True)


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "page carried no CSRF token"
    return m.group(1)


def _signup(client: TestClient, email: str, password: str = "correct-horse-battery") -> None:
    # Signup now requires a chosen plan; these tests pair a device, so they need
    # a terminal tier (automation) — that's also what lands on /app/devices.
    page = client.get("/signup?plan=automation")
    r = client.post("/signup", data={"email": email, "password": password,
                                     "plan": "automation",
                                     "csrf_token": _csrf(page.text)}, follow_redirects=True)
    assert str(r.url).endswith("/app/devices?welcome=1"), f"signup landed on {r.url}"


def _pair(client: TestClient, browser: TestClient) -> str:
    """Full pairing handshake. Returns the device bearer token."""
    start = client.post("/api/v1/devices/pair/start",
                        json={"machine_id": "e2e", "device_name": "E2E Rig"}).json()
    code, poll = start["code"], start["poll_token"]

    assert client.post("/api/v1/devices/pair/poll",
                       json={"poll_token": poll}).json()["status"] == "pending"

    page = browser.get("/app/devices").text
    # lowercase on purpose: normalize_code() must accept it
    claimed = browser.post("/app/devices/claim",
                           data={"code": code.lower(), "csrf_token": _csrf(page)},
                           follow_redirects=True)
    assert "Linked" in claimed.text, "claim did not link the device"

    got = client.post("/api/v1/devices/pair/poll", json={"poll_token": poll}).json()
    assert got["status"] == "claimed"
    return got["device_token"]


def _push_all_trades(client: TestClient, token: str, trades: list[dict]) -> int:
    headers = {"Authorization": f"Bearer {token}"}
    inserted = 0
    for i in range(0, len(trades), 400):
        batch = [{k: t.get(k) for k in UPLOAD_FIELDS} for t in trades[i:i + 400]]
        r = client.post("/api/v1/sync/trades", json={"trades": batch}, headers=headers)
        assert r.status_code == 200, r.text
        inserted += r.json()["inserted"]
    return inserted


@pytest.fixture(scope="module")
def real_trades() -> list[dict]:
    if not TRADES_JSON.exists():
        pytest.skip("no trades.json to test against")
    return json.loads(TRADES_JSON.read_text("utf-8"))


@pytest.fixture(scope="module")
def paired(real_trades):
    """A signed-in browser session plus a paired device holding the real journal."""
    with TestClient(app) as browser, TestClient(app) as device:
        _signup(browser, "owner@example.com")
        token = _pair(device, browser)
        inserted = _push_all_trades(device, token, real_trades)
        assert inserted == len(real_trades), f"inserted {inserted} of {len(real_trades)}"
        yield browser, device, token


# ------------------------------------------------------------------- pairing

def test_wrong_code_is_rejected():
    with TestClient(app) as browser:
        _signup(browser, "wrongcode@example.com")
        page = browser.get("/app/devices").text
        r = browser.post("/app/devices/claim",
                         data={"code": "ZZZZZZ", "csrf_token": _csrf(page)},
                         follow_redirects=True)
        assert "wrong or has expired" in r.text
        assert "Revoke" not in r.text, "a bogus code created a device"


def test_device_token_is_single_pickup():
    """Replaying the poll must not hand the token out twice."""
    with TestClient(app) as browser, TestClient(app) as device:
        _signup(browser, "once@example.com")
        start = device.post("/api/v1/devices/pair/start", json={"machine_id": "m"}).json()
        page = browser.get("/app/devices").text
        browser.post("/app/devices/claim",
                     data={"code": start["code"], "csrf_token": _csrf(page)})

        first = device.post("/api/v1/devices/pair/poll",
                            json={"poll_token": start["poll_token"]}).json()
        assert first["status"] == "claimed" and first["device_token"]

        second = device.post("/api/v1/devices/pair/poll",
                             json={"poll_token": start["poll_token"]}).json()
        assert second["status"] == "consumed"
        assert "device_token" not in second


def test_code_cannot_be_claimed_twice():
    with TestClient(app) as a, TestClient(app) as b, TestClient(app) as device:
        _signup(a, "first@example.com")
        _signup(b, "second@example.com")
        start = device.post("/api/v1/devices/pair/start", json={"machine_id": "m"}).json()

        page = a.get("/app/devices").text
        a.post("/app/devices/claim", data={"code": start["code"], "csrf_token": _csrf(page)})

        page = b.get("/app/devices").text
        r = b.post("/app/devices/claim",
                   data={"code": start["code"], "csrf_token": _csrf(page)}, follow_redirects=True)
        assert "already used" in r.text, "a claimed code was stolen by another account"


def test_sync_requires_a_valid_token():
    with TestClient(app) as c:
        assert c.post("/api/v1/sync/trades", json={"trades": []}).status_code == 401
        assert c.post("/api/v1/sync/trades", json={"trades": []},
                      headers={"Authorization": "Bearer nonsense"}).status_code == 401


# ---------------------------------------------------------------------- sync

def test_push_is_idempotent(paired, real_trades):
    _browser, device, token = paired
    batch = [{k: t.get(k) for k in UPLOAD_FIELDS} for t in real_trades[:400]]
    r = device.post("/api/v1/sync/trades", json={"trades": batch},
                    headers={"Authorization": f"Bearer {token}"}).json()
    assert r["inserted"] == 0, "re-pushing the same trades created duplicates"
    assert r["total"] == len(real_trades)


def test_oversized_batch_is_refused(paired):
    _browser, device, token = paired
    fat = [{"id": f"x{i}", "timestamp": "2026-01-01T00:00:00+00:00", "broker": "b",
            "side": "buy", "symbol": "A", "qty": 1} for i in range(501)]
    r = device.post("/api/v1/sync/trades", json={"trades": fat},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 413


def test_holdings_snapshot_round_trips(paired):
    browser, device, token = paired
    r = device.post("/api/v1/sync/holdings", headers={"Authorization": f"Bearer {token}"},
                    json={"holdings": [
                        {"broker": "fidelity", "account_id": "Fidelity 1",
                         "symbol": "HERZ", "qty": 1, "value": 2.10},
                        {"broker": "public", "account_id": "Public 2",
                         "symbol": "AIFA", "qty": 3, "value": 4.50},
                    ]})
    assert r.status_code == 200 and r.json()["rows"] == 2
    page = browser.get("/app/holdings").text
    assert "HERZ" in page and "Fidelity" in page


# ----------------------------------------------------------------- dashboard

def test_dashboard_matches_app_py(paired, real_trades):
    """The number on the website must be the number in the GUI."""
    browser, _device, _token = paired
    expected = analytics.summarize(analytics.to_tradelike(real_trades)).realized
    page = browser.get("/app").text
    assert f"${expected:+,.2f}" in page, f"dashboard did not render ${expected:+,.2f}"


def test_zero_basis_symbol_is_disclosed(paired):
    """MASK was bought with fill_price=None. Say so; don't quietly book it."""
    browser, _device, _token = paired
    page = browser.get("/app").text
    assert "MASK" in page and "overstated" in page


def test_csv_export_contains_every_trade(paired, real_trades):
    browser, _device, _token = paired
    r = browser.get("/app/trades.csv")
    assert r.status_code == 200
    body = r.text.strip().splitlines()
    assert len(body) == len(real_trades) + 1  # + header


# -------------------------------------------------------- security invariants

def test_tenant_isolation(paired, real_trades):
    """A second account must see an empty dashboard, not someone else's money."""
    _owner, _device, _token = paired
    expected = analytics.summarize(analytics.to_tradelike(real_trades)).realized

    with TestClient(app) as intruder:
        _signup(intruder, "intruder@example.com")
        page = intruder.get("/app").text
        assert "No trades synced yet" in page
        assert f"${expected:+,.2f}" not in page
        assert intruder.get("/app/trades.csv").text.strip().count("\n") == 0  # header only


def test_cannot_revoke_another_users_device(paired):
    browser, _device, _token = paired
    victim_page = browser.get("/app/devices").text
    victim_id = re.search(r"/app/devices/(\d+)/revoke", victim_page).group(1)

    with TestClient(app) as intruder:
        _signup(intruder, "thief@example.com")
        page = intruder.get("/app/devices").text
        r = intruder.post(f"/app/devices/{victim_id}/revoke",
                          data={"csrf_token": _csrf(page)}, follow_redirects=True)
        assert "Device not found" in r.text

    # ...and the victim's device still works
    assert browser.get("/app/devices").text.count("Revoke") >= 1


def test_csrf_is_enforced(paired):
    browser, _device, _token = paired
    r = browser.post("/app/devices/claim", data={"code": "ABC123", "csrf_token": "forged"},
                     follow_redirects=True)
    assert "Session expired" in r.text


def test_revoke_kills_token(real_trades):
    with TestClient(app) as browser, TestClient(app) as device:
        _signup(browser, "revoker@example.com")
        token = _pair(device, browser)
        headers = {"Authorization": f"Bearer {token}"}
        assert device.get("/api/v1/me", headers=headers).status_code == 200

        page = browser.get("/app/devices").text
        did = re.search(r"/app/devices/(\d+)/revoke", page).group(1)
        browser.post(f"/app/devices/{did}/revoke", data={"csrf_token": _csrf(page)})

        assert device.get("/api/v1/me", headers=headers).status_code == 401
        assert device.post("/api/v1/sync/trades", json={"trades": []},
                           headers=headers).status_code == 401


def test_logged_out_dashboard_redirects_to_login():
    with TestClient(app) as c:
        r = c.get("/app", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"


def test_api_401s_as_json_not_a_redirect():
    """Browsers get redirected; the desktop client must get a clean 401."""
    with TestClient(app) as c:
        r = c.get("/api/v1/me", follow_redirects=False)
        assert r.status_code == 401
        assert r.json()["detail"]


def test_pair_url_is_derived_from_the_request_when_unconfigured():
    """A hardcoded PUBLIC_BASE_URL shipped `http://127.0.0.1:8000` to production
    and would have told every customer to pair on their own laptop."""
    from app import config
    assert config.PUBLIC_BASE_URL == "", "this test assumes PUBLIC_BASE_URL is unset"

    with TestClient(app, base_url="https://rsamaxxed.example.com") as device:
        r = device.post("/api/v1/devices/pair/start", json={"machine_id": "m"})
        assert r.json()["pair_url"] == "https://rsamaxxed.example.com/app/devices"


def test_pair_url_prefers_explicit_configuration(monkeypatch):
    from app.routes import api as api_routes
    monkeypatch.setattr(api_routes.config, "PUBLIC_BASE_URL", "https://rsamaxxed.com")
    with TestClient(app, base_url="https://ignored.example.com") as device:
        r = device.post("/api/v1/devices/pair/start", json={"machine_id": "m"})
        assert r.json()["pair_url"] == "https://rsamaxxed.com/app/devices"

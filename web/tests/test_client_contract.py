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
    # A synthetic journal in tmp, never the repo root's trades.json: that file
    # is the operator's live trade history, absent from a fresh clone, and a
    # test that reads it passes or fails on whatever was traded that week.
    trades_file = tmp_path / "trades.json"
    trades_file.write_text(json.dumps(_SAMPLE_TRADES), encoding="utf-8")
    monkeypatch.setattr(cloud_sync, "_TRADES_FILE", trades_file)

    sync = cloud_sync.CloudSync(base_url="http://testserver")
    return sync, client


# Two round trips — one up, one down — so the realized figure the dashboard
# prints is a real sum and not a lone row. Tickers and labels are made up.
_SAMPLE_TRADES = [
    {"id": "t-1", "timestamp": "2026-07-01T14:30:00+00:00", "broker": "public",
     "account_id": "Public 1 BROKERAGE (0001)", "side": "buy", "symbol": "AAAA",
     "qty": 1, "fill_price": 0.25},
    {"id": "t-2", "timestamp": "2026-07-09T15:00:00+00:00", "broker": "public",
     "account_id": "Public 1 BROKERAGE (0001)", "side": "sell", "symbol": "AAAA",
     "qty": 1, "fill_price": 4.75},
    {"id": "t-3", "timestamp": "2026-07-02T14:30:00+00:00", "broker": "fidelity",
     "account_id": "Fidelity 1 (0002)", "side": "buy", "symbol": "BBBB",
     "qty": 2, "fill_price": 1.10},
    {"id": "t-4", "timestamp": "2026-07-12T15:00:00+00:00", "broker": "fidelity",
     "account_id": "Fidelity 1 (0002)", "side": "sell", "symbol": "BBBB",
     "qty": 2, "fill_price": 0.90},
]


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

    trades = json.loads(cloud_sync._TRADES_FILE.read_text("utf-8"))
    assert trades, "the fixture journal is empty; the push below proves nothing"
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


def test_unreachable_cloud_raises_cloud_error_not_a_crash(tmp_path, monkeypatch):
    """The GUI catches CloudError. Anything else would surface as a traceback."""
    # begin_pairing mints a machine id and saves it; keep that out of the
    # repo root, where cloud_state.json is the operator's real device link.
    monkeypatch.setattr(cloud_sync, "_STATE_FILE", tmp_path / "cloud_state.json")
    sync = cloud_sync.CloudSync(base_url="http://127.0.0.1:9")  # nothing listens on :9
    with pytest.raises(cloud_sync.CloudError):
        sync.begin_pairing()


# ------------------------------------------------- account numbers (privacy)

def _link(sync, email):
    pending = sync.begin_pairing()
    browser = _signup_browser(email)
    page = browser.get("/app/devices").text
    browser.post("/app/devices/claim", data={"code": pending.code, "csrf_token": _csrf(page)})
    assert sync.poll_pairing(pending) == "claimed"
    return browser


def _stored(table: str, email: str) -> list[str]:
    from sqlalchemy import text
    q = (f"SELECT r.account_id FROM {table} r " +
         ("JOIN users u ON u.id = r.user_id " if table == "trades" else
          "JOIN holding_snapshots s ON s.id = r.snapshot_id "
          "JOIN users u ON u.id = s.user_id ") +
         "WHERE u.email = :e")
    with engine.connect() as conn:
        return [r[0] for r in conn.execute(text(q), {"e": email})]


def test_account_numbers_never_leave_the_desktop(wired):
    sync, _ = wired
    _link(sync, "mask@example.com")
    trades = json.loads(cloud_sync._TRADES_FILE.read_text("utf-8"))
    trades.append({"id": "t-5", "timestamp": "2026-07-03T14:30:00+00:00",
                   "broker": "fidelity",
                   "account_id": "Fidelity Individual (Z12345678)", "side": "buy",
                   "symbol": "CCCC", "qty": 1, "fill_price": 1.0})
    cloud_sync._TRADES_FILE.write_text(json.dumps(trades), encoding="utf-8")

    sent = []
    real = cloud_sync.requests.post

    def spy(url, json=None, headers=None, timeout=None):
        sent.append(json)
        return real(url, json=json, headers=headers, timeout=timeout)

    cloud_sync.requests.post = spy
    try:
        sync.push_trades()
    finally:
        cloud_sync.requests.post = real

    body = repr(sent)
    for number in ("12345678", "0001", "0002"):
        assert number not in body
    stored = _stored("trades", "mask@example.com")
    assert not any(re.search(r"\d{4}", a) for a in stored)
    # Still three distinct accounts, each with its readable label.
    assert len(set(stored)) == 3
    assert any(a.startswith("Fidelity Individual #") for a in stored)
    # Stable: the same device masks the same account the same way.
    salt = json.loads(cloud_sync._STATE_FILE.read_text("utf-8"))["account_salt"]
    assert cloud_sync._clean(trades[0], salt)["account_id"] == \
        cloud_sync._clean(trades[1], salt)["account_id"]


def test_holdings_upload_is_masked(wired):
    sync, _ = wired
    _link(sync, "maskholdings@example.com")

    class Acct:
        broker = "fidelity"
        account_id = "Fidelity Individual (Z87654321)"
        holdings = [{"symbol": "HERZ", "quantity": 1, "value": 2.0}]

    sync.push_holdings([Acct()])
    stored = _stored("holding_rows", "maskholdings@example.com")
    assert stored and not any("87654321" in a for a in stored)


def test_an_old_client_upload_is_masked_by_the_server(wired):
    """A desktop that has not been updated still sends raw numbers."""
    sync, client = wired
    _link(sync, "oldclient@example.com")
    token = json.loads(cloud_sync._STATE_FILE.read_text("utf-8"))["device_token"]
    raw = {"id": "old-1", "timestamp": "2026-07-01T14:30:00+00:00",
           "broker": "fidelity", "account_id": "Fidelity Individual (Z11112222)",
           "side": "buy", "symbol": "DDDD", "qty": 1, "fill_price": 1.0}
    r = client.post("/api/v1/sync/trades", json={"trades": [raw]},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    [stored] = _stored("trades", "oldclient@example.com")
    assert "11112222" not in stored and stored.startswith("Fidelity Individual #")

    # Updated desktop: its first push re-sends everything once, and the
    # server swaps in the device-masked label instead of keeping its own.
    cloud_sync._TRADES_FILE.write_text(json.dumps([raw]), encoding="utf-8")
    out = sync.push_trades()
    assert out["sent"] == 1 and out["inserted"] == 0
    [after] = _stored("trades", "oldclient@example.com")
    salt = json.loads(cloud_sync._STATE_FILE.read_text("utf-8"))["account_salt"]
    assert after == cloud_sync.mask_account_id(raw["account_id"], salt)
    assert sync.push_trades()["sent"] == 0          # only once


def test_startup_migration_masks_stored_numbers_idempotently():
    from datetime import datetime, timezone

    from app.db import SessionLocal, _mask_stored_account_ids
    from app.models import Trade, User

    with SessionLocal() as db:
        user = User(email="migrate@example.com", password_hash="x")
        db.add(user)
        db.flush()
        for i, acct in enumerate(["Fidelity Individual (Z12345678)",
                                  "Public 1 BROKERAGE (0001)", "Fidelity 1"]):
            db.add(Trade(user_id=user.id, client_id=f"m-{i}",
                         timestamp=datetime.now(timezone.utc), broker="fidelity",
                         account_id=acct, side="buy", symbol="AAAA", qty=1.0))
        db.commit()
    assert _mask_stored_account_ids() >= 2
    stored = _stored("trades", "migrate@example.com")
    assert not any(re.search(r"\d{4}", a) for a in stored)
    assert "Fidelity 1" in stored                           # nothing to mask
    assert len(set(stored)) == 3
    assert _mask_stored_account_ids() == 0                  # idempotent
    assert _stored("trades", "migrate@example.com") == stored


# ------------------------------------------- fix4 N4: the web nets like the app


def _server_rows(email: str) -> list[dict]:
    from sqlalchemy import text
    q = ("SELECT r.client_id, r.timestamp, r.broker, r.account_id, r.side, "
         "r.symbol, r.qty, r.fill_price FROM trades r "
         "JOIN users u ON u.id = r.user_id WHERE u.email = :e ORDER BY r.timestamp")
    with engine.connect() as conn:
        rows = conn.execute(text(q), {"e": email}).mappings().all()
    return [dict(r) for r in rows]


def _web_realized(email: str) -> float:
    from app import analytics
    return analytics.summarize(analytics.to_tradelike(_server_rows(email))).realized


def _row(i, day, acct, side, sym, qty, price, broker="fidelity"):
    return {"id": f"f4-{i}", "timestamp": f"2026-09-{day:02d}T14:30:00+00:00",
            "broker": broker, "account_id": acct, "side": side, "symbol": sym,
            "qty": qty, "fill_price": price}


def test_a_price_backfilled_after_the_push_reaches_the_server(wired):
    """A push that beat the worker's quote lookup left the sell unpriced on the
    server forever: it never updated fill_price and the desktop never re-sent."""
    sync, _ = wired
    _link(sync, "backfill@example.com")
    rows = [_row(1, 1, "Fidelity 1 · Individual (Z5550001)", "buy", "CCCC", 1, 1.0),
            _row(2, 5, "Fidelity 1 · Individual (Z5550001)", "sell", "CCCC", 1, None)]
    cloud_sync._TRADES_FILE.write_text(json.dumps(rows), encoding="utf-8")
    assert sync.push_trades(renames={})["inserted"] == 2
    assert _web_realized("backfill@example.com") == 0.0

    rows[1]["fill_price"] = 3.0                      # set_fill_prices, later
    cloud_sync._TRADES_FILE.write_text(json.dumps(rows), encoding="utf-8")
    out = sync.push_trades(renames={})
    assert out["sent"] == 1 and out["updated"] == 1 and out["inserted"] == 0
    assert _web_realized("backfill@example.com") == pytest.approx(2.0)
    assert sync.push_trades(renames={})["sent"] == 0  # nothing changed since


def test_a_drifted_label_and_a_rename_net_as_one_position(wired):
    """r4/r5: 'Robinhood 1 | ' vs bare, Individual vs FinTec, AGAE -> AIFA. The
    app says -0.30 + 2.00 = 1.70; the web said 0.87 / -0.30 before."""
    sync, _ = wired
    _link(sync, "drift@example.com")
    rows = [
        _row(1, 1, "Robinhood 1 | individual (****0042)", "buy", "GRNQ", 1, 1.30,
             broker="robinhood"),
        _row(2, 5, "individual (****0042)", "sell", "GRNQ", 0.1, 10.0, broker="robinhood"),
        _row(3, 2, "Fidelity 1 · Individual (Z5550002)", "buy", "AGAE", 1, 1.00),
        _row(4, 6, "Fidelity 1 · FinTec (Z5550002)", "sell", "AIFA", 1, 3.00),
    ]
    cloud_sync._TRADES_FILE.write_text(json.dumps(rows), encoding="utf-8")
    sync.push_trades(renames={"AIFA": "AGAE"})
    stored = _server_rows("drift@example.com")
    assert {r["symbol"] for r in stored} == {"GRNQ", "AGAE"}
    assert len({r["account_id"] for r in stored if r["broker"] == "robinhood"}) == 1
    assert _web_realized("drift@example.com") == pytest.approx(1.70)

    # A rename learnt AFTER the first push re-sends the sell under the folded
    # name, and the server takes the new symbol.
    _link(sync, "drift2@example.com")
    sync.push_trades(force=True, renames={})
    assert "AIFA" in {r["symbol"] for r in _server_rows("drift2@example.com")}
    out = sync.push_trades(renames={"AIFA": "AGAE"})
    assert out["updated"] == 1
    assert "AIFA" not in {r["symbol"] for r in _server_rows("drift2@example.com")}


def test_two_logins_with_the_same_account_number_stay_two_accounts(wired):
    sync, _ = wired
    salt = "s" * 32
    a = cloud_sync.mask_account_id("Public 1 BROKERAGE (0043)", salt, "public")
    b = cloud_sync.mask_account_id("Public 2 BROKERAGE (0043)", salt, "public")
    assert a != b
    from app import analytics
    assert analytics.account_key(a) != analytics.account_key(b)


def test_a_close_row_does_not_fail_the_batch(wired):
    sync, _ = wired
    _link(sync, "close@example.com")
    rows = [_row(1, 1, "Fidelity 1 (0003)", "buy", "DDDD", 1, 1.0),
            _row(2, 3, "Fidelity 1 (0003)", "close", "DDDD", 1, None)]
    cloud_sync._TRADES_FILE.write_text(json.dumps(rows), encoding="utf-8")
    assert sync.push_trades(renames={})["inserted"] == 2

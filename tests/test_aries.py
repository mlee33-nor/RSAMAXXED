"""Aries: paste a Client ID + Secret, and the app buys and sells over the API.

Everything here runs against a fake of Aries' REST API (no network). What
matters most is the wording on every failure: the app re-sends only what
positively says "nothing was sent", and never what says "submitted … verify".
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as A  # noqa: E402
import aries  # noqa: E402
import broker_logins as BL  # noqa: E402
import lifecycle  # noqa: E402
import rsa_feed  # noqa: E402
from etf_plan import Capability, capability_for  # noqa: E402


class Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class _Exc:
    class ConnectionError(Exception):
        pass

    class Timeout(Exception):
        pass

    class ConnectTimeout(ConnectionError, Timeout):
        pass

    class ReadTimeout(Timeout):
        pass


class FakeAries:
    exceptions = _Exc

    def __init__(self):
        self.accounts = [
            {"trading_account_id": "SIM6B86XEYOC", "is_sim": True, "status": "OPEN"},
            {"trading_account_id": "3AF05000", "is_sim": False, "status": "OPEN",
             "account_type": "INDIVIDUAL", "account_class": "CASH"},
        ]
        self.positions = {"3AF05000": [{"symbol": "IPDN", "quantity": "1",
                                        "securityType": "EQUITY", "price": "4.75"}]}
        self.preview_resp = {"commission": "0", "fees": "0", "estimatedCost": "4.75"}
        self.order_resp = None          # None -> NEW ack
        self.order_exc = None
        self.later = None               # order as listed a moment later
        self.token_status = 200
        self.orders = []
        self.previews = []

    def post(self, url, json=None, data=None, headers=None, timeout=None):
        if url.endswith("/v1/oauth2/token"):
            if self.token_status != 200:
                return Resp(self.token_status, {"error": "invalid_client"})
            assert data["grant_type"] == "client_credentials"
            return Resp(200, {"access_token": "tok", "expires_in": 900,
                              "scope": " ".join(aries.SCOPES_NEEDED)})
        assert headers["Authorization"] == "Bearer tok"
        if url.endswith("/v1/orders/preview"):
            self.previews.append(json)
            return Resp(200, self.preview_resp)
        if url.endswith("/v1/orders"):
            self.orders.append(json)
            if self.order_exc is not None:
                raise self.order_exc
            if self.order_resp is not None:
                return self.order_resp
            return Resp(200, {"success": True, "clOrdId": "CL1", "status": "NEW",
                              "cumQty": "0", "avgPrice": "0"})
        raise AssertionError(url)

    def get(self, url, headers=None, params=None, timeout=None):
        if url.endswith("/v2/users/me/accounts"):
            return Resp(200, {"accounts": self.accounts})
        if url.endswith("/positions"):
            acct = url.split("/accounts/")[1].split("/")[0]
            return Resp(200, {"positions": self.positions.get(acct, [])})
        if url.endswith("/balance"):
            return Resp(200, {"cashBalance": "100.50", "balance": "105.25",
                              "stockBuyingPower": "100.50"})
        if url.endswith("/orders"):
            return Resp(200, {"orders": [self.later] if self.later else []})
        if url.endswith("/orders/history"):
            return Resp(200, {"orders": []})
        raise AssertionError(url)


@pytest.fixture()
def fake(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("ARIES_"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ARIES_CLIENT_ID", "ARI-PERSONAL-TK.abc")
    monkeypatch.setenv("ARIES_CLIENT_SECRET", "s3cret")
    f = FakeAries()
    monkeypatch.setattr(aries._AriesClient, "_requests", lambda self: f)
    monkeypatch.setattr(aries, "_CLIENTS", {})
    monkeypatch.setattr(aries, "CONFIRM_WAIT", 0.0)
    monkeypatch.setattr(aries.time, "sleep", lambda *_a: None)
    monkeypatch.setattr(aries, "_root_dir", lambda: Path(__import__("tempfile").mkdtemp()))
    return f


def _row(out):
    (row,) = out.accounts
    return row


# ------------------------------------------------------------- registration

def test_aries_is_registered_everywhere_a_broker_must_be():
    import reconcile
    import runner
    assert A.BROKER_MODULES["aries"] == "aries"
    assert runner.BROKER_MODULES["aries"] == "aries"
    assert "aries" in reconcile.BROKERS
    assert "aries" in A.RETRYABLE_ACCOUNT_BROKERS
    assert "aries" in A.AUTOSELL_DAY_ORDER_BROKERS
    assert "aries" not in A._BROWSER_BROKERS
    assert lifecycle.app_key("Aries") == "aries"
    assert "Aries" in rsa_feed.SUPPORTED_BROKERS
    assert "Aries" in rsa_feed.CASH_IN_LIEU_BROKERS
    assert capability_for("aries") is Capability.UNVERIFIED
    assert A._is_login_label("Aries") and A._is_login_label("Aries 2")
    assert not A._is_login_label("Aries (5000)")


def test_two_pasted_values_are_a_login(fake, monkeypatch):
    (login,) = BL.logins("aries")
    assert login.complete and login.label_prefix == ""
    assert A._broker_has_creds("aries")
    secret = {f.name: f.secret for f in BL.SCHEMAS["aries"].fields}
    assert secret == {"client_id": False, "client_secret": True}
    assert BL.env_key("aries", "client_secret", 2) == "ARIES_CLIENT_SECRET_2"


def test_aries_runs_no_subprocess():
    assert "subprocess" not in Path(aries.__file__).read_text(encoding="utf-8")


# ------------------------------------------------------------------- buying

def test_a_buy_previews_then_places_one_day_market_order(fake):
    out = aries.execute_trade(side="buy", qty="1", symbol="ipdn")
    assert out.state == "success"
    row = _row(out)                                  # the SIM account is skipped
    assert row.ok and row.account_id == "Aries (5000)" and row.order_id == "CL1"
    (body,) = fake.orders
    assert body["tradingAccountId"] == "3AF05000"
    assert {k: body[k] for k in ("symbol", "side", "type", "qty", "timeInForce")} == \
        {"symbol": "IPDN", "side": "BUY", "type": "MARKET", "qty": "1",
         "timeInForce": "DAY"}
    assert body["clientId"].startswith("rsa-") and len(body["clientId"]) <= 50
    assert fake.previews == [body]


def test_paper_accounts_trade_only_when_asked(fake, monkeypatch):
    monkeypatch.setenv("ARIES_USE_SIM", "1")
    out = aries.execute_trade(side="buy", qty="1", symbol="IPDN")
    labels = sorted(a.account_id for a in out.accounts)
    assert labels == ["Aries (5000)", "Aries SIM (EYOC)"]


def test_a_quoted_fee_is_written_on_the_row(fake):
    fake.preview_resp = {"commission": "0.99", "fees": "0.01"}
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert row.ok and "commission $0.99" in row.message


def test_preview_errors_stop_the_order(fake):
    fake.preview_resp = {"errors": ["Insufficient buying power"]}
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert not row.ok and fake.orders == []
    assert A._nothing_was_sent(row.message)


def test_a_dry_run_sends_nothing(fake):
    out = aries.execute_trade(side="buy", qty="1", symbol="IPDN", dry_run=True)
    assert fake.orders == [] and _row(out).ok
    assert "DRY RUN" in out.message


def test_a_fill_price_is_reported(fake, monkeypatch):
    fake.later = {"clOrdId": "CL1", "ordStatus": "FILLED", "avgPrice": "4.75"}
    monkeypatch.setattr(aries, "CONFIRM_WAIT", 0.01)
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert row.ok and row.extra["fill_price"] == 4.75 and "FILLED" in row.message


def test_a_late_rejection_is_a_failure_with_nothing_sent(fake, monkeypatch):
    fake.later = {"clOrdId": "CL1", "ordStatus": "REJECTED",
                  "ordRejReason": "EXCHANGE_CLOSED"}
    monkeypatch.setattr(aries, "CONFIRM_WAIT", 0.01)
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert not row.ok and "EXCHANGE_CLOSED" in row.message
    assert A._nothing_was_sent(row.message)


# ------------------------------------------------------------ order failures

def test_a_lost_answer_is_never_retried(fake):
    fake.order_resp = Resp(504, {"error": "broker timeout"})
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert not row.ok
    assert A._account_order_may_exist({"ok": False, "message": row.message})
    assert not A._nothing_was_sent(row.message)


def test_a_read_timeout_may_exist(fake):
    fake.order_exc = _Exc.ReadTimeout("read timed out")
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert A._account_order_may_exist({"ok": False, "message": row.message})


def test_never_connecting_is_nothing_sent(fake):
    fake.order_exc = _Exc.ConnectTimeout("connect timed out")
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert not row.ok and A._nothing_was_sent(row.message)


def test_a_4xx_refusal_is_nothing_sent(fake):
    fake.order_resp = Resp(400, {"error": {"message": "symbol not tradable"}})
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert not row.ok and "symbol not tradable" in row.message
    assert A._nothing_was_sent(row.message)


def test_a_missing_scope_says_which(fake):
    fake.order_resp = Resp(403, {"error": "insufficient_scope"})
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert "order:execution" in row.message and A._nothing_was_sent(row.message)


def test_a_bad_key_is_a_failed_login_with_nothing_sent(fake):
    fake.token_status = 401
    out = aries.execute_trade(side="buy", qty="1", symbol="IPDN")
    row = _row(out)
    assert row.account_id == "Aries" and not row.ok
    assert "Client Secret" in row.message and A._nothing_was_sent(row.message)
    assert fake.orders == []


def test_not_set_up(fake, monkeypatch):
    monkeypatch.delenv("ARIES_CLIENT_ID")
    monkeypatch.delenv("ARIES_CLIENT_SECRET")
    row = _row(aries.execute_trade(side="buy", qty="1", symbol="IPDN"))
    assert "Client Center" in row.message and A._nothing_was_sent(row.message)


# ------------------------------------------------------------------- selling

def test_a_sell_never_opens_a_short(fake):
    fake.positions["3AF05000"] = []
    row = _row(aries.execute_trade(side="sell", qty="1", symbol="IPDN"))
    assert not row.ok and fake.orders == [] and A._nothing_was_sent(row.message)


def test_a_held_share_sells(fake):
    row = _row(aries.execute_trade(side="sell", qty="1", symbol="IPDN"))
    assert row.ok and fake.orders[0]["side"] == "SELL"


# ------------------------------------------------------------------ retries

def test_only_accounts_narrows_and_a_login_name_means_all(fake):
    out = aries.execute_trade(side="buy", qty="1", symbol="IPDN",
                              only_accounts=["Aries (9999)"])
    assert fake.orders == [] and A._nothing_was_sent(_row(out).message)
    out = aries.execute_trade(side="buy", qty="1", symbol="IPDN",
                              only_accounts=["Aries"])
    assert len(fake.orders) == 1 and _row(out).ok


# ------------------------------------------------------------------ holdings

def test_holdings_carry_cash_and_the_same_labels_as_trades(fake):
    out = aries.get_holdings()
    row = _row(out)
    assert row.account_id == "Aries (5000)"
    assert row.holdings[0].symbol == "IPDN" and row.holdings[0].shares == 1.0
    assert row.extra["cash"] == 100.5
    import balances
    assert balances.cash_from_extra("aries", row.extra) == 100.5


def test_accounts_that_end_alike_get_more_digits():
    labels = aries._labels("", [("AAA11234", False), ("BBB21234", False)])
    assert len(set(labels.values())) == 2

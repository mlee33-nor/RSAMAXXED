"""The Public evidence log: verbatim API answers, hash-chained.

It exists to show, later, what Public's API disclosed when the tool bought:
so every preflight and order must land in it, and any edit to it must show.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import public  # noqa: E402
import public_evidence as ev  # noqa: E402
import public_fees  # noqa: E402


class FakeResponse:
    def __init__(self, status, body, date="Mon, 09 Nov 2026 15:00:00 GMT"):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)
        self.headers = {"Date": date, "Content-Type": "application/json",
                        "Authorization": "never-recorded"}

    def json(self):
        return self._body


class FakeRequests:
    class exceptions:
        ConnectTimeout = type("ConnectTimeout", (Exception,), {})

    def __init__(self):
        self.posts = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.posts.append((url, json))
        if url.endswith("/preflight/single-leg"):
            return FakeResponse(200, {"estimatedCommission": "0.00",
                                      "regulatoryFees": {"secFee": "0.00", "tafFee": "0.00"},
                                      "orderValue": "1.10"})
        return FakeResponse(200, {"orderId": json["orderId"]})


def _client(monkeypatch):
    c = public._PublicClient(secret="s")
    fake = FakeRequests()
    monkeypatch.setattr(c, "_requests", lambda: fake)
    monkeypatch.setattr(c, "_headers", lambda: {"Authorization": "Bearer x"})
    return c


def test_preflight_and_order_are_recorded_verbatim(monkeypatch):
    c = _client(monkeypatch)
    c.preflight_equity_market_order(account_id="ACCT12345678", side="BUY",
                                    symbol="IPDN", quantity="1")
    oid = c.place_equity_market_order(account_id="ACCT12345678", side="BUY",
                                      symbol="IPDN", quantity="1")
    recs = ev.read_all()
    assert [r["kind"] for r in recs] == ["preflight", "order"]
    pre, order = recs
    assert pre["response"]["body"]["estimatedCommission"] == "0.00"
    assert pre["response"]["server_date"].startswith("Mon, 09 Nov 2026")
    assert order["request"]["orderId"] == oid
    assert pre["account"] == "5678" or pre["account"].endswith("5678")
    assert "ACCT1234" not in json.dumps(recs)           # last 4 only
    assert "never-recorded" not in json.dumps(recs)     # no auth headers
    assert ev.verify()["ok"]


def test_any_edit_breaks_the_chain():
    for i in range(3):
        ev.record("note", i=i)
    assert ev.verify()["ok"] and ev.verify()["count"] == 3
    lines = ev.EVIDENCE_FILE.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["i"] = 99
    lines[1] = json.dumps(rec)
    ev.EVIDENCE_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = ev.verify()
    assert not bad["ok"] and bad["bad_seq"] == 1


def test_a_removed_line_breaks_the_chain():
    for i in range(3):
        ev.record("note", i=i)
    lines = ev.EVIDENCE_FILE.read_text(encoding="utf-8").splitlines()
    ev.EVIDENCE_FILE.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    assert not ev.verify()["ok"]


def test_history_transactions_are_recorded_once():
    txs = [{"id": "t1", "type": "TRADE", "fees": "0.00"},
           {"id": "m1", "type": "MONEY_MOVEMENT", "netAmount": "100"}]
    assert ev.record_history("Public 1 BROKERAGE (1234)", txs) == 1
    assert ev.record_history("Public 1 BROKERAGE (1234)", txs) == 0


def test_summary_counts_clean_and_flagged_buys(monkeypatch):
    c = _client(monkeypatch)
    c.preflight_equity_market_order(account_id="A1", side="BUY", symbol="IPDN",
                                    quantity="1")
    ev.record_http("preflight", account="0002",
                   request={"orderSide": "BUY", "instrument": {"symbol": "X"}},
                   response=FakeResponse(200, {"estimatedCommission": "0.99",
                                               "warnings": ["reverse split fee"]}))
    s = ev.summary()
    assert s["buy_preflights"] == 2 and s["buy_preflights_flagged"] == 1
    assert s["chain"]["ok"]
    assert s["recent"][0]["notices"]


def test_export_pack_verifies_with_its_own_script(tmp_path):
    ev.record("note", i=1)
    ev.record("note", i=2)
    out, chk = ev.export(tmp_path)
    assert chk["ok"]
    assert (out / "README.txt").read_text(encoding="utf-8").count(chk["head"]) == 1
    r = subprocess.run([sys.executable, "-I", str(out / "verify_evidence.py"),
                        str(out / "public_evidence.jsonl")],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "OK: 2 records" in r.stdout


def test_scan_records_last_scan_status():
    class C:
        def get_history(self, account_id, start=None, next_token=None):
            return {"transactions": [{"id": "t", "type": "TRADE", "fees": "0"}]}
    public_fees.scan_accounts([(C(), "A1", "Public 1 BROKERAGE (A1)")])
    st = public_fees._load()["last_scan"]
    assert st["scanned"] == 1 and st["found"] == 0


def test_history_is_recorded_redacted():
    ev.record_history("Public 1 BROKERAGE (5678)",
                      [{"id": "t9", "type": "TRADE", "accountNumber": "5PX12345678"}])
    assert "12345678" not in ev.EVIDENCE_FILE.read_text(encoding="utf-8")


def test_a_failed_write_leaves_no_partial_line(monkeypatch):
    ev.record("note", i=1)
    good = ev.EVIDENCE_FILE.read_bytes()
    assert ev.record("note", bad=object()) is not None   # default=str copes
    # Unencodable content never reaches the file half-written.
    assert ev.record("note", text="\ud800") is not None
    assert ev.verify()["ok"]
    assert ev.EVIDENCE_FILE.read_bytes().startswith(good)

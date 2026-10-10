"""Pre-launch QA: loose feed chat never becomes a pick the mirror buys, the
feed diagnostic needs no key, and the obsolete deploy-by-git script is gone.

No GUI: `_extract_picks_from_text` is called unbound with a stand-in self.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import app as A
import rsa_feed

ROOT = Path(A.__file__).resolve().parent


def _extract(text: str):
    return A.App._extract_picks_from_text(types.SimpleNamespace(), text)


def test_loose_chat_extracts_as_unverified_never_reg_alert():
    for text, sym in (("Market opens 9:30 (ET)", "ET"),
                      ("(ABCD) cancelled its reverse split - do NOT buy", "ABCD"),
                      ("$NVDA https://example.com", "NVDA")):
        picks = _extract(text)
        assert [p["symbol"] for p in picks] == [sym]
        assert picks[0]["note"] == "unverified"
        assert picks[0]["note"].lower() not in A.MIRROR_NOTES


def test_rsa_note_maps_conditional_before_otc():
    assert A.App._rsa_note("CONDITIONAL OTC", "") == "conditional"
    assert A.App._rsa_note("OTC", "") == "OTC"
    assert A.App._rsa_note("STANDARD", "RSA Alert") == "Reg Alert"


def test_embed_alert_still_makes_a_reg_alert_pick():
    msg = {"id": "1", "embeds": [{"title": "RSA Alert", "description": "STANDARD",
                                  "fields": [{"name": "Ticker", "value": "NASDAQ: SBFM"},
                                             {"name": "Alert Date", "value": "6/18/26"}]}]}
    picks = A.App._extract_picks_from_message(types.SimpleNamespace(), msg)
    # The identity keys exactly; anything else is an optional display extra
    # (rsa_feed.to_pick), here only the post time.
    assert [{k: p[k] for k in ("symbol", "note", "date")} for p in picks] == [
        {"symbol": "SBFM", "note": "Reg Alert", "date": "2026-06-18"}]
    assert set(picks[0]) <= {"symbol", "note", "date", "last_buy", *A.PICK_DISPLAY_EXTRAS}
    assert picks[0]["note"].lower() in A.MIRROR_NOTES


def test_version_bumped():
    assert A.APP_VERSION == "1.0.1"


def test_diagnose_feed_does_not_require_a_plays_key(monkeypatch, capsys):
    monkeypatch.delenv("RSAMAXXED_PLAYS_KEY", raising=False)
    sys.path.insert(0, str(ROOT))
    import diagnose_feed

    class FakeCloud:
        device_token = ""
        base_url = "https://example.invalid"

        def fetch_picks(self):
            return [{"symbol": "SBFM", "note": "Reg Alert", "date": "2026-06-18"}]

    monkeypatch.setitem(sys.modules, "cloud_sync",
                        types.SimpleNamespace(CloudSync=FakeCloud))
    # load_dotenv must not pull a real .env's key back in.
    monkeypatch.setitem(sys.modules, "dotenv",
                        types.SimpleNamespace(load_dotenv=lambda *a, **k: None))
    assert diagnose_feed.main() == 0
    out = capsys.readouterr().out
    assert "RSAMAXXED_PLAYS_KEY" not in out
    assert "SBFM" in out


def test_publish_picks_is_gone_and_unreferenced():
    assert not (ROOT / "publish_picks.py").exists()
    for f in list(ROOT.glob("*.bat")) + list(ROOT.glob("*.py")):
        if f.name == Path(__file__).name:
            continue
        assert "publish_picks" not in f.read_text(encoding="utf-8", errors="ignore"), f

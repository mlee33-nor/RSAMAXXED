"""Every broker really is multi-login — checked against the modules, not the plan.

The feature is only true if all ten agree, and the five that were converted
(BBAE, Chase, DSPAC, SoFi, Wells Fargo) were converted by a script. A wiring
test is what stops "I patched five files" from quietly meaning four: each
assertion here reads the real module, so an eleventh broker added later, or a
refactor that drops a wrapper, fails this file rather than failing a customer's
second login in silence.

Nothing here logs in. It checks the seams: the schema exists, the single-login
body is still there under its new name, the public entry point goes through the
fan-out, and one login's session directory is not another's.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import broker_logins as BL

#: Every broker the app can load.
ALL = ["bbae", "chase", "dspac", "fennel", "fidelity", "public", "robinhood",
       "schwab", "sofi", "wellsfargo"]

#: The five that could hold exactly one login and now run through fan_out.
CONVERTED = ["bbae", "chase", "dspac", "sofi", "wellsfargo"]

#: The four that already parsed several logins out of one variable. They were
#: deliberately NOT touched — rewriting a working multi-login flow to prove a
#: point is how you break Fidelity's ten accounts.
ALREADY = ["fennel", "fidelity", "robinhood", "schwab"]


def load(broker: str):
    return importlib.import_module(broker)


def test_every_broker_has_a_login_schema():
    assert sorted(BL.SCHEMAS) == sorted(ALL)


@pytest.mark.parametrize("broker", ALL)
def test_every_broker_can_report_its_logins(broker):
    """No exceptions, whatever this developer's own .env happens to hold."""
    assert isinstance(BL.logins(broker), list)


@pytest.mark.parametrize("broker", CONVERTED)
def test_the_single_login_body_is_still_there_under_its_own_name(broker):
    """The conversion renames rather than rewrites: `_get_holdings_one` is the
    same code that shipped, which is the entire reason this was safe to do to
    five login flows at once."""
    mod = load(broker)
    for fn in ("_bootstrap_one", "_get_holdings_one", "_execute_trade_one"):
        assert callable(getattr(mod, fn, None)), f"{broker}.{fn}"


@pytest.mark.parametrize("broker", CONVERTED)
def test_the_public_entry_points_fan_out(broker):
    """Reading the source, because calling it would try to log in."""
    src = Path(f"{broker}.py").read_text(encoding="utf-8")
    for fn in ("bootstrap", "get_holdings", "execute_trade"):
        assert f"def {fn}(" in src
    assert src.count("broker_logins.fan_out(BROKER, _MODULE") >= 3, broker


@pytest.mark.parametrize("broker", CONVERTED)
def test_two_logins_do_not_share_a_session_directory(broker, monkeypatch, tmp_path):
    """Two logins in one browser profile fight over the same cookies and
    neither stays signed in. Login 1 keeps the original path so an upgrade does
    not put an existing user back through 2FA."""
    mod = load(broker)
    monkeypatch.setattr(mod, "_root_dir", lambda: tmp_path)

    monkeypatch.setattr(BL, "_active", {broker: 1})
    first = mod._sessions_dir()
    monkeypatch.setattr(BL, "_active", {broker: 2})
    second = mod._sessions_dir()

    assert first == tmp_path / "sessions" / BL.SCHEMAS[broker].broker
    assert second != first
    assert second.parent == first


@pytest.mark.parametrize("broker", CONVERTED)
def test_a_module_that_caches_a_session_can_swap_it(broker):
    """Chase and SoFi hold cookies in module globals; BBAE and DSPAC hold a
    signed-in client. Wells Fargo holds nothing between calls — its session
    lives entirely in the browser profile on disk, which _sessions_dir already
    separates, so it needs no hook."""
    mod = load(broker)
    if broker == "wellsfargo":
        assert not hasattr(mod, "_on_login_switch")
        return
    assert callable(getattr(mod, "_on_login_switch", None)), broker


@pytest.mark.parametrize("broker", ALREADY)
def test_the_brokers_that_already_worked_were_left_alone(broker):
    """They parse their own multi-login blob and always have. No fan-out, no
    renamed entry points, no new failure modes."""
    src = Path(f"{broker}.py").read_text(encoding="utf-8")
    assert "fan_out" not in src, f"{broker} should not have been converted"
    assert "def get_holdings(" in src


def test_public_lost_its_ceiling(monkeypatch):
    """A loop over the literal (1, 2, 3) was the whole cap, and a fourth token
    could be saved and then read by nothing — which on screen is
    indistinguishable from a broken login."""
    for i in range(1, 7):
        monkeypatch.setenv(f"PUBLIC_SECRET_TOKEN_{i}", f"tok-{i}")

    assert len(load("public")._load_public_secrets()) == 6


def test_public_keeps_a_logins_number_across_a_gap(monkeypatch):
    """Public builds "Public 3 BROKERAGE (1234)" out of this index and the
    journal nets buys against sells on that string. Closing a gap would rename
    the accounts and orphan every open position at that login."""
    for i in range(1, 5):
        monkeypatch.delenv(f"PUBLIC_SECRET_TOKEN_{i}", raising=False)
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_1", "a")
    monkeypatch.setenv("PUBLIC_SECRET_TOKEN_3", "c")

    assert load("public")._load_public_secrets() == [(1, "a"), (3, "c")]

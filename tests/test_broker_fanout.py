"""Running a one-login broker module once per login, without rewriting it.

BBAE, Chase, DSPAC, SoFi and Wells Fargo were each written around exactly one
set of credentials — module-global clients, one cookie jar, one browser
profile. Teaching all five to loop internally is five rewrites of five working
login flows, and a broker login is the one thing here that cannot be tested
without a real account.

So the driver runs each module's untouched single-login body once per login.
That makes this file the test for all five at once, driven by a stub module
that records exactly what each call could see.

The assertions that matter most are the ones about the SINGLE-login case: with
one login configured nothing may change at all, because that is every existing
install.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import broker_logins as BL
from modules.outputs import AccountOutput, BrokerOutput


class StubBroker:
    """A broker module the way the driver sees one."""

    BROKER = "bbae"
    BrokerOutput = BrokerOutput
    AccountOutput = AccountOutput

    def __init__(self, fail_on=()):
        self.saw: list = []                 # (username, session suffix) per call
        self.switched: list = []            # every _on_login_switch(idx)
        self.fail_on = set(fail_on)

    def _on_login_switch(self, idx: int) -> None:
        self.switched.append(idx)

    def get_holdings(self):
        user = os.getenv("BBAE_USER", "")
        self.saw.append((user, BL.active_suffix("bbae")))
        if user in self.fail_on:
            return BrokerOutput(
                broker="bbae", state="failed",
                accounts=[AccountOutput(account_id="BBAE", ok=False,
                                        message="Login failed")],
                message="Login failed")
        return BrokerOutput(
            broker="bbae", state="success",
            accounts=[AccountOutput(account_id=f"Individual (****{user[-4:]})",
                                    ok=True, message="")],
            message="ok", extra={"who": user})


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for idx in range(1, 6):
        for name in ("username", "password"):
            monkeypatch.delenv(BL.env_key("bbae", name, idx), raising=False)
        monkeypatch.delenv(BL.tag_key("bbae", idx), raising=False)


def one_login(monkeypatch):
    monkeypatch.setenv("BBAE_USER", "first@x.com")
    monkeypatch.setenv("BBAE_PASSWORD", "pw1")


def two_logins(monkeypatch):
    one_login(monkeypatch)
    monkeypatch.setenv("BBAE_USER_2", "second@x.com")
    monkeypatch.setenv("BBAE_PASSWORD_2", "pw2")


# ------------------------------------------------ the existing install

def test_one_login_is_called_once_with_nothing_changed(monkeypatch):
    """Every install today. One call, the original env, no label prefix."""
    one_login(monkeypatch)
    mod = StubBroker()

    out = BL.fan_out("bbae", mod, mod.get_holdings)

    assert mod.saw == [("first@x.com", "")]
    assert [a.account_id for a in out.accounts] == ["Individual (****.com)"]
    assert out.state == "success"


def test_no_logins_at_all_still_reaches_the_module(monkeypatch):
    """A broker with no credentials must produce its OWN error message —
    'Missing BBAE_USER or BBAE_PASSWORD' — not a generic one invented here."""
    mod = StubBroker()
    BL.fan_out("bbae", mod, mod.get_holdings)
    assert mod.saw == [("", "")]


def test_login_one_keeps_its_session_directory(monkeypatch):
    """The suffix is what each module appends to sessions/<broker>/. Empty for
    login 1, so the existing pkl and cookie jar are reused and nobody is asked
    for a 2FA code they were not expecting."""
    two_logins(monkeypatch)
    mod = StubBroker()

    BL.fan_out("bbae", mod, mod.get_holdings)

    assert [suffix for _u, suffix in mod.saw] == ["", "_2"]


# ------------------------------------------------------- the new case

def test_each_login_sees_its_own_credentials(monkeypatch):
    two_logins(monkeypatch)
    mod = StubBroker()

    BL.fan_out("bbae", mod, mod.get_holdings)

    assert [u for u, _s in mod.saw] == ["first@x.com", "second@x.com"]


def test_only_the_second_login_gets_a_label_prefix(monkeypatch):
    """Login 1's account_id is what trades.json already nets buys and sells on.
    Prefixing it would orphan every open position at that broker."""
    two_logins(monkeypatch)
    mod = StubBroker()

    out = BL.fan_out("bbae", mod, mod.get_holdings)

    assert [a.account_id for a in out.accounts] == [
        "Individual (****.com)", "BBAE 2 · Individual (****.com)"]


def test_the_cached_client_is_swapped_between_logins(monkeypatch):
    """Without the switch hook the in-memory session check inside these modules
    hands login 2 the client already signed in as login 1 — the fan-out reads
    the first set of accounts twice and never touches the second."""
    two_logins(monkeypatch)
    mod = StubBroker()

    BL.fan_out("bbae", mod, mod.get_holdings)

    assert mod.switched == [1, 1, 2, 1]      # in, out, in, out


def test_the_environment_is_put_back_afterwards(monkeypatch):
    two_logins(monkeypatch)
    mod = StubBroker()

    BL.fan_out("bbae", mod, mod.get_holdings)

    assert os.environ["BBAE_USER"] == "first@x.com"
    assert BL.active_idx("bbae") == 1


# --------------------------------------------------- partial failures

def test_one_dead_login_does_not_hide_the_other(monkeypatch):
    """'partial', which lifecycle.resolve treats as readable-but-incomplete.
    Reporting 'failed' would throw away the accounts that did read; reporting
    'success' would state that a broker holds nothing when we never got in."""
    two_logins(monkeypatch)
    mod = StubBroker(fail_on={"second@x.com"})

    out = BL.fan_out("bbae", mod, mod.get_holdings)

    assert out.state == "partial"
    assert len(out.accounts) == 2
    assert [a.ok for a in out.accounts] == [True, False]
    assert out.extra["logins_ok"] == 1


def test_a_login_that_raises_becomes_its_own_failed_account(monkeypatch):
    """One login blowing up must cost only that login."""
    two_logins(monkeypatch)
    mod = StubBroker()
    calls = {"n": 0}

    def explode():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("chrome would not start")
        return mod.get_holdings()

    out = BL.fan_out("bbae", mod, explode)

    assert out.state == "partial"
    assert out.accounts[0].ok is False
    assert "chrome would not start" in out.accounts[0].message
    assert out.accounts[1].ok is True


def test_every_login_failing_is_a_failure(monkeypatch):
    two_logins(monkeypatch)
    mod = StubBroker(fail_on={"first@x.com", "second@x.com"})
    assert BL.fan_out("bbae", mod, mod.get_holdings).state == "failed"

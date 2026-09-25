"""The day Fidelity re-cased a column and the app said we owned nothing.

Auto-sell reported "SMTK — nothing to sell (no position at Fidelity)" while ten
Fidelity accounts each held a share of it. Nothing had failed: the September
2026 positions export renamed "Account Number" to "Account number", the parser
looked up the old spelling, every one of the 86 rows was dropped for having no
account number, and `_parse_positions_csv` handed back its "(no positions)"
placeholder — ok=True, holdings=[]. `lifecycle.resolve` reads that as a real
empty account, which is the one answer auto-sell believes and does not retry.

Three layers are covered here, because any one of them alone would have let it
through:

  * columns are read by NORMALISED name, so casing and spacing cannot break them
  * a header we genuinely cannot read RAISES, which lands Fidelity in the
    "could not read" bucket (retried) instead of the "no position" one (final)
  * when a broker reports empty and the journal says we hold there, auto-sell
    treats that as a disagreement and refuses to mark the play sold

The CSV bodies here are shaped like the real export, headers included.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import fidelity
import lifecycle


# The header exactly as Fidelity wrote it on 2026-09-08.
NEW_HEADER = ("Account number,Account name,Symbol,Description,Quantity,"
              "Last price,Last price change,Current value\n")
# ...and as it had been written until then.
OLD_HEADER = ("Account Number,Account Name,Symbol,Description,Quantity,"
              "Last Price,Last Price Change,Current Value\n")

ROWS = (
    "Z31914316,Fidelity ETFs,SPAXX**,HELD IN MONEY MARKET,,,,$58.62\n"
    "Z31914316,Fidelity ETFs,SMTK,SMARTKEM INC COM,1,$2.38,+$0.04,$2.38\n"
    "Z32633097,Vanguard ETFs,SMTK,SMARTKEM INC COM,1,$2.38,+$0.04,$2.38\n"
)


def write_csv(tmp_path, header: str, rows: str = ROWS) -> Path:
    p = tmp_path / "Portfolio_Positions_Sep-08-2026.csv"
    p.write_text(header + rows, encoding="utf-8")
    return p


def smtk(acct):
    """The SMTK row on one account. The money-market row rides along with it
    exactly as it did before — that is not what broke."""
    return [h for h in acct.holdings if h.symbol == "SMTK"]


# ------------------------------------------------------------------ parsing

@pytest.mark.parametrize("header", [NEW_HEADER, OLD_HEADER])
def test_both_spellings_of_the_header_read_the_same(tmp_path, header):
    accts = fidelity._parse_positions_csv(write_csv(tmp_path, header))
    assert len(accts) == 2
    assert [len(smtk(a)) for a in accts] == [1, 1]
    assert all(h.shares == 1.0 for a in accts for h in smtk(a))


def test_the_new_casing_still_carries_price_and_value(tmp_path):
    """Not just the account columns: "Last Price" was re-cased too, and a price
    silently read as 0 is how a holding stops counting."""
    accts = fidelity._parse_positions_csv(write_csv(tmp_path, NEW_HEADER))
    (holding,) = smtk(accts[0])
    assert holding.price == 2.38
    # 58.62 of money market + 2.38 of SMTK, both read out of "Current value"
    assert accts[0].extra["account_total_value_calc"] == pytest.approx(61.00)


def test_an_unreadable_header_raises_rather_than_reporting_no_positions(tmp_path):
    """THE POINT OF THE WHOLE FILE.

    A header we cannot parse is not an empty portfolio. Raising sends Fidelity
    to resolve()'s errors bucket, which auto-sell hands back for another try;
    returning an empty account sends it to `missing`, which it believes.
    """
    csv = write_csv(tmp_path, "Fund,Ticker Sym,Units\n", "Roth,SMTK,1\n")
    with pytest.raises(RuntimeError) as e:
        fidelity._parse_positions_csv(csv)
    assert "Account Number" in str(e.value)
    assert "Ticker Sym" in str(e.value)      # says what the file did have


def test_a_position_row_with_no_account_refuses_the_whole_file(tmp_path):
    """The guard for the version of this nobody has thought of yet.

    _check_positions_columns catches a rename we can name. This catches the
    same damage arriving another way — here Fidelity grouping the rows and
    printing the account once per group, which reads as a file full of
    positions belonging to nobody. However it arrives, the damage looks the
    same: rows carrying a symbol that cannot be filed under an account.
    """
    grouped = ("Z31914316,Fidelity ETFs,,,,,,\n"
               ",,SMTK,SMARTKEM INC COM,1,$2.38,+$0.04,$2.38\n")
    with pytest.raises(RuntimeError) as e:
        fidelity._parse_positions_csv(write_csv(tmp_path, NEW_HEADER, grouped))
    assert "no account number" in str(e.value)


def test_footers_are_not_mistaken_for_orphaned_positions(tmp_path):
    """The real export ends in three disclaimer paragraphs and a date line.
    None of them carries a symbol, so none of them can trip the guard — an
    empty portfolio has to stay readable."""
    footer = ('"The data and information in this spreadsheet is provided to you '
              'solely for your use and is not for distribution."\n'
              '"Date downloaded Sep-08-2026 3:10 p.m ET"\n')
    (acct,) = fidelity._parse_positions_csv(write_csv(tmp_path, NEW_HEADER, footer))
    assert acct.ok and acct.holdings == []


def test_an_account_holding_nothing_is_still_an_empty_account(tmp_path):
    """The placeholder is only wrong when it is covering for a parse failure.
    A readable export with no positions in it is genuinely empty."""
    (acct,) = fidelity._parse_positions_csv(write_csv(tmp_path, NEW_HEADER, ""))
    assert acct.ok and acct.holdings == []


def test_the_account_number_never_reaches_a_holdings_extra(tmp_path):
    """The pops were written against the old spelling too."""
    accts = fidelity._parse_positions_csv(write_csv(tmp_path, NEW_HEADER))
    for a in accts:
        for h in a.holdings:
            assert not [k for k in (h.extra or {})
                        if fidelity._norm_col(k) in ("accountnumber", "accountname")]


def test_smart_sell_reads_the_new_casing_too(tmp_path):
    """The sell itself sizes off this file. Fixing only the holdings read would
    have moved the failure from "nothing to sell" to "Smart Sell: no holdings
    found for SMTK"."""
    targets = fidelity._parse_sell_targets_csv(
        write_csv(tmp_path, NEW_HEADER), symbol="SMTK")
    assert len(targets) == 2
    assert all(t["qty"] == 1.0 for t in targets.values())


def test_resolve_prices_the_real_export(tmp_path):
    """End to end over the parser: this is the call that said "no position"."""

    class Out:
        state = "success"
        accounts = fidelity._parse_positions_csv(write_csv(tmp_path, NEW_HEADER))

    task = lifecycle.SellTask(symbol="SMTK", alert_symbol="SMTK",
                              alert_date="2026-09-02", status="exit_called",
                              brokers=("Fidelity",), accounts=2)
    r = lifecycle.resolve(task, {"fidelity": Out()})
    assert r.ok and not r.missing and not r.errors
    (leg,) = r.legs
    assert (leg.qty, leg.accounts) == ("1", 2)


# ------------------------------------------------- the app-level cross-check
#
# App can't be instantiated headlessly, so the real methods run unbound against
# a stub — same approach as test_roundup_sweep.

class Var:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value


class Auto:
    """Just enough App for the "nothing to sell" path."""

    _autosell_fire = A.App._autosell_fire
    _autosell_retry = A.App._autosell_retry
    _autosell_key = A.App._autosell_key
    _journal_disputes = A.App._journal_disputes
    _journal_shortfalls = A.App._journal_shortfalls
    _queue_extend = A.App._queue_extend

    def __init__(self):
        self._queue_busy = True
        self._trade_in_flight = False
        self._autosell_queue: list = []
        self._autosell_sold: set = set()
        self._autosell_fails: dict = {}
        self._autosell_dry_run = Var(False)
        self.logs: list = []
        self.notes: list = []

    def after(self, ms, cb=None, *a):
        return "after#1"

    def _pump_later(self, ms):
        pass

    def _log(self, msg, *_a, **_k):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _save_autosell_state(self):
        pass

    def _autosell_pump(self):
        pass

    def _exit_fire(self, resolved, dry_run=False):
        self.fired = resolved


def empty_read(symbol="SMTK", brokers=("Fidelity",)):
    """What the SMTK read came back as: readable, and holding nothing."""
    task = lifecycle.SellTask(symbol=symbol, alert_symbol=symbol,
                              alert_date="2026-09-02", status="exit_called",
                              brokers=tuple(brokers), accounts=10)
    return lifecycle.ResolvedExit(task=task, legs=(), missing=tuple(brokers))


def test_an_empty_read_the_journal_contradicts_is_not_marked_sold(monkeypatch):
    monkeypatch.setattr(A, "_leg_open_accounts",
                        lambda broker, sym: [(f"acct{i}", 1.0) for i in range(10)])
    app = Auto()
    resolved = empty_read()
    key = app._autosell_key(resolved.task)
    app._autosell_sold.add(key)                 # claimed before the read

    Auto._autosell_fire(app, resolved)

    assert key not in app._autosell_sold
    assert app._autosell_fails[key] == 1
    assert any("journal says we hold" in m for m in app.logs)
    assert any("Fidelity (10 accounts)" in m for m in app.logs)


def test_an_empty_read_the_journal_agrees_with_stays_claimed(monkeypatch):
    """The ordinary case — sold by hand, or swept to cash — must not start
    retrying, or every settled play drives three more broker logins."""
    monkeypatch.setattr(A, "_leg_open_accounts", lambda broker, sym: [])
    app = Auto()
    resolved = empty_read()
    key = app._autosell_key(resolved.task)
    app._autosell_sold.add(key)

    Auto._autosell_fire(app, resolved)

    assert key in app._autosell_sold
    assert key not in app._autosell_fails
    assert not any("journal says we hold" in m for m in app.logs)


def test_a_broker_we_could_not_read_is_still_handed_back(monkeypatch):
    """The pre-existing rule, kept: an unreadable broker retries whether or not
    the journal has anything to say."""
    monkeypatch.setattr(A, "_leg_open_accounts", lambda broker, sym: [])
    app = Auto()
    task = lifecycle.SellTask(symbol="SMTK", alert_symbol="SMTK",
                              alert_date="2026-09-02", status="exit_called",
                              brokers=("Fidelity",), accounts=10)
    resolved = lifecycle.ResolvedExit(task=task, legs=(), errors=("Fidelity",))
    key = app._autosell_key(task)
    app._autosell_sold.add(key)

    Auto._autosell_fire(app, resolved)

    assert key not in app._autosell_sold


def partial_read(found: int, brokers=("Fidelity",)):
    """A read that saw only some of the accounts — the quiet version."""
    task = lifecycle.SellTask(symbol="SMTK", alert_symbol="SMTK",
                              alert_date="2026-09-02", status="exit_called",
                              brokers=tuple(brokers), accounts=10)
    leg = lifecycle.BrokerLeg(broker="Fidelity", key="fidelity", qty="1",
                              accounts=found, low=1.0, high=1.0)
    return lifecycle.ResolvedExit(task=task, legs=(leg,))


def test_a_short_read_still_sells_but_says_so(monkeypatch):
    """Three of ten accounts missing from the export must not pass in silence.
    The order still goes — the seven are real — but the gap is on the record."""
    monkeypatch.setattr(A, "_leg_open_accounts",
                        lambda broker, sym: [(f"acct{i}", 1.0) for i in range(10)])
    app = Auto()
    resolved = partial_read(found=7)

    Auto._autosell_fire(app, resolved)

    assert app.fired is resolved                       # the sell was NOT blocked
    assert any("journal says 10 account(s) open, the read found 7" in m
               for m in app.logs)


def test_a_full_read_says_nothing(monkeypatch):
    """No warning when the two agree, or the log is noise and gets ignored."""
    monkeypatch.setattr(A, "_leg_open_accounts",
                        lambda broker, sym: [(f"acct{i}", 1.0) for i in range(10)])
    app = Auto()

    Auto._autosell_fire(app, partial_read(found=10))

    assert not any("the read found" in m for m in app.logs)


def test_more_found_than_the_journal_knows_is_not_a_shortfall(monkeypatch):
    """The journal only records what this tool bought. Holding the name in an
    account we never traded from is normal and is not a missing account."""
    monkeypatch.setattr(A, "_leg_open_accounts",
                        lambda broker, sym: [("acct0", 1.0)])
    app = Auto()

    Auto._autosell_fire(app, partial_read(found=10))

    assert not any("the read found" in m for m in app.logs)


# ------------------------------------------------------------------ tripwire

REAL_CSVS = sorted(Path(__file__).resolve().parent.parent.glob(
    "sessions/fidelity/downloads_*/Portfolio_Positions_*.csv"))


@pytest.mark.skipif(not REAL_CSVS, reason="no downloaded Fidelity export on this machine")
@pytest.mark.parametrize("path", REAL_CSVS, ids=lambda p: p.parent.name)
def test_the_export_sitting_on_disk_still_parses(path):
    """Run against the LAST FILE FIDELITY ACTUALLY SENT, not a fixture.

    Every other test here proves the parser handles a format we already know
    about, which is exactly the assurance that was worthless in September: the
    fixtures all passed while the real export could not be read at all. This
    one fails the moment the live file stops parsing, whatever they change
    next — so the suite finds it before an exit does.

    Deliberately weak assertions. It is a tripwire, not a portfolio check:
    nothing here depends on which tickers happen to be held today.
    """
    accts = fidelity._parse_positions_csv(path)
    assert accts, f"{path.name} parsed to no accounts at all"
    assert any(a.holdings for a in accts), (
        f"{path.name} parsed {len(accts)} account(s) and not one position — "
        f"if the portfolio really is empty, delete the file")

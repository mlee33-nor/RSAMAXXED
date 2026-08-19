"""The two cash figures that were being parsed and then thrown away.

Fidelity's FCASH row and Chase's Cash positions were both read out of the
broker payload and dropped one line before anything could use them. Recovering
them is what turns "manual entry for every whole-share broker" into "manual for
Wells Fargo and the three small ones".

The risk in both changes is the same and it is not the new number: it is that
cash leaks into the holdings list or into the securities total, which is why
those two are asserted here as hard as the cash itself. Neither broker can be
reached from a test, so these drive the parsing with payloads shaped like the
real ones.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import balances
import fidelity


# --------------------------------------------------------------- fidelity

HEADER = ("Account Number,Account Name,Symbol,Description,Quantity,"
          "Last Price,Current Value\n")


def write_csv(tmp_path, rows: str) -> Path:
    p = tmp_path / "Portfolio_Positions.csv"
    p.write_text(HEADER + rows, encoding="utf-8")
    return p


def test_fcash_becomes_the_accounts_cash(tmp_path):
    csv = write_csv(tmp_path, (
        "Z34671501,Individual,SPY,SPDR S&P 500,2,$770.56,$1541.12\n"
        "Z34671501,Individual,FCASH,CASH,300.00,$1.00,$300.00\n"))
    (acct,) = fidelity._parse_positions_csv(csv)
    assert acct.extra["cash"] == 300.0
    assert acct.extra["cash_source"] == "fcash"


def test_fcash_still_never_appears_as_a_holding(tmp_path):
    """The hard rule the original code existed to enforce. Recovering the
    number must not put the sweep back on the positions list."""
    csv = write_csv(tmp_path, (
        "Z34671501,Individual,SPY,SPDR S&P 500,2,$770.56,$1541.12\n"
        "Z34671501,Individual,FCASH,CASH,300.00,$1.00,$300.00\n"))
    (acct,) = fidelity._parse_positions_csv(csv)
    assert [h.symbol for h in acct.holdings] == ["SPY"]


def test_fcash_is_still_excluded_from_the_securities_total(tmp_path):
    """account_total_value_calc is what the account label shows. Folding cash
    into it would silently restate every Fidelity account's value."""
    csv = write_csv(tmp_path, (
        "Z34671501,Individual,SPY,SPDR S&P 500,2,$770.56,$1541.12\n"
        "Z34671501,Individual,FCASH,CASH,300.00,$1.00,$300.00\n"))
    (acct,) = fidelity._parse_positions_csv(csv)
    assert acct.extra["account_total_value_calc"] == 1541.12
    assert "1541.12" in acct.account_id


def test_an_account_with_no_fcash_row_reports_zero_cash(tmp_path):
    csv = write_csv(tmp_path,
                    "Z34671501,Individual,SPY,SPDR S&P 500,2,$770.56,$1541.12\n")
    (acct,) = fidelity._parse_positions_csv(csv)
    assert acct.extra["cash"] == 0.0


def test_cash_is_kept_per_account_not_pooled(tmp_path):
    csv = write_csv(tmp_path, (
        "Z34671501,Individual,FCASH,CASH,300.00,$1.00,$300.00\n"
        "Z35642087,Fidelity Etf 2,FCASH,CASH,50.00,$1.00,$50.00\n"))
    cash = {a.extra["account_last4"]: a.extra["cash"]
            for a in fidelity._parse_positions_csv(csv)}
    assert cash == {"1501": 300.0, "2087": 50.0}


def test_multiple_fcash_rows_in_one_account_are_summed(tmp_path):
    csv = write_csv(tmp_path, (
        "Z34671501,Individual,FCASH,CASH,300.00,$1.00,$300.00\n"
        "Z34671501,Individual,FCASH,CASH,25.50,$1.00,$25.50\n"))
    (acct,) = fidelity._parse_positions_csv(csv)
    assert acct.extra["cash"] == 325.50


def test_the_recovered_figure_is_the_one_balances_reads(tmp_path):
    """End of the chain: parsed by fidelity.py, keyed by balances.py."""
    csv = write_csv(tmp_path,
                    "Z34671501,Individual,FCASH,CASH,300.00,$1.00,$300.00\n")
    (acct,) = fidelity._parse_positions_csv(csv)
    assert balances.cash_from_extra("fidelity", acct.extra) == 300.0


# --------------------------------------------------------------- chase

def chase_cash_from(positions):
    """Re-run chase.py's own cash accumulation over a position list.

    The loop lives inside a long async get_holdings that cannot be called
    without a browser session, so the arithmetic is exercised here in the same
    form the module uses it -- quantity x price, falling back to quantity when
    a cash line comes back with no price.
    """
    import chase
    total = 0.0
    skipped = 0
    for pos in positions:
        if "Cash" in str(pos.get("instrumentLongName") or ""):
            skipped += 1
            q = chase._as_float(pos.get("tradedUnitQuantity")) or 0.0
            p = chase._as_float((pos.get("marketPrice") or {}).get("baseValueAmount"))
            total += q * p if p else q
    return total, skipped


def test_a_chase_cash_line_with_no_price_is_valued_at_its_quantity():
    total, skipped = chase_cash_from([
        {"instrumentLongName": "Cash", "tradedUnitQuantity": 412.75},
    ])
    assert (total, skipped) == (412.75, 1)


def test_a_chase_cash_line_with_a_price_is_quantity_times_price():
    total, _ = chase_cash_from([
        {"instrumentLongName": "Deposit Cash",
         "tradedUnitQuantity": 100.0,
         "marketPrice": {"baseValueAmount": 1.0}},
    ])
    assert total == 100.0


def test_chase_securities_are_not_counted_as_cash():
    total, skipped = chase_cash_from([
        {"instrumentLongName": "SPDR S&P 500 ETF", "tradedUnitQuantity": 2,
         "marketPrice": {"baseValueAmount": 770.56}},
        {"instrumentLongName": "Cash", "tradedUnitQuantity": 50.0},
    ])
    assert (total, skipped) == (50.0, 1)


def test_chase_cash_lines_are_summed():
    total, skipped = chase_cash_from([
        {"instrumentLongName": "Cash", "tradedUnitQuantity": 10.0},
        {"instrumentLongName": "Cash Sweep", "tradedUnitQuantity": 5.25},
    ])
    assert (total, skipped) == (15.25, 2)


def test_chase_still_skips_cash_from_the_holdings_list():
    """Structural: the `continue` that keeps cash out of `rows` must still be
    the last thing the branch does."""
    src = Path(__file__).resolve().parent.parent.joinpath("chase.py").read_text(
        encoding="utf-8")
    branch = src[src.index('if "Cash" in long_name:'):]
    branch = branch[:branch.index("# --- build symbol ---")]
    assert branch.rstrip().endswith("continue")
    assert "cash_value +=" in branch


def test_the_chase_figure_is_the_one_balances_reads():
    assert balances.cash_from_extra(
        "chase", {"cash": 412.75, "cash_source": "cash_positions"}) == 412.75

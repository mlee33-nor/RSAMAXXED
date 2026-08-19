"""
Turning idle cash into an ETF order plan.

This module is the arithmetic behind the Invest page, and nothing else. No Tk,
no network, no disk — hand it balances and prices, get back a list of orders.
That is deliberate: it is the only part of the feature that can be proved
correct without a broker session, and it is the part that decides how much
money moves.

THE CONSTRAINT EVERYTHING FOLLOWS FROM
--------------------------------------
`execute_trade(*, side, qty, symbol, dry_run)` takes no account parameter. One
call sends the SAME quantity to every account that broker owns. Only Wells Fargo
and Fidelity honour `only_accounts` (see app.RETRYABLE_ACCOUNT_BROKERS); the
other six accept **kwargs and would swallow it and trade everything anyway.

So the unit of a plan is (broker, ticker, shares-per-account) — never
per-account dollars, not even at Public or Robinhood. An account that cannot
afford the uniform quantity does not get a smaller one; it sits the round out.
Every "short" figure this module reports exists to make that visible instead of
letting an order fail at the broker.

There is also no notional/dollar order anywhere in the fleet (chase.py even
hard-codes dollarBasedTradingEligibleIndicator=False), so dollars -> shares is
our arithmetic to do, and rounding it in the wrong direction spends money that
is not there. Everything below rounds DOWN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN
from enum import Enum
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "Capability", "BROKER_CAPABILITY", "capability_for", "buys_fractional",
    "Exposure", "EXPOSURES", "exposure_by_key",
    "Fund", "CATALOG", "TIERS", "funds_in_tier", "fund_by_symbol",
    "catalog_tickers", "plan_ticker", "recommend", "Recommendation",
    "AccountPlan", "BrokerPlan", "Plan", "plan_exposure",
    "qty_text", "FRACTIONAL_PLACES", "MIN_FRACTIONAL_ORDER",
]


# --------------------------------------------------------------------- capability

class Capability(Enum):
    """What quantities a broker's execute_trade will actually accept.

    This is a BUY-side question and it is NOT rsa_feed.FRACTIONAL_BROKERS.
    That tuple answers "who hands back a fractional share after a reverse
    split", which is about what a broker CUSTODIES, not what it will let you
    order. The two overlap enough to look interchangeable and are not:
    SoFi returns fractions and can only buy them below one share.

    Nothing in this module imports rsa_feed, so the two tables can never drift
    into each other by accident.
    """

    FULL = "full"
    """Any fractional quantity. Public keeps a Decimal, Robinhood has a
    dedicated fractional endpoint."""

    SUB_ONE_ONLY = "sub_one"
    """Fractions strictly below 1 share, and only during core hours. SoFi
    routes qty < 1 to an order-fractional endpoint and everything else to a
    whole-share LIMIT order (sofi.py:1871), and refuses fractions outside
    CORE_HOURS (sofi.py:1874). So 0.4 is fine and 1.5 is not."""

    WHOLE_ONLY = "whole"
    """Integers. Fidelity silently truncates with int(float(qty))
    (fidelity.py:3387) — a 0.5 becomes 0 and comes back "Invalid qty" — while
    Chase and Wells Fargo reject outright with "whole shares only"."""

    UNVERIFIED = "unverified"
    """Accepts float(qty) but has no fractional order path anyone has
    exercised. Treated as WHOLE_ONLY: an untested fractional order is worse
    than an under-deployed account, because the failure lands at the broker
    with real money behind it."""


BROKER_CAPABILITY: Dict[str, Capability] = {
    "public":     Capability.FULL,          # public.py:45  Decimal, never rounded
    "robinhood":  Capability.FULL,          # robinhood.py:1132 fractional endpoint
    "sofi":       Capability.SUB_ONE_ONLY,  # sofi.py:1871, :1874
    "fidelity":   Capability.WHOLE_ONLY,    # fidelity.py:3387 int(float(qty))
    "chase":      Capability.WHOLE_ONLY,    # chase.py:1387
    "wellsfargo": Capability.WHOLE_ONLY,    # wellsfargo.py:1538
    "schwab":     Capability.UNVERIFIED,
    "fennel":     Capability.UNVERIFIED,
    "bbae":       Capability.UNVERIFIED,
    "dspac":      Capability.UNVERIFIED,
}

#: Decimal places a fractional order is rounded to. Broker APIs take the
#: quantity as a string and several reject anything longer.
FRACTIONAL_PLACES = 5

#: Below this dollar value an order is not worth placing (and most brokers
#: reject it). Keeps a $0.30 leftover from becoming an order.
MIN_FRACTIONAL_ORDER = Decimal("1.00")

#: How much extra deployment it takes to justify leaving the preferred ticker.
#: Two funds tracking the same index are not equally good — the headline one is
#: bigger and more liquid — so dropping to the cheap equivalent should happen
#: when it genuinely unlocks the account, not to capture the last few dollars
#: of a balance. At 5%, a $300 account moves from SPY to SCHX (which unlocks it
#: entirely) but an $800 target stays on SPY rather than chasing $29 into SPLG.
TIER_TOLERANCE = Decimal("0.05")

_ONE = Decimal("1")
_SUB_ONE_MAX = Decimal("0.99999")


def capability_for(broker: str,
                   *,
                   market_open: bool = True,
                   overrides: Optional[Dict[str, Capability]] = None) -> Capability:
    """Effective capability for this broker right now.

    `market_open` matters for exactly one broker: SoFi cannot place a
    fractional order outside core hours, so out of hours it is a whole-share
    broker and the planner must not hand it a 0.4.
    """
    table = dict(BROKER_CAPABILITY)
    if overrides:
        table.update(overrides)
    cap = table.get(str(broker or "").strip().lower(), Capability.UNVERIFIED)
    if cap is Capability.SUB_ONE_ONLY and not market_open:
        return Capability.WHOLE_ONLY
    return cap


def buys_fractional(cap: Capability) -> bool:
    """True if this capability permits any non-integer quantity at all."""
    return cap in (Capability.FULL, Capability.SUB_ONE_ONLY)


# --------------------------------------------------------------------- catalog

@dataclass(frozen=True)
class Exposure:
    """One thing you can be invested in, and the tickers that deliver it.

    Organised by exposure rather than by ticker because share price is the
    whole problem on a whole-share broker: SPY and SPLG track the same index,
    and at $770 vs $80 only one of them is buyable in an account holding $300.
    `tickers` is ordered most-expensive first purely as documentation of intent
    — the planner sorts by live price, never by this order.
    """

    key: str
    name: str
    blurb: str
    tickers: Tuple[str, ...]


EXPOSURES: Tuple[Exposure, ...] = (
    Exposure(
        key="sp500",
        name="S&P 500",
        blurb="The 500 largest US companies. SPLG and SCHX track the same "
              "index as SPY at a fraction of the share price.",
        tickers=("SPY", "VOO", "IVV", "SPLG", "SCHX"),
    ),
    Exposure(
        key="total_us",
        name="Total US market",
        blurb="Every listed US company, not just the large ones.",
        tickers=("VTI", "ITOT", "SCHB"),
    ),
    Exposure(
        key="nasdaq100",
        name="Nasdaq 100",
        blurb="The large non-financial Nasdaq names — tech-heavy. "
              "QQQM is the same index as QQQ, cheaper per share.",
        tickers=("QQQ", "QQQM"),
    ),
    Exposure(
        key="growth",
        name="US large-cap growth",
        blurb="The growth half of the US large-cap market.",
        tickers=("SCHG",),
    ),
    Exposure(
        key="dividend",
        name="Dividend equity",
        blurb="Established US companies with a sustained dividend record.",
        tickers=("SCHD",),
    ),
    Exposure(
        key="world",
        name="Total world",
        blurb="US and international in one holding.",
        tickers=("VT",),
    ),
)


# --------------------------------------------------------------------- funds

@dataclass(frozen=True)
class Fund:
    """One buyable ETF, filed by what a single share costs.

    Price tier is the organising idea rather than an afterthought, because on a
    whole-share broker the share price IS the constraint: an account holding
    $300 can buy SCHX today and cannot buy SPY at any point this year. Sorting
    the menu by price puts that fact in front of the choice instead of behind
    a failed order.
    """

    symbol: str
    name: str
    tracks: str
    tier: str          # "high" | "mid" | "low"
    exposure: str      # key into EXPOSURES, for the tier-substitution logic


#: Three per tier. Deliberately short: this is a menu, not a screener, and
#: every one of them is a large, liquid, low-fee index fund.
CATALOG: Tuple[Fund, ...] = (
    # High — one share is a few hundred dollars.
    Fund("SPY",  "SPDR S&P 500",            "The 500 largest US companies",  "high", "sp500"),
    Fund("QQQ",  "Invesco QQQ",             "The Nasdaq 100 — tech-heavy",   "high", "nasdaq100"),
    Fund("VOO",  "Vanguard S&P 500",        "The 500 largest US companies",  "high", "sp500"),
    # Mid — reachable by a moderately funded account.
    Fund("VTI",  "Vanguard Total Stock",    "Every listed US company",       "mid",  "total_us"),
    Fund("QQQM", "Invesco Nasdaq 100",      "The Nasdaq 100, cheaper/share", "mid",  "nasdaq100"),
    Fund("VT",   "Vanguard Total World",    "US and international together", "mid",  "world"),
    # Low — buyable in almost any funded account, whole shares included.
    Fund("SPLG", "SPDR Portfolio S&P 500",  "Same index as SPY, ~1/10 price", "low", "sp500"),
    Fund("SCHD", "Schwab US Dividend",      "US companies paying dividends", "low",  "dividend"),
    Fund("SCHX", "Schwab US Large-Cap",     "Same index as SPY, ~1/25 price", "low", "sp500"),
)

TIERS: Tuple[Tuple[str, str, str], ...] = (
    ("high", "Higher priced",
     "A few hundred dollars a share. Fine at Public or Robinhood, which buy "
     "fractions; a whole-share account needs the full price."),
    ("mid", "Mid priced",
     "Reachable by a moderately funded account without going fractional."),
    ("low", "Lower priced",
     "Buyable as whole shares in almost any funded account — the way to get "
     "Fidelity and Wells Fargo invested today."),
)


def funds_in_tier(tier: str) -> Tuple[Fund, ...]:
    return tuple(f for f in CATALOG if f.tier == tier)


def fund_by_symbol(symbol: str) -> Optional[Fund]:
    want = str(symbol or "").strip().upper()
    for f in CATALOG:
        if f.symbol == want:
            return f
    return None


def catalog_tickers() -> Tuple[str, ...]:
    return tuple(f.symbol for f in CATALOG)


def exposure_by_key(key: str) -> Optional[Exposure]:
    for e in EXPOSURES:
        if e.key == key:
            return e
    return None


def all_tickers() -> Tuple[str, ...]:
    """Every ticker in the catalog — what the page needs to quote."""
    seen: List[str] = []
    for e in EXPOSURES:
        for t in e.tickers:
            if t not in seen:
                seen.append(t)
    return tuple(seen)


# --------------------------------------------------------------------- formatting

def qty_text(value: Decimal) -> str:
    """0.04545 -> '0.04545', never '4.545E-2'.

    Broker APIs take the quantity as a string and several reject exponent
    notation outright. lifecycle.qty_text does the same job for the sell side;
    it is duplicated rather than imported so this module stays free of the
    RSA lifecycle code (see the module docstring).
    """
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text in ("", "-0"):
        return "0"
    return text


def _dec(x) -> Decimal:
    if isinstance(x, Decimal):
        return x
    return Decimal(str(x))


def _floor_shares(cash: Decimal, price: Decimal, cap: Capability) -> Decimal:
    """Largest quantity of `price` that `cash` covers, under `cap`'s rules.

    Always rounds DOWN. Rounding a fractional quantity up by one ulp is enough
    to overdraw an account whose whole balance is being deployed.
    """
    if price <= 0 or cash <= 0:
        return Decimal("0")
    raw = cash / price
    if not buys_fractional(cap):
        return raw.to_integral_value(rounding=ROUND_DOWN)
    q = raw.quantize(Decimal(1).scaleb(-FRACTIONAL_PLACES), rounding=ROUND_DOWN)
    if cap is Capability.SUB_ONE_ONLY and q >= _ONE:
        # SoFi's fractional endpoint only takes < 1 share. A whole share is
        # still placeable there, just down the LIMIT path, so floor it.
        return raw.to_integral_value(rounding=ROUND_DOWN)
    return q


# --------------------------------------------------------------------- results

@dataclass
class AccountPlan:
    """What one account can do with the quantity its broker is going to send."""

    broker: str
    account_id: str
    cash: Decimal
    affordable: Decimal          # what this account could buy on its own
    participates: bool           # can it cover the uniform order quantity?
    deployed: Decimal            # qty * price, 0 when sitting out
    leftover: Decimal            # cash it still holds afterwards
    shortfall: Decimal           # dollars needed to join, 0 when participating
    source: str = ""             # where its cash figure came from
    note: str = ""

    @property
    def progress(self) -> float:
        """0..1 toward affording one unit of the chosen ticker. Only
        meaningful for an account sitting the round out."""
        need = self.cash + self.shortfall
        if need <= 0:
            return 1.0
        return float(min(_ONE, self.cash / need))


@dataclass
class BrokerPlan:
    """One order: `qty` shares of `ticker`, sent once, landing on every account."""

    broker: str
    capability: Capability
    ticker: str
    price: Decimal
    qty: Decimal
    accounts: List[AccountPlan] = field(default_factory=list)
    skipped_reason: str = ""

    @property
    def participating(self) -> List[AccountPlan]:
        return [a for a in self.accounts if a.participates]

    @property
    def short(self) -> List[AccountPlan]:
        return [a for a in self.accounts if not a.participates]

    @property
    def deployed(self) -> Decimal:
        return sum((a.deployed for a in self.accounts), Decimal("0"))

    @property
    def idle(self) -> Decimal:
        return sum((a.leftover for a in self.accounts), Decimal("0"))

    @property
    def actionable(self) -> bool:
        return bool(self.qty > 0 and self.participating)

    @property
    def per_account(self) -> Decimal:
        """Dollars each participating account puts in.

        The page leads with this rather than the share count. Nobody holds a
        mental model of 0.02686 shares; everybody holds one of $20.69, and the
        quantity is an artefact of the broker API taking shares rather than
        dollars."""
        return self.qty * self.price

    @property
    def leftover_each(self) -> Decimal:
        """What a participating account still holds afterwards. Zero-ish at a
        fractional broker, and the whole point at a whole-share one."""
        rows = self.participating
        if not rows:
            return Decimal("0")
        return sum((a.leftover for a in rows), Decimal("0")) / len(rows)

    @property
    def advisory(self) -> str:
        """A warning when uniform quantity is costing more than it is worth.

        One order goes to every account, so the smallest participating balance
        decides the size of it. When balances are close together that is
        barely visible; when they are not, a single small account can hold the
        whole broker to a token order — five accounts holding $6,630 between
        them deploying $152 because one of them has $50. The page says so
        rather than reporting a healthy-looking plan that quietly left almost
        everything in cash.
        """
        if not self.actionable or self.idle <= 0:
            return ""
        if self.deployed * 4 < self.idle:
            smallest = min((a for a in self.participating),
                           key=lambda a: a.cash, default=None)
            who = f" ({smallest.account_id}, ${smallest.cash:,.2f})" if smallest else ""
            return (f"${self.idle:,.2f} stays in cash — the smallest "
                    f"participating account{who} caps the order for all "
                    f"{len(self.participating)}.")
        return ""

    def order(self) -> Tuple[str, str, str]:
        """(broker, ticker, qty-as-string) — exactly what execute_trade wants."""
        return (self.broker, self.ticker, qty_text(self.qty))


@dataclass
class Plan:
    exposure: Exposure
    mode: str
    target_per_account: Optional[Decimal]
    brokers: List[BrokerPlan] = field(default_factory=list)

    @property
    def actionable(self) -> List[BrokerPlan]:
        return [b for b in self.brokers if b.actionable]

    @property
    def deployed(self) -> Decimal:
        return sum((b.deployed for b in self.brokers), Decimal("0"))

    @property
    def idle(self) -> Decimal:
        return sum((b.idle for b in self.brokers), Decimal("0"))

    @property
    def account_count(self) -> int:
        return sum(len(b.participating) for b in self.brokers)

    @property
    def short_count(self) -> int:
        return sum(len(b.short) for b in self.brokers)

    def orders(self) -> List[Tuple[str, str, str]]:
        return [b.order() for b in self.actionable]


# --------------------------------------------------------------------- planner

def _plan_one_broker(broker: str,
                     accounts: Sequence[Tuple[str, Decimal, str]],
                     ticker: str,
                     price: Decimal,
                     cap: Capability,
                     mode: str,
                     target: Optional[Decimal]) -> BrokerPlan:
    """Build the plan for a single (broker, ticker) pair.

    `mode` is either:
      "target"  every account buys the same fixed dollar amount, so the
                quantity is decided by the target and an account either
                affords it or sits out. Predictable, and what the page
                defaults to.
      "max"     deploy as much as possible. The quantity is the MINIMUM
                affordable across participating accounts, because the order
                goes to all of them and the poorest one decides what fits.
                This is the same rule lifecycle.resolve uses for fractional
                sells, for the same reason: an order bigger than the account
                can honour is simply rejected.
    """
    per_account = [(aid, _dec(cash), src) for aid, cash, src in accounts]

    if price <= 0:
        return BrokerPlan(broker=broker, capability=cap, ticker=ticker,
                          price=price, qty=Decimal("0"),
                          accounts=[AccountPlan(broker, aid, cash, Decimal("0"),
                                                False, Decimal("0"), cash,
                                                Decimal("0"), src)
                                    for aid, cash, src in per_account],
                          skipped_reason="no quote")

    affordable = {aid: _floor_shares(cash, price, cap)
                  for aid, cash, _src in per_account}

    if mode == "target" and target is not None and target > 0:
        qty = _floor_shares(target, price, cap)
    else:
        usable = [q for q in affordable.values() if q > 0]
        qty = min(usable) if usable else Decimal("0")

    # An order has to be worth placing. Both branches can land on a sliver.
    if qty > 0 and qty * price < MIN_FRACTIONAL_ORDER:
        qty = Decimal("0")

    if cap is Capability.SUB_ONE_ONLY and 0 < qty < _ONE:
        qty = min(qty, _SUB_ONE_MAX)

    cost = qty * price
    rows: List[AccountPlan] = []
    for aid, cash, src in per_account:
        joins = bool(qty > 0 and cash >= cost)
        rows.append(AccountPlan(
            broker=broker,
            account_id=aid,
            cash=cash,
            affordable=affordable[aid],
            participates=joins,
            deployed=cost if joins else Decimal("0"),
            leftover=(cash - cost) if joins else cash,
            shortfall=Decimal("0") if joins else max(Decimal("0"), cost - cash),
            source=src,
        ))

    plan = BrokerPlan(broker=broker, capability=cap, ticker=ticker,
                      price=price, qty=qty, accounts=rows)
    if qty <= 0:
        plan.skipped_reason = ("no account can afford a share of "
                               f"{ticker} at ${price:,.2f}")
    elif not plan.participating:
        plan.skipped_reason = "every account is short of the order amount"
    return plan


def plan_exposure(exposure: Exposure,
                  balances: Dict[str, Dict[str, object]],
                  prices: Dict[str, object],
                  *,
                  mode: str = "target",
                  target_per_account: Optional[object] = None,
                  brokers: Optional[Iterable[str]] = None,
                  market_open: bool = True,
                  capability_overrides: Optional[Dict[str, Capability]] = None,
                  ticker_override: Optional[Dict[str, str]] = None) -> Plan:
    """Plan a buy of `exposure` across the fleet.

    balances: {broker: {account_id: cash}} — cash may be a number or a dict
              carrying {"cash": ..., "source": ...}.
    prices:   {ticker: price}. Tickers with no price are skipped, so a Yahoo
              miss narrows the choice instead of planning against a guess.

    Ticker choice per broker: a fractional broker deploys essentially all of
    the cash whatever the share price, so it keeps the headline ticker. A
    whole-share broker is limited by the share price itself, so it walks the
    catalog in preference order and takes the first tier that gets within
    TIER_TOLERANCE of the most money any tier could put to work.
    """
    target = _dec(target_per_account) if target_per_account is not None else None
    # Catalog order, not price order — exposure.tickers is a preference list
    # (headline fund first), and the tier choice below reads it as one.
    priced: List[Tuple[str, Decimal]] = []
    for t in exposure.tickers:
        p = prices.get(t)
        if p is None:
            continue
        d = _dec(p)
        if d > 0:
            priced.append((t, d))

    wanted = ([b.strip().lower() for b in brokers]
              if brokers is not None else sorted(balances))

    out: List[BrokerPlan] = []
    for broker in wanted:
        accts_raw = balances.get(broker) or {}
        accounts: List[Tuple[str, Decimal, str]] = []
        for aid, val in accts_raw.items():
            if isinstance(val, dict):
                cash = val.get("cash")
                src = str(val.get("source") or "")
            else:
                cash, src = val, ""
            if cash is None:
                continue
            accounts.append((str(aid), _dec(cash), src))

        cap = capability_for(broker, market_open=market_open,
                             overrides=capability_overrides)

        if not accounts:
            out.append(BrokerPlan(broker=broker, capability=cap,
                                  ticker=priced[0][0] if priced else "",
                                  price=priced[0][1] if priced else Decimal("0"),
                                  qty=Decimal("0"),
                                  skipped_reason="no cash on record"))
            continue
        if not priced:
            out.append(BrokerPlan(broker=broker, capability=cap, ticker="",
                                  price=Decimal("0"), qty=Decimal("0"),
                                  skipped_reason="no quote for this exposure"))
            continue

        forced = (ticker_override or {}).get(broker)
        if forced:
            chosen = [tp for tp in priced if tp[0] == forced] or priced[:1]
            candidates = chosen[:1]
        elif buys_fractional(cap):
            candidates = priced[:1]           # headline; price is not a barrier
        else:
            candidates = priced

        built = [_plan_one_broker(broker, accounts, ticker, price, cap,
                                  mode, target)
                 for ticker, price in candidates]
        # Participation first, dollars second.
        #
        # Ranking on dollars alone picks the tier that serves whichever
        # account happens to be richest: across balances of
        # {50, 300, 1200, 5000, 80} it chose SPY, which two accounts could
        # afford, over SCHX, which all five could — banking more dollars while
        # leaving three accounts out entirely. That is the opposite of why a
        # cheap equivalent is offered at all. Among the tiers that include the
        # most accounts, the catalog order then wins unless a later tier
        # deploys meaningfully more (TIER_TOLERANCE).
        reach = max((len(c.participating) for c in built), default=0)
        widest = [c for c in built if len(c.participating) == reach] or built
        ceiling = max((c.deployed for c in widest), default=Decimal("0"))
        floor_ = ceiling * (_ONE - TIER_TOLERANCE)
        best = next((c for c in widest if c.deployed >= floor_), widest[0])
        out.append(best)

    return Plan(exposure=exposure, mode=mode, target_per_account=target,
                brokers=out)


# --------------------------------------------------------------------- picking

def plan_ticker(symbol: str,
                balances: Dict[str, Dict[str, object]],
                prices: Dict[str, object],
                **kw) -> Plan:
    """Plan one specific fund across the fleet.

    The "I'll choose" path. Unlike plan_exposure it does not substitute a
    cheaper tier when an account cannot reach the price — if you pick SPY, the
    accounts that cannot afford SPY are reported short rather than quietly
    bought something else. Being overruled without being told is worse than
    being told you cannot have it.
    """
    symbol = str(symbol or "").strip().upper()
    fund = fund_by_symbol(symbol)
    exp = Exposure(key=f"ticker:{symbol}",
                   name=fund.name if fund else symbol,
                   blurb=fund.tracks if fund else "",
                   tickers=(symbol,))
    return plan_exposure(exp, balances, prices, **kw)


@dataclass
class Recommendation:
    """A suggested fund, and the sentence explaining why it was suggested."""

    fund: Optional[Fund]
    plan: Optional[Plan]
    reason: str
    reach: int = 0
    total_accounts: int = 0
    alternatives: List[Tuple["Fund", int]] = field(default_factory=list)


def recommend(balances: Dict[str, Dict[str, object]],
              prices: Dict[str, object],
              *,
              mode: str = "max",
              target_per_account: Optional[object] = None,
              brokers: Optional[Iterable[str]] = None,
              market_open: bool = True,
              funds: Optional[Sequence[Fund]] = None) -> Recommendation:
    """Suggest one fund for the whole fleet, chosen by how many accounts it
    actually reaches.

    Reach first, because an account that cannot afford a share is an account
    that stays in cash. Among funds that reach the same number, the one that
    deploys more money wins, and the catalog order breaks the remaining ties so
    the answer is stable between refreshes rather than flipping between two
    near-identical funds as prices move by a cent.

    Returns a plan alongside the pick so the caller never has to recompute it,
    and the runners-up so the page can say what the alternative would have been.
    """
    considered: List[Tuple[Fund, Plan, int, Decimal]] = []
    for fund in (funds or CATALOG):
        if prices.get(fund.symbol) is None:
            continue
        plan = plan_ticker(fund.symbol, balances, prices, mode=mode,
                           target_per_account=target_per_account,
                           brokers=brokers, market_open=market_open)
        reach = plan.account_count
        considered.append((fund, plan, reach, plan.deployed))

    if not considered:
        return Recommendation(None, None,
                              "No prices yet — refresh quotes to get a "
                              "recommendation.")

    total_accounts = max(
        (sum(len(b.accounts) for b in p.brokers) for _f, p, _r, _d in considered),
        default=0)
    best_reach = max(r for _f, _p, r, _d in considered)
    if best_reach == 0:
        cheapest = min(considered, key=lambda c: prices_of(c[0], prices))
        return Recommendation(
            None, None,
            f"No account can afford a whole share of anything on the list — "
            f"the cheapest is {cheapest[0].symbol} at "
            f"${float(_dec(prices[cheapest[0].symbol])):,.2f}. Add cash, or "
            f"check the balances below are right.",
            0, total_accounts)

    widest = [c for c in considered if c[2] == best_reach]
    ceiling = max(d for _f, _p, _r, d in widest)
    floor_ = ceiling * (_ONE - TIER_TOLERANCE)
    fund, plan, reach, _deployed = next(
        (c for c in widest if c[3] >= floor_), widest[0])

    others = sorted((c for c in considered if c[0].symbol != fund.symbol),
                    key=lambda c: (-c[2], -float(c[3])))[:3]
    return Recommendation(
        fund=fund, plan=plan,
        reason=(f"{fund.symbol} reaches {reach} of your {total_accounts} "
                f"account(s) and puts ${plan.deployed:,.2f} to work"
                + (f" — {others[0][0].symbol} would reach {others[0][2]}."
                   if others and others[0][2] != reach else ".")),
        reach=reach, total_accounts=total_accounts,
        alternatives=[(f, r) for f, _p, r, _d in others])


def prices_of(fund: Fund, prices: Dict[str, object]) -> float:
    try:
        return float(_dec(prices.get(fund.symbol) or 0))
    except Exception:
        return 0.0

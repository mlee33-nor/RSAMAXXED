# modules/brokers/public/public.py
from __future__ import annotations

import os
import random
import re
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from zoneinfo import ZoneInfo

import broker_logins
from modules.broker_logging import log_exception, write_log
from modules.outputs import AccountOutput, BrokerOutput, HoldingRow

BROKER = "public"
API_BASE = "https://api.public.com"
VALIDITY_MINUTES = 15  # hard default


# =============================================================================
# Logging
# =============================================================================

def _log_ctx() -> dict:
    root = Path(__file__).resolve().parent
    return {"log_dir": root / "logs"}


# =============================================================================
# Env + small utils
# =============================================================================

def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _safe_last4(x: str) -> str:
    x = (x or "").strip()
    return x[-4:] if len(x) >= 4 else (x or "----")


def _to_decimal_qty(qty: str) -> Decimal:
    try:
        d = Decimal(str(qty).strip())
    except (InvalidOperation, AttributeError):
        raise ValueError(f"Invalid qty: {qty!r}")
    if d <= 0:
        raise ValueError("qty must be > 0")
    return d


def _fmt_decimal(d: Decimal) -> str:
    s = format(d, "f")
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s or "0"


def _money(d: Optional[Decimal]) -> str:
    if d is None:
        return "?"
    try:
        return f"${float(d):.2f}"
    except Exception:
        return "?"


def _as_decimal(v: Any) -> Optional[Decimal]:
    if v is None:
        return None
    try:
        return Decimal(str(v))
    except Exception:
        return None


def _as_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(str(v))
    except Exception:
        return None


def _load_public_secrets() -> List[Tuple[int, str]]:
    """Every configured Public login, as (idx, token), skipping blanks.

    Numbered tokens: PUBLIC_SECRET_TOKEN_1, _2, _3, _4, ...

    THE COUNT USED TO BE THREE, spelled `for i in (1, 2, 3)`, and a household
    running two people's accounts hit that ceiling immediately — a fourth token
    could be saved and was then read by nothing, which looks exactly like a
    broken login. broker_logins scans the whole range instead.

    It also PRESERVES THE INDEX rather than closing gaps: a blank token 2 with
    a token 3 set still yields 3, because Public builds its account labels out
    of this number ("Public 3 BROKERAGE (1234)") and that string is the key
    trades.json nets buys against sells on. Renumbering here would orphan every
    open position at the renumbered login.
    """
    return [(login.idx, login.get("token"))
            for login in broker_logins.logins("public")]


def _state_from_counts(ok_ct: int, fail_ct: int) -> str:
    if ok_ct > 0 and fail_ct == 0:
        return "success"
    if ok_ct == 0 and fail_ct > 0:
        return "failed"
    if ok_ct == 0 and fail_ct == 0:
        return "failed"
    return "partial"


def _validate_trade_inputs(
    side: str, qty: str, symbol: str
) -> Tuple[str, str, str, Optional[BrokerOutput]]:
    side_norm = (side or "").strip().lower()
    if side_norm not in ("buy", "sell"):
        return "", "", "", BrokerOutput(
            broker=BROKER, state="failed", message=f"Invalid side: {side!r}", accounts=[]
        )

    try:
        qty_d = _to_decimal_qty(qty)
    except Exception as e:
        return "", "", "", BrokerOutput(broker=BROKER, state="failed", message=str(e), accounts=[])

    sym = (symbol or "").strip().upper()
    if not sym:
        return "", "", "", BrokerOutput(broker=BROKER, state="failed", message="Invalid symbol", accounts=[])

    api_side = "BUY" if side_norm == "buy" else "SELL"
    qty_s = _fmt_decimal(qty_d)
    return api_side, qty_s, sym, None


# =============================================================================
# Public client
# =============================================================================

class _OrderMayExist(RuntimeError):
    """The order POST went out but its outcome is unknown. The message carries
    the "submitted ... verify" wording that keeps the app from re-sending it."""


class _PublicClient:
    """
    Minimal Public REST client with short-lived access tokens.
    """

    def __init__(self, *, secret: str, validity_minutes: int = VALIDITY_MINUTES):
        self.secret = secret
        self.validity_minutes = max(1, int(validity_minutes))
        self._access_token: Optional[str] = None
        self._access_expiry_epoch: float = 0.0

    def _requests(self):
        try:
            import requests  # type: ignore
        except Exception as e:
            import sys
            raise RuntimeError(
                f"Missing dependency: requests.\n"
                f"Install with: {sys.executable} -m pip install requests"
            ) from e
        return requests

    def _refresh_access_token_if_needed(self) -> None:
        now = time.time()
        if self._access_token and now < (self._access_expiry_epoch - 120):
            return

        requests = self._requests()
        url = f"{API_BASE}/userapiauthservice/personal/access-tokens"
        payload = {"secret": self.secret, "validityInMinutes": self.validity_minutes}

        r = requests.post(url, json=payload, timeout=30)
        if r.status_code >= 400:
            raise RuntimeError(f"Token exchange failed: HTTP {r.status_code} - {r.text}")

        data = r.json() or {}
        token = data.get("accessToken")
        if not token:
            raise RuntimeError("Token exchange failed: missing accessToken in response")

        self._access_token = token
        self._access_expiry_epoch = now + (self.validity_minutes * 60)

    def _headers(self) -> Dict[str, str]:
        self._refresh_access_token_if_needed()
        return {"Authorization": f"Bearer {self._access_token}"}

    def get_accounts(self) -> List[Dict[str, Any]]:
        requests = self._requests()
        url = f"{API_BASE}/userapigateway/trading/account"
        r = requests.get(url, headers=self._headers(), timeout=30)
        if r.status_code >= 400:
            raise RuntimeError(f"Account fetch failed: HTTP {r.status_code} - {r.text}")
        return (r.json() or {}).get("accounts", []) or []

    def get_portfolio_v2(self, account_id: str) -> Dict[str, Any]:
        requests = self._requests()
        url = f"{API_BASE}/userapigateway/trading/{account_id}/portfolio/v2"
        r = requests.get(url, headers=self._headers(), timeout=30)
        if r.status_code >= 400:
            raise RuntimeError(f"Portfolio fetch failed: HTTP {r.status_code} - {r.text}")
        return r.json() or {}

    def place_equity_market_order(
        self,
        *,
        account_id: str,
        side: str,
        symbol: str,
        quantity: str,
        market_session: str = "CORE",
        tif: str = "DAY",
        order_id: Optional[str] = None,
    ) -> str:
        requests = self._requests()
        url = f"{API_BASE}/userapigateway/trading/{account_id}/order"
        oid = order_id or str(uuid.uuid4())

        body: Dict[str, Any] = {
            "orderId": oid,
            "instrument": {"symbol": symbol, "type": "EQUITY"},
            "orderSide": side,
            "orderType": "MARKET",
            "expiration": {"timeInForce": tif},
            "quantity": quantity,
        }
        if market_session:
            body["equityMarketSession"] = market_session

        try:
            headers = self._headers()   # token refresh: before anything is sent
        except Exception as e:
            raise RuntimeError(f"Public sign-in refresh failed ({e}) — nothing was sent") from e
        try:
            r = requests.post(url, json=body, headers=headers, timeout=30)
        except requests.exceptions.ConnectTimeout as e:
            # Never connected, so the order never left this machine.
            raise RuntimeError(f"Order not sent: could not reach Public ({e})") from e
        except Exception as e:
            # A read timeout or dropped connection: the POST went out and
            # Public may well have taken it.
            raise _OrderMayExist(
                f"Public did not answer after the order may have been submitted "
                f"({type(e).__name__}: {e}) — verify in Public before retrying") from e
        if r.status_code >= 500:
            raise _OrderMayExist(
                f"Public returned HTTP {r.status_code} after the order may have been "
                f"submitted ({r.text[:200]}) — verify in Public before retrying")
        if r.status_code >= 400:
            raise RuntimeError(f"Order failed: HTTP {r.status_code} - {r.text}")

        try:
            data = r.json() or {}
        except Exception:
            # 2xx: Public accepted it, the body just didn't parse. We chose
            # the orderId ourselves, so we still know which order it is.
            data = {}
        return (data.get("orderId") if isinstance(data, dict) else None) or oid


# =============================================================================
# In-memory client cache (Legacy analogue: keep session warm)
# =============================================================================

_CLIENTS: Dict[int, _PublicClient] = {}


def _get_client_for_secret(idx: int, secret: str) -> _PublicClient:
    """
    Reuse clients across commands so access-token caching persists (session stays warm).
    """
    c = _CLIENTS.get(idx)
    if c is not None and getattr(c, "secret", None) == secret:
        return c
    c = _PublicClient(secret=secret, validity_minutes=VALIDITY_MINUTES)
    _CLIENTS[idx] = c
    return c


def _ensure_clients() -> Tuple[bool, str, List[Tuple[int, _PublicClient, List[Dict[str, Any]]]]]:
    """
    Legacy-style "ensure":
      - validates env secrets exist
      - validates each secret can exchange token + fetch accounts
      - returns clients + accounts for downstream calls
    """
    pairs = _load_public_secrets()
    if not pairs:
        return False, "Missing PUBLIC_SECRET_TOKEN_1 (and _2, _3, ... for more logins)", []

    ready: List[Tuple[int, Any, Any]] = []
    last_err = ""

    # A login that fails is KEPT, as (idx, None, reason). It used to be
    # dropped, so a dead token's accounts simply vanished from the result --
    # no row, no failure, nothing for Retry -- and when every login failed the
    # callers returned accounts=[], which the app counted as no failure at
    # all. Callers turn these entries into one ok=False "Public <idx>" row.
    any_ok = False
    for idx, secret in pairs:
        try:
            client = _get_client_for_secret(idx, secret)
            accounts = client.get_accounts()
            if not isinstance(accounts, list):
                raise RuntimeError("unexpected accounts response")
            ready.append((idx, client, accounts))
            any_ok = True
        except Exception as e:
            last_err = str(e)
            ready.append((idx, None, last_err or "Auth failed"))

    if not any_ok:
        return False, (last_err or "Auth failed"), ready
    return True, "ok", ready


def _failed_login_row(idx: int, reason: Any, **extra: Any) -> AccountOutput:
    """One row for a Public login that could not sign in. Nothing was sent."""
    text = f"Public login {idx} failed: {reason}"
    if "nothing was sent" not in text.lower():
        text += " — nothing was sent"
    return AccountOutput(account_id=f"Public {idx}", ok=False, message=text, **extra)


_CAP_LABEL = re.compile(r"^Public\s+\d+\s+(.+?)\s+\(([^()]{4})\)$")


def _cap_key(label: str) -> Optional[Tuple[str, str]]:
    """("BROKERAGE", "0001") from "Public 2 BROKERAGE (0001)" -- the account's
    identity without the login number, which moves when .env is reordered."""
    m = _CAP_LABEL.match(str(label or "").strip())
    return (m.group(1).strip().upper(), m.group(2)) if m else None


def _match_caps(caps: Dict[str, Decimal], labels: List[str],
                fallback: bool = True) -> Dict[str, str]:
    """account label -> the caps key that applies to it.

    The exact label first. Failing that, the same account type and last 4
    under a different login number: caps are keyed by the label each buy was
    journaled under, "Public {login#} {type} ({last4})", and moving a token in
    .env renumbers the logins -- every account then read as "not ours", was
    silently left unsold, and the late-round-up check was marked done. The
    fallback only takes a pair that is unique on both sides, so it can never
    hand one account another account's cap.

    Unique among the labels that were READ, though: with login 1 down, its
    account is not in `labels`, and a login-2 account of the same type and
    last 4 looked unique and took login 1's cap. So `fallback=False` -- the
    caller passes it unless every configured login answered -- takes exact
    labels only.
    """
    out: Dict[str, str] = {}
    used = set()
    for lab in labels:
        if lab in caps:
            out[lab] = lab
            used.add(lab)
    if not fallback:
        return out
    by_key: Dict[Tuple[str, str], List[str]] = {}
    for k in caps:
        if k in used:
            continue
        ck = _cap_key(k)
        if ck:
            by_key.setdefault(ck, []).append(k)
    acct_keys: Dict[Tuple[str, str], List[str]] = {}
    for lab in labels:
        ck = _cap_key(lab)
        if ck:
            acct_keys.setdefault(ck, []).append(lab)
    for lab in labels:
        if lab in out:
            continue
        ck = _cap_key(lab)
        if ck and len(by_key.get(ck, [])) == 1 and len(acct_keys.get(ck, [])) == 1:
            out[lab] = by_key[ck][0]
    return out


def _failed_login_rows(ready: List[Tuple[int, Any, Any]], **extra: Any) -> List[AccountOutput]:
    return [_failed_login_row(idx, reason, **extra)
            for idx, client, reason in ready if client is None]


# =============================================================================
# Normalizers (raw API -> normalized model)
# =============================================================================

def _portfolio_value_from_equity(equity: Any) -> Optional[Decimal]:
    if not isinstance(equity, list):
        return None
    total = Decimal("0")
    seen = False
    for e in equity:
        if not isinstance(e, dict):
            continue
        dv = _as_decimal(e.get("value"))
        if dv is None:
            continue
        total += dv
        seen = True
    return total if seen else None


def _held_by_symbol(client: Any, account_id: str,
                    symbols: Tuple[str, ...]) -> Dict[str, Decimal]:
    """This account's position in each of `symbols`, read from Public right now.

    Per SYMBOL, not summed. After a rename an account can list the position
    under the old ticker or the new one, and an order has to go out under the
    ticker that actually holds the shares -- adding the two together and
    selling the total under the new name asks that ticker for shares it does
    not have.

    Decimal from the raw quantity string, never through float: a fractional
    remnant like 0.03333 has to go back to Public exactly as Public reported
    it, or the sell asks for a hair more than the account holds and is refused.
    Raises if the portfolio cannot be read -- the caller must not mistake a
    failed read for an empty account.
    """
    pf = client.get_portfolio_v2(account_id)
    held: Dict[str, Decimal] = {s: Decimal("0") for s in symbols}
    for p in pf.get("positions") or []:
        if not isinstance(p, dict):
            continue
        inst = p.get("instrument") or {}
        sym = str((inst.get("symbol") if isinstance(inst, dict) else "") or "").strip().upper()
        if sym not in held:
            continue
        q = _as_decimal(p.get("quantity"))
        if q is not None and q > 0:
            held[sym] += q
    return held


def _holdings_from_positions(positions: Any) -> List[HoldingRow]:
    """
    Convert Public's portfolio positions payload into universal HoldingRow objects.

    Discovery mode (safe): we capture additional *scalar* fields into HoldingRow.extra so we
    can later decide what to standardize universally.

    NOTE: We intentionally avoid storing full nested objects/lists to keep the snapshot small
    and JSON-safe.
    """
    if not isinstance(positions, list) or not positions:
        return []

    def _is_scalar(v: Any) -> bool:
        return v is None or isinstance(v, (str, int, float, bool))

    def _safe_num(v: Any) -> Any:
        # Keep ints/bools, coerce numeric strings/Decimals-like to float when possible.
        if v is None or isinstance(v, (int, float, bool)):
            return v
        if isinstance(v, str):
            s = v.strip()
            try:
                return float(s)
            except Exception:
                return s
        # Decimal or other numeric-ish objects
        try:
            return float(v)
        except Exception:
            return str(v)

    out: List[HoldingRow] = []
    for p in positions:
        if not isinstance(p, dict):
            continue

        inst = p.get("instrument") or {}
        if not isinstance(inst, dict):
            inst = {}

        sym = (inst.get("symbol") or "?").strip().upper() or "?"
        sh = _as_float(p.get("quantity"))

        lp_obj = p.get("lastPrice") or {}
        if not isinstance(lp_obj, dict):
            lp_obj = {}
        px = _as_float(lp_obj.get("lastPrice"))

        extra: Dict[str, Any] = {
            "_position_keys": sorted([str(k) for k in p.keys()]),
        }

        # instrument scalar fields
        for k, v in inst.items():
            if k == "symbol":
                continue
            if _is_scalar(v):
                extra[f"instrument_{k}"] = v
            elif isinstance(v, dict):
                for k2, v2 in v.items():
                    if _is_scalar(v2):
                        extra[f"instrument_{k}_{k2}"] = v2

        # lastPrice scalar fields
        for k, v in lp_obj.items():
            if k == "lastPrice":
                continue
            if _is_scalar(v):
                extra[f"lastPrice_{k}"] = v
            elif isinstance(v, dict):
                for k2, v2 in v.items():
                    if _is_scalar(v2):
                        extra[f"lastPrice_{k}_{k2}"] = v2

        # top-level position scalar fields (excluding ones already used)
        for k, v in p.items():
            if k in ("instrument", "lastPrice", "quantity"):
                continue
            if _is_scalar(v):
                extra[str(k)] = _safe_num(v)
            elif isinstance(v, dict):
                # one-level flatten for small dicts
                for k2, v2 in v.items():
                    if _is_scalar(v2):
                        extra[f"{k}_{k2}"] = _safe_num(v2)

        out.append(HoldingRow(symbol=sym, shares=sh, price=px, extra=extra))

    return out


# =============================================================================
# Bootstrap / healthcheck (compat only; no "login" concept)
# =============================================================================

def bootstrap(*args, **kwargs) -> BrokerOutput:
    """
    Compatibility shim:
      - validates that secret token(s) can exchange for access token
      - validates we can fetch accounts successfully

    Returns a BrokerOutput (success/failed) like every other broker so GUI/CLI
    callers can read ``output.state`` — returning None here previously crashed
    the GUI with "'NoneType' object has no attribute 'state'" on a valid key.
    """
    return healthcheck(*args, **kwargs)


def healthcheck(*args, **kwargs) -> BrokerOutput:
    """
    Deprecated in orchestration (no longer used).
    Keep as a non-interactive probe for manual/testing usage.
    """
    ctx = _log_ctx()
    ok, msg, ready = _ensure_clients()

    accs: List[AccountOutput] = []
    if not ok:
        log_exception(ctx, broker=BROKER, action="healthcheck", label="fatal", exc=RuntimeError(msg))
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=(_failed_login_rows(ready)
                      or [AccountOutput(account_id="Public", ok=False, message=msg)]),
            message=msg,
        )

    # Per-secret status lines
    for idx, _client, accounts in ready:
        if _client is None:
            accs.append(_failed_login_row(idx, accounts))
            continue
        label = f"Public {idx}"
        accs.append(AccountOutput(account_id=label, ok=True, message=f"ok (accounts={len(accounts)})"))

        write_log(
            ctx,
            broker=BROKER,
            action="healthcheck",
            label=str(idx),
            text=f"OK: accounts={len(accounts)}",
        )

    ok_ct = sum(1 for a in accs if a.ok)
    return BrokerOutput(broker=BROKER, state=_state_from_counts(ok_ct, len(accs) - ok_ct),
                        accounts=accs, message="ok")


# =============================================================================
# DRY RUN logging (Public)
# =============================================================================

_ET = ZoneInfo("America/New_York")

def _logs_root_dir() -> Path:
    return Path(__file__).resolve().parent

def _dry_run_log_dir() -> Path:
    d = datetime.now(_ET).strftime("%m.%d.%y")
    p = _logs_root_dir() / "logs" / BROKER / d
    p.mkdir(parents=True, exist_ok=True)
    return p

def _write_dry_run_log(*, content: str) -> str:
    rand = uuid.uuid4().hex[:10]
    path = _dry_run_log_dir() / f"test_order_{BROKER}_{rand}.log"
    path.write_text(content, encoding="utf-8")
    return str(path)

def _build_public_market_order_body(
    *,
    order_id: str,
    side: str,
    symbol: str,
    quantity: str,
    market_session: str = "CORE",
    tif: str = "DAY",
) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "orderId": order_id,
        "instrument": {"symbol": symbol, "type": "EQUITY"},
        "orderSide": side,
        "orderType": "MARKET",
        "expiration": {"timeInForce": tif},
        "quantity": quantity,
    }
    if market_session:
        body["equityMarketSession"] = market_session
    return body

def _format_preview_ticket(*, endpoint_path: str, body: Dict[str, Any]) -> str:
    inst = body.get("instrument") or {}
    exp = body.get("expiration") or {}
    lines = [
        "DRY RUN payload:",
        f"  endpoint: {endpoint_path}",
        f"  side: {body.get('orderSide')}",
        f"  symbol: {inst.get('symbol')}",
        f"  qty: {body.get('quantity')}",
        f"  type: {body.get('orderType')}",
        f"  tif: {exp.get('timeInForce')}",
        f"  session: {body.get('equityMarketSession', 'CORE')}",
        f"  orderId: {body.get('orderId')}",
    ]
    return "\n".join(lines)


# =============================================================================
# Executors (contract outputs only)
# =============================================================================

def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False,
                  size_from_holdings: bool = False, remnant_only: bool = False,
                  also_symbols: Tuple[str, ...] = (),
                  max_by_account: Optional[Dict[str, str]] = None,
                  **kwargs) -> BrokerOutput:
    """Place one market order per Public account.

    SELLING WHAT IS ACTUALLY THERE (`size_from_holdings`, sells only)

    One `qty` for every account is right for a buy and wrong for an exit. A
    reverse split credits each account whatever fraction Public decides, a
    fractional sell can leave 0.98 behind, and an account may hold nothing at
    all. Sending the same number to all of them strands shares in the accounts
    that hold more and gets rejected in the ones that hold less. So each
    account's position is read the moment before its order, and that account
    sells what it holds; `qty` is ignored. An account holding nothing is
    skipped, not sent an order it would reject. A read that fails is a failed
    account, never "holds nothing".

    CAPPED AT WHAT THIS TOOL BOUGHT (`max_by_account`, required)

    "What it holds" is not "what we bought". An account that held 100 IPDN
    before RSAMAXXED bought it 1 more holds 101, and an exit is an instruction
    about OUR share, not the customer's own position. So every account sells
    min(held, cap), where the cap is the caller's figure for what this tool
    bought there (label -> Decimal string, labels exactly as built below). An
    account missing from the map is skipped: we never bought there, or we are
    already out. The map is required rather than optional because the uncapped
    version sells a customer's entire position on our say-so, and a caller that
    forgot to pass it has to fail loudly, not do that.

    `remnant_only` additionally skips any account holding a whole share or
    more. It is for an exit called at OTHER brokerages while Public returned a
    fraction: the fraction is dead weight to clear, but a whole share here is a
    position that waits for its own exit.

    `also_symbols` are other tickers the same position may be listed under
    (the pre-split name after a rename). The account is sized from `symbol`
    alone; only if it holds nothing under `symbol` is an old ticker tried, and
    then the order goes out under THAT ticker -- the one the shares are really
    listed under. The ticker sold is returned in `extra["symbol"]`.

    Accounts sold this way carry the quantity actually sent in
    `extra["qty"]`, so the journal records what was sold rather than `qty`.
    """
    ok, msg, ready = _ensure_clients()
    sized = bool(size_from_holdings) and str(side or "").strip().lower() == "sell"

    def _login_failed(idx: int, reason: Any) -> AccountOutput:
        row = _failed_login_row(idx, reason)
        if sized:
            # Same words as a failed per-account read, so the exit batch
            # hands the play back exactly as it does for that.
            row.message = f"Could not read the position before selling: {row.message}"
        return row

    if not ok:
        return BrokerOutput(broker=BROKER, state="failed", message=msg,
                            accounts=[_login_failed(i, r) for i, c, r in ready if c is None])

    # Holdings-sized sells ignore `qty`, so only they may arrive without one.
    # A buy or a plain sell with a blank quantity is a caller bug and keeps
    # failing validation exactly as it always did.
    sized_sell = bool(size_from_holdings) and str(side or "").strip().lower() == "sell"
    api_side, qty_s, sym, err = _validate_trade_inputs(
        side, (qty or "1") if sized_sell else qty, symbol)
    if err:
        return err
    per_account = sized_sell
    caps: Dict[str, Decimal] = {}
    if per_account:
        if max_by_account is None:
            return BrokerOutput(
                broker=BROKER, state="failed", accounts=[],
                message="Holdings-sized sell refused: no per-account cap was "
                        "given, and selling every account's whole position "
                        "could sell shares RSAMAXXED never bought.")
        for label, cap in max_by_account.items():
            d = _as_decimal(cap)
            if d is not None and d > 0:
                caps[str(label).strip()] = d
    symbols = tuple(dict.fromkeys(
        [sym] + [str(s).strip().upper() for s in also_symbols if str(s).strip()]))
    skipped: List[str] = []
    # Why accounts were skipped, counted, so the app can say "nothing to sell
    # -- 21 whole shares wait for their own exit" instead of "failed".
    skip_kinds: Dict[str, int] = {}

    outs: List[AccountOutput] = []
    log_sections: List[str] = []
    _acct_i = 0

    # Which cap belongs to which account (see _match_caps), and which caps
    # found their account: one that found none is reported, never dropped.
    cap_for: Dict[str, str] = {}
    caps_used: set = set()
    if per_account:
        all_labels = [
            f"Public {pi} {(a.get('accountType') or '').strip() or 'ACCOUNT'} "
            f"({_safe_last4((a.get('accountId') or '').strip())})"
            for pi, c, accts in ready if c is not None
            for a in (accts or []) if isinstance(a, dict)]
        # The renumbered-login fallback only when every login was read: an
        # unread login's accounts are missing from all_labels, so "unique"
        # there proves nothing (see _match_caps).
        every_login_read = all(c is not None and accts for _pi, c, accts in ready)
        cap_for = _match_caps(caps, all_labels, fallback=every_login_read)

    log_sections.append("DRY RUN — NO ORDER SUBMITTED" if dry_run else "LIVE ORDER MODE")
    log_sections.append(f"broker: {BROKER}")
    log_sections.append(f"requested: side={api_side} symbol={sym} qty={qty_s}")
    log_sections.append(f"time_et: {datetime.now(_ET).isoformat()}")
    log_sections.append("")

    for pub_idx, client, accounts in ready:
        if client is None:
            outs.append(_login_failed(pub_idx, accounts))
            continue
        if not accounts:
            outs.append(AccountOutput(
                account_id=f"Public {pub_idx} (auth)",
                ok=False,
                message="No accounts returned for this login.",
                order_id=None,
            ))
            continue

        for acct in accounts:
            if _acct_i > 0:
                time.sleep(random.uniform(1.0, 3.0))
            _acct_i += 1

            acct_id = (acct.get("accountId") or "").strip()
            acct_type = (acct.get("accountType") or "").strip() or "ACCOUNT"
            acct_label = f"Public {pub_idx} {acct_type} ({_safe_last4(acct_id)})"

            if not acct_id:
                outs.append(AccountOutput(
                    account_id=acct_label,
                    ok=False,
                    message="Missing accountId in API response",
                    order_id=None,
                ))
                continue

            acct_qty = qty_s
            order_sym = sym
            extra: Optional[Dict[str, Any]] = None
            if per_account:
                cap_label = cap_for.get(acct_label)
                cap = caps.get(cap_label) if cap_label else None
                if cap_label:
                    caps_used.add(cap_label)
                if cap is None:
                    # Checked before the read: an account we have no share in
                    # is not ours to sell, whatever it holds, so there is no
                    # reason to spend a portfolio call finding out.
                    skipped.append(f"{acct_label}: not bought through RSAMAXXED, "
                                   f"or already sold")
                    skip_kinds["not_ours"] = skip_kinds.get("not_ours", 0) + 1
                    continue
                try:
                    by_sym = _held_by_symbol(client, acct_id, symbols)
                except Exception as e:
                    outs.append(AccountOutput(
                        account_id=acct_label, ok=False,
                        message=f"Could not read the position before selling: {e}",
                        order_id=None,
                    ))
                    continue
                # The ticker being sold first; an old name only when the
                # account shows nothing at all under the new one.
                held = by_sym.get(sym, Decimal("0"))
                if held <= 0:
                    for alt in symbols[1:]:
                        if by_sym.get(alt, Decimal("0")) > 0:
                            held, order_sym = by_sym[alt], alt
                            break
                if held <= 0:
                    skipped.append(f"{acct_label}: holds none")
                    skip_kinds["none"] = skip_kinds.get("none", 0) + 1
                    continue
                if remnant_only and held >= 1:
                    skipped.append(f"{acct_label}: holds {_fmt_decimal(held)}, "
                                   f"a whole share - waits for its own exit")
                    skip_kinds["whole"] = skip_kinds.get("whole", 0) + 1
                    continue
                acct_qty = _fmt_decimal(min(held, cap))
                extra = {"qty": acct_qty, "symbol": order_sym}

            endpoint_path = f"/userapigateway/trading/{acct_id}/order"
            oid = str(uuid.uuid4())
            body = _build_public_market_order_body(
                order_id=oid,
                side=api_side,
                symbol=order_sym,
                quantity=acct_qty,
                market_session="CORE",
                tif="DAY",
            )
            ticket = _format_preview_ticket(endpoint_path=endpoint_path, body=body)

            if dry_run:
                outs.append(AccountOutput(account_id=acct_label, ok=True, message=ticket,
                                          order_id=oid, extra=extra))
                log_sections.append(f"[{acct_label}]")
                log_sections.append(ticket)
                log_sections.append("")
                continue

            try:
                order_id = client.place_equity_market_order(
                    account_id=acct_id,
                    side=api_side,
                    symbol=order_sym,
                    quantity=acct_qty,
                    market_session="CORE",
                    tif="DAY",
                    order_id=oid,
                )
                placed = ("order placed" if not per_account
                          else f"order placed ({acct_qty} sh {order_sym})")
                outs.append(AccountOutput(account_id=acct_label, ok=True, message=placed,
                                          order_id=str(order_id) if order_id else oid, extra=extra))
            except Exception as e:
                outs.append(AccountOutput(account_id=acct_label, ok=False, message=str(e), order_id=None))

    if per_account:
        failed_logins = [pi for pi, c, _a in ready if c is None]
        for cap_label in caps:
            if cap_label in caps_used:
                continue
            # Shares this tool bought in an account no signed-in login shows:
            # a renamed or reordered login, or one that did not sign in.
            # Unsold either way, so never a clean "nothing to sell".
            why = ("its login did not sign in" if failed_logins
                   else "no Public login shows this account — check the Public tokens in .env")
            outs.append(AccountOutput(
                account_id=cap_label, ok=False, order_id=None,
                message=f"Skipped: could not find this account to sell ({why}) — nothing was sent"))

    ok_ct = sum(1 for a in outs if a.ok)
    fail_ct = sum(1 for a in outs if not a.ok)
    state = _state_from_counts(ok_ct, fail_ct)
    # Nothing to sell anywhere is an answer, not a failure: every account was
    # read and none held a sellable balance. The skips say why.
    if per_account and not outs and skipped:
        state = "success"

    broker_msg = ""
    if skipped:
        broker_msg = f"skipped {len(skipped)}: " + "; ".join(skipped)
    if dry_run:
        log_path = _write_dry_run_log(content="\n".join(log_sections).rstrip() + "\n")
        broker_msg = (f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}"
                      + (f" | {broker_msg}" if broker_msg else ""))

    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=broker_msg,
                        extra={"skipped": dict(skip_kinds)} if skip_kinds else None)


def get_accounts(*args, **kwargs) -> BrokerOutput:
    ok, msg, ready = _ensure_clients()
    if not ok:
        return BrokerOutput(broker=BROKER, state="failed", message=msg,
                            accounts=_failed_login_rows(ready))

    outs: List[AccountOutput] = []

    for pub_idx, client, accounts in ready:
        if client is None:
            outs.append(_failed_login_row(pub_idx, accounts))
            continue
        if not accounts:
            outs.append(AccountOutput(account_id=f"Public {pub_idx} (auth)", ok=False, message="No accounts returned for this login."))
            continue

        for acct in accounts:
            acct_id = (acct.get("accountId") or "").strip()
            acct_type = (acct.get("accountType") or "").strip() or "ACCOUNT"
            acct_label = f"Public {pub_idx} {acct_type} ({_safe_last4(acct_id)})"

            if not acct_id:
                outs.append(AccountOutput(account_id=acct_label, ok=False, message="Missing accountId in API response"))
                continue

            try:
                pf = client.get_portfolio_v2(acct_id)
                buying_power = pf.get("buyingPower") or {}
                if not isinstance(buying_power, dict):
                    buying_power = {}

                bp = _as_decimal(buying_power.get("buyingPower"))
                cash_bp = _as_decimal(buying_power.get("cashOnlyBuyingPower"))


                buying_power = pf.get("buyingPower") or {}
                if not isinstance(buying_power, dict):
                    buying_power = {}

                bp = _as_decimal(buying_power.get("buyingPower"))
                cash_bp = _as_decimal(buying_power.get("cashOnlyBuyingPower"))

                equity = pf.get("equity") or []
                pv = _portfolio_value_from_equity(equity)

                positions = pf.get("positions") or []
                pos_ct = len(positions) if isinstance(positions, list) else 0

                msg2 = f"PV={_money(pv)} BP={_money(bp)} Cash={_money(cash_bp)} | {pos_ct} positions"
                outs.append(AccountOutput(account_id=acct_label, ok=True, message=msg2))

            except Exception as e:
                outs.append(AccountOutput(account_id=acct_label, ok=False, message=str(e)))

    ok_ct = sum(1 for a in outs if a.ok)
    fail_ct = sum(1 for a in outs if not a.ok)
    return BrokerOutput(broker=BROKER, state=_state_from_counts(ok_ct, fail_ct), accounts=outs, message="")


def get_holdings(*args, **kwargs) -> BrokerOutput:
    ok, msg, ready = _ensure_clients()
    if not ok:
        return BrokerOutput(broker=BROKER, state="failed", message=msg,
                            accounts=_failed_login_rows(ready, holdings=[]))

    outs: List[AccountOutput] = []
    total_value = Decimal("0")
    total_value_seen = False

    for pub_idx, client, accounts in ready:
        if client is None:
            outs.append(_failed_login_row(pub_idx, accounts, holdings=[]))
            continue
        if not accounts:
            outs.append(AccountOutput(account_id=f"Public {pub_idx} (auth) = ?", ok=False, message="No accounts returned for this login.", holdings=[]))
            continue

        for acct in accounts:
            acct_id = (acct.get("accountId") or "").strip()
            acct_type = (acct.get("accountType") or "").strip() or "ACCOUNT"
            base_label = f"Public {pub_idx} {acct_type} ({_safe_last4(acct_id)})"

            if not acct_id:
                outs.append(AccountOutput(account_id=f"{base_label} = ?", ok=False, message="Missing accountId in API response", holdings=[]))
                continue

            try:
                pf = client.get_portfolio_v2(acct_id)
                buying_power = pf.get("buyingPower") or {}
                if not isinstance(buying_power, dict):
                    buying_power = {}

                bp = _as_decimal(buying_power.get("buyingPower"))
                cash_bp = _as_decimal(buying_power.get("cashOnlyBuyingPower"))


                equity = pf.get("equity") or []
                pv = _portfolio_value_from_equity(equity)

                if pv is not None:
                    total_value += pv
                    total_value_seen = True

                acct_value_str = _money(pv)

                positions = pf.get("positions") or []
                holdings = _holdings_from_positions(positions)

                pos_ct = len(positions) if isinstance(positions, list) else 0

                account_extra: Dict[str, Any] = {
                    "portfolio_value": float(pv) if pv is not None else None,
                    "buying_power": float(bp) if bp is not None else None,
                    "cash_only_buying_power": float(cash_bp) if cash_bp is not None else None,
                    "positions_count": int(pos_ct),
                }


                outs.append(AccountOutput(account_id=f"{base_label} = {acct_value_str}", ok=True, message="", holdings=holdings, extra=account_extra))

            except Exception as e:
                outs.append(AccountOutput(account_id=f"{base_label} = ?", ok=False, message=str(e), holdings=[]))

    ok_ct = sum(1 for a in outs if a.ok)
    fail_ct = sum(1 for a in outs if not a.ok)
    state = _state_from_counts(ok_ct, fail_ct)

    total_line = f"Total Value = ${float(total_value):.2f}" if total_value_seen else "Total Value = ?"
    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=total_line, extra={"total_value": float(total_value) if total_value_seen else None})
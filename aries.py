"""Aries (aries.com) — stocks over Aries' REST API (docs: finance.dev).

ONE KEY, NO BROWSER

In Aries' Client Center the user goes to the API tab and clicks Generate Key.
That gives a personal client (Client ID ``ARI-PERSONAL-TK.…``) and a Client
Secret. Both are pasted on the Brokers page; nothing else is needed. The
client_credentials grant turns them into a 15-minute bearer token that acts as
that user, refreshed here whenever it is close to expiring. No login page, no
2FA, no Chrome.

The key must carry the trading scopes, chosen when it is generated:
``account:information``, ``position:information``, ``order:execution`` and
``order:information``. A key without them signs in fine and is then refused
(HTTP 403) on the first order -- the message says which scope to add.

WHAT AN ORDER IS

One DAY market order per account, the same shape every other broker here
sends:  POST /v1/orders  {tradingAccountId, symbol, side, type=MARKET, qty,
timeInForce=DAY, clientId}. Before it, POST /v1/orders/preview is asked what
the order costs; blocking ``errors`` there stop the order (nothing is sent),
and any commission or fee it quotes is written on the result row so a fee is
never silent. A preview that cannot be read does not hold the order up.

WHEN THE ANSWER IS LOST

Aries documents no idempotency key, so an order whose answer never came back
(read timeout, dropped connection, 5xx, the documented 504 "broker timeout,
outcome unknown") is reported with the app's may-exist wording -- "submitted
… verify" -- and is never retried automatically. Only a failure before the
request left this machine, or a 4xx refusal, says "nothing was sent".

SELLS NEVER OPEN A SHORT

A market SELL is checked against the account's live position first; an
account holding fewer shares than asked is skipped with nothing sent.

ACCOUNT LABELS

"Aries (1234)" -- the last four of the trading account id, more digits only
if two accounts would otherwise read alike. A simulation (paper) account is
"Aries SIM (1234)" and is skipped unless ARIES_USE_SIM=1, so a paper fill can
never net against a live position in the journal. Login 2 and up carry
broker_logins' prefix ("Aries 2 · Aries (1234)"); login 1 never does.
"""
from __future__ import annotations

import os
import random
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from zoneinfo import ZoneInfo

import broker_logins
from modules.broker_logging import write_log
from modules.outputs import AccountOutput, BrokerOutput, HoldingRow

BROKER = "aries"
DISPLAY = "Aries"
API_BASE = os.getenv("ARIES_API_BASE", "").strip().rstrip("/") or "https://api.aries.com"

TOKEN_TIMEOUT = 20
READ_TIMEOUT = 20
ORDER_TIMEOUT = 30
#: How long after an order to look for its status (a rejection such as
#: EXCHANGE_CLOSED can arrive after the HTTP answer said NEW).
CONFIRM_WAIT = 4.0

SCOPES_NEEDED = ("account:information", "position:information",
                 "order:execution", "order:information")

_ET = ZoneInfo("America/New_York")


# =============================================================================
# small utils
# =============================================================================

def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _log_ctx() -> dict:
    return {"log_dir": _root_dir() / "logs"}


def _trace(msg: str) -> None:
    try:
        write_log(_log_ctx(), broker=BROKER, action="trace", label="aries",
                  text=str(msg))
    except Exception:
        pass


def _dec(v: Any) -> Optional[Decimal]:
    if v is None or v == "":
        return None
    try:
        return Decimal(str(v).strip())
    except (InvalidOperation, ValueError):
        return None


def _float(v: Any) -> Optional[float]:
    d = _dec(v)
    return float(d) if d is not None else None


def _fmt(d: Decimal) -> str:
    s = format(d, "f")
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s or "0"


def _not_sent(msg: str) -> str:
    msg = str(msg or "").strip() or "Aries failed"
    return msg if "nothing was sent" in msg.lower() else f"{msg} — nothing was sent"


def _verify(why: str) -> str:
    """The may-exist wording: the app never re-sends these by itself."""
    return (f"{why} — the order may have been submitted; verify in Aries "
            f"(app → Orders) before retrying")


def _sim_allowed() -> bool:
    return os.getenv("ARIES_USE_SIM", "").strip().lower() in ("1", "true", "yes")


def _state_from_counts(ok_ct: int, fail_ct: int) -> str:
    if ok_ct > 0 and fail_ct == 0:
        return "success"
    if ok_ct > 0:
        return "partial"
    return "failed"


def _short(text: Any, n: int = 240) -> str:
    t = re.sub(r"\s+", " ", str(text or "")).strip()
    return t if len(t) <= n else t[:n] + "…"


def _err_text(r: Any) -> str:
    """Aries' error body, flat or nested, as one short line."""
    try:
        body = r.json()
    except Exception:
        return _short(getattr(r, "text", ""))
    if isinstance(body, dict):
        e = body.get("error")
        if isinstance(e, dict):
            return _short(e.get("message") or e.get("code") or e)
        for k in ("error", "message", "error_description", "text", "ordRejReason"):
            if body.get(k):
                return _short(body.get(k))
    return _short(body)


_NOT_SET_UP = ("Aries isn't set up — on the Brokers page paste the Client ID and "
               "Client Secret from Aries' Client Center → API → Generate Key")


# =============================================================================
# client
# =============================================================================

class _SignInFailed(RuntimeError):
    pass


class _AriesClient:
    """Aries REST with a cached client_credentials token."""

    def __init__(self, *, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._expires = 0.0
        self._lock = threading.Lock()

    def _requests(self):
        import requests  # type: ignore
        return requests

    def _ensure_token(self) -> str:
        with self._lock:
            now = time.time()
            if self._token and now < self._expires - 60:
                return self._token
            rq = self._requests()
            try:
                r = rq.post(f"{API_BASE}/v1/oauth2/token",
                            data={"grant_type": "client_credentials",
                                  "client_id": self.client_id,
                                  "client_secret": self.client_secret},
                            timeout=TOKEN_TIMEOUT)
            except Exception as e:
                raise _SignInFailed(f"could not reach Aries to sign in ({type(e).__name__})") from e
            if r.status_code >= 400:
                why = _err_text(r)
                if r.status_code in (400, 401, 403):
                    raise _SignInFailed(
                        f"Aries refused the API key (HTTP {r.status_code}: {why}) — check the "
                        f"Client ID and Client Secret; it must be a personal key")
                raise _SignInFailed(f"Aries sign-in failed: HTTP {r.status_code} {why}")
            data = r.json() or {}
            tok = data.get("access_token")
            if not tok:
                raise _SignInFailed("Aries sign-in returned no access token")
            try:
                ttl = float(data.get("expires_in") or 900)
            except (TypeError, ValueError):
                ttl = 900.0
            self._token, self._expires = tok, now + max(60.0, ttl)
            self.scopes = str(data.get("scope") or "")
            return tok

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._ensure_token()}",
                "Accept": "application/json"}

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        rq = self._requests()
        r = rq.get(f"{API_BASE}{path}", headers=self._headers(), params=params,
                   timeout=READ_TIMEOUT)
        if r.status_code == 401:            # token revoked early: once more
            with self._lock:
                self._token = None
            r = rq.get(f"{API_BASE}{path}", headers=self._headers(), params=params,
                       timeout=READ_TIMEOUT)
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {_err_text(r)}"
                               + (_scope_hint(path) if r.status_code == 403 else ""))
        return r.json() or {}

    # -- reads ---------------------------------------------------------------

    def accounts(self) -> List[Dict[str, Any]]:
        data = self._get("/v2/users/me/accounts")
        accts = data.get("accounts") if isinstance(data, dict) else None
        return [a for a in (accts or []) if isinstance(a, dict)]

    def positions(self, account_id: str) -> List[Dict[str, Any]]:
        data = self._get(f"/v1/accounts/{account_id}/positions")
        pos = data.get("positions") if isinstance(data, dict) else None
        return [p for p in (pos or []) if isinstance(p, dict)]

    def balance(self, account_id: str) -> Dict[str, Any]:
        data = self._get(f"/v2/accounts/{account_id}/balance")
        return data if isinstance(data, dict) else {}

    def find_order(self, account_id: str, cl_ord_id: str = "",
                   client_tag: str = "") -> Optional[Dict[str, Any]]:
        """Today's order with this clOrdId (or our clientId tag), from the
        active list first and then today's history."""
        def match(o: Dict[str, Any]) -> bool:
            return bool((cl_ord_id and o.get("clOrdId") == cl_ord_id)
                        or (client_tag and o.get("clientId") == client_tag))
        try:
            act = self._get(f"/v2/accounts/{account_id}/orders", {"limit": 100})
            for o in (act.get("orders") or []) if isinstance(act, dict) else []:
                if isinstance(o, dict) and match(o):
                    return o
        except Exception:
            pass
        since = (datetime.now(timezone.utc) - timedelta(hours=18)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        try:
            hist = self._get(f"/v2/accounts/{account_id}/orders/history",
                             {"from": since, "limit": 100, "order_by": "desc"})
            for o in (hist.get("orders") or []) if isinstance(hist, dict) else []:
                if isinstance(o, dict) and match(o):
                    return o
        except Exception:
            pass
        return None

    # -- orders --------------------------------------------------------------

    def preview(self, body: Dict[str, Any]) -> Dict[str, Any]:
        rq = self._requests()
        r = rq.post(f"{API_BASE}/v1/orders/preview", json=body,
                    headers=self._headers(), timeout=READ_TIMEOUT)
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {_err_text(r)}")
        data = r.json() or {}
        return data if isinstance(data, dict) else {}

    def place(self, body: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """("ok"|"refused"|"may_exist"|"not_sent", detail). Never raises."""
        rq = self._requests()
        try:
            headers = self._headers()         # sign-in before anything is sent
        except Exception as e:
            return "not_sent", {"why": f"Aries sign-in failed ({e})"}
        try:
            r = rq.post(f"{API_BASE}/v1/orders", json=body, headers=headers,
                        timeout=ORDER_TIMEOUT)
        except Exception as e:
            if _never_connected(rq, e):
                return "not_sent", {"why": f"could not reach Aries ({type(e).__name__})"}
            # A read timeout or a connection dropped mid-request: the order
            # went out and Aries may well have taken it.
            return "may_exist", {"why": f"Aries did not answer ({type(e).__name__})"}
        if r.status_code >= 500:
            return "may_exist", {"why": f"Aries returned HTTP {r.status_code} "
                                        f"({_err_text(r)})"}
        if r.status_code >= 400:
            why = f"HTTP {r.status_code}: {_err_text(r)}"
            if r.status_code == 403:
                why += _scope_hint("/v1/orders")
            return "refused", {"why": why}
        try:
            data = r.json() or {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        return "ok", data


_NO_CONNECTION = ("NewConnectionError", "NameResolutionError",
                  "Failed to establish a new connection", "getaddrinfo failed")


def _never_connected(rq: Any, e: BaseException) -> bool:
    """True only when the request provably never reached Aries."""
    exc = getattr(rq, "exceptions", None)
    if exc is None:
        return False
    if isinstance(e, getattr(exc, "ConnectTimeout", ())):
        return True
    if isinstance(e, getattr(exc, "ReadTimeout", ())):
        return False
    return isinstance(e, getattr(exc, "ConnectionError", ())) and \
        any(s in repr(e) for s in _NO_CONNECTION)


def _scope_hint(path: str) -> str:
    need = ("order:execution" if "/orders" in path and "history" not in path
            else "position:information" if "positions" in path
            else "account:information")
    return (f" — the API key may be missing the {need} scope; generate a new key "
            f"in Aries' Client Center with {', '.join(SCOPES_NEEDED)}")


_CLIENTS: Dict[int, _AriesClient] = {}
_CLIENTS_LOCK = threading.Lock()


def _client_for(idx: int, cid: str, secret: str) -> _AriesClient:
    with _CLIENTS_LOCK:
        c = _CLIENTS.get(idx)
        if c is None or c.client_id != cid or c.client_secret != secret:
            c = _AriesClient(client_id=cid, client_secret=secret)
            _CLIENTS[idx] = c
        return c


# =============================================================================
# logins and accounts
# =============================================================================

class _Login:
    def __init__(self, idx: int, prefix: str, client: Optional[_AriesClient],
                 problem: str = ""):
        self.idx = idx
        self.prefix = prefix
        self.client = client
        self.problem = problem
        self.accounts: List[Tuple[str, str]] = []      # (trading_account_id, label)
        self.skipped_sim = 0

    @property
    def name(self) -> str:
        """The row that stands for this whole login: 'Aries', 'Aries 2'."""
        return DISPLAY if self.idx == 1 else f"{DISPLAY} {self.idx}"


def _labels(prefix: str, accts: List[Tuple[str, bool]]) -> Dict[str, str]:
    """trading_account_id -> label; more digits only where two would clash."""
    ids = list(dict.fromkeys(a for a, _sim in accts))
    sim = {a: s for a, s in accts}
    keep = {a: 4 for a in ids}
    while True:
        lab = {a: f"{prefix}{DISPLAY}{' SIM' if sim[a] else ''} "
                  f"({a[-keep[a]:] if len(a) > keep[a] else a})" for a in ids}
        seen: Dict[str, int] = {}
        for v in lab.values():
            seen[v] = seen.get(v, 0) + 1
        clash = [a for a in ids if seen[lab[a]] > 1 and keep[a] < len(a)]
        if not clash:
            return lab
        for a in clash:
            keep[a] += 1


def _logins() -> List[_Login]:
    """Every configured Aries login, signed in, with its accounts listed."""
    out: List[_Login] = []
    for login in broker_logins.logins(BROKER):
        cid, secret = login.get("client_id"), login.get("client_secret")
        lg = _Login(login.idx, login.label_prefix, None)
        if not (cid and secret):
            lg.problem = _not_sent(f"{lg.name}: Client ID and Client Secret are both needed")
            out.append(lg)
            continue
        client = _client_for(login.idx, cid, secret)
        lg.client = client
        try:
            raw = client.accounts()
        except Exception as e:
            lg.problem = _not_sent(f"{lg.name} login failed: {_short(e)}")
            out.append(lg)
            continue
        usable: List[Tuple[str, bool]] = []
        for a in raw:
            tid = str(a.get("trading_account_id") or "").strip()
            status = str(a.get("status") or "").strip().upper()
            is_sim = bool(a.get("is_sim"))
            if not tid or (status and status != "OPEN"):
                continue
            if is_sim and not _sim_allowed():
                lg.skipped_sim += 1
                continue
            usable.append((tid, is_sim))
        labels = _labels(lg.prefix, usable)
        lg.accounts = [(tid, labels[tid]) for tid, _s in usable]
        if not lg.accounts:
            lg.problem = _not_sent(
                f"{lg.name}: no open live accounts on this key"
                + (f" ({lg.skipped_sim} paper account"
                   f"{'s' if lg.skipped_sim != 1 else ''} skipped — set ARIES_USE_SIM=1 "
                   f"to trade paper)" if lg.skipped_sim else ""))
        out.append(lg)
    return out


# =============================================================================
# bootstrap / holdings
# =============================================================================

def bootstrap(*args, **kwargs) -> BrokerOutput:
    """Sign in with each key and list its accounts (one row each)."""
    lgs = _logins()
    if not lgs:
        return BrokerOutput(broker=BROKER, state="failed", message=_NOT_SET_UP,
                            accounts=[AccountOutput(account_id=DISPLAY, ok=False,
                                                    message=_NOT_SET_UP)])
    outs: List[AccountOutput] = []
    for lg in lgs:
        if lg.problem:
            outs.append(AccountOutput(account_id=lg.name, ok=False, message=lg.problem))
            continue
        for _tid, label in lg.accounts:
            outs.append(AccountOutput(account_id=label, ok=True,
                                      message="connected via Aries API"))
    ok_ct = sum(1 for a in outs if a.ok)
    state = _state_from_counts(ok_ct, len(outs) - ok_ct)
    msg = (f"ok ({ok_ct} account{'s' if ok_ct != 1 else ''})" if state == "success"
           else "; ".join(a.message for a in outs if not a.ok))
    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg)


def healthcheck(*args, **kwargs) -> BrokerOutput:
    return bootstrap(*args, **kwargs)


def get_accounts(*args, **kwargs) -> BrokerOutput:
    return bootstrap(*args, **kwargs)


def _holding_rows(positions: List[Dict[str, Any]]) -> List[HoldingRow]:
    rows: List[HoldingRow] = []
    for p in positions:
        if str(p.get("securityType") or "EQUITY").upper() != "EQUITY":
            continue
        qty = _float(p.get("quantity"))
        if not qty:
            continue
        rows.append(HoldingRow(
            symbol=str(p.get("symbol") or "?").strip().upper() or "?",
            shares=qty,
            price=_float(p.get("price")),
            extra={"avg_cost": _float(p.get("averagePrice")),
                   "market_value": _float(p.get("marketValue")),
                   "cost_basis": _float(p.get("costBasis"))}))
    return rows


def get_holdings(*args, **kwargs) -> BrokerOutput:
    lgs = _logins()
    if not lgs:
        return BrokerOutput(broker=BROKER, state="failed", message=_NOT_SET_UP,
                            accounts=[AccountOutput(account_id=DISPLAY, ok=False,
                                                    message=_NOT_SET_UP)])
    outs: List[AccountOutput] = []
    for lg in lgs:
        if lg.problem:
            outs.append(AccountOutput(account_id=lg.name, ok=False, message=lg.problem))
            continue
        for tid, label in lg.accounts:
            try:
                holdings = _holding_rows(lg.client.positions(tid))
            except Exception as e:
                outs.append(AccountOutput(account_id=label, ok=False,
                                          message=f"Could not read positions: {_short(e)}"))
                continue
            cash = bp = value = None
            try:
                bal = lg.client.balance(tid)
                cash = _float(bal.get("cashBalance")
                              if bal.get("cashBalance") not in (None, "")
                              else bal.get("settledFunds"))
                bp = _float(bal.get("stockBuyingPower") or bal.get("netBuyingPower"))
                value = _float(bal.get("balance"))
            except Exception as e:
                _trace(f"{label}: balance read failed: {e}")
            outs.append(AccountOutput(
                account_id=label, ok=True,
                message=f"{len(holdings)} position{'s' if len(holdings) != 1 else ''}",
                holdings=holdings,
                extra={"cash": cash, "buying_power": bp, "portfolio_value": value,
                       "positions_count": len(holdings)}))
    ok_ct = sum(1 for a in outs if a.ok)
    return BrokerOutput(broker=BROKER, state=_state_from_counts(ok_ct, len(outs) - ok_ct),
                        accounts=outs, message="")


# =============================================================================
# trading
# =============================================================================

_DEAD = {"REJECTED", "CANCELED", "EXPIRED", "SUSPENDED", "STOPPED"}


def _held(client: _AriesClient, tid: str, symbol: str) -> Decimal:
    total = Decimal("0")
    for p in client.positions(tid):
        if str(p.get("symbol") or "").strip().upper() == symbol:
            q = _dec(p.get("quantity"))
            if q is not None:
                total += q
    return total


def _preview_note(pv: Dict[str, Any]) -> str:
    """'' when the preview quotes no cost; else e.g. 'commission $0.99'."""
    parts = []
    for key, name in (("commission", "commission"), ("fees", "fees")):
        d = _dec(pv.get(key))
        if d is not None and d > 0:
            parts.append(f"{name} ${d:.2f}")
    warns = [str(w) for w in (pv.get("warnings") or []) if str(w).strip()]
    if warns:
        parts.append("warning: " + "; ".join(_short(w, 120) for w in warns))
    return ", ".join(parts)


def _ticket(body: Dict[str, Any], label: str, note: str) -> str:
    return ("DRY RUN — NO ORDER SUBMITTED\n"
            f"side: {body['side']}\nsymbol: {body['symbol']}\nquantity: {body['qty']}\n"
            f"order_type: MARKET\ntif: DAY\naccount: {label}"
            + (f"\naries preview: {note}" if note else "\naries preview: no cost quoted"))


def _write_dry_run_log(content: str) -> str:
    d = _root_dir() / "logs" / BROKER / datetime.now(_ET).strftime("%m.%d.%y")
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"test_order_{BROKER}_{uuid.uuid4().hex[:10]}.log"
    p.write_text(content, encoding="utf-8")
    return str(p)


def _trade_one(client: _AriesClient, tid: str, label: str, side: str, qty: Decimal,
               sym: str, dry_run: bool) -> AccountOutput:
    if side == "SELL":
        try:
            held = _held(client, tid, sym)
        except Exception as e:
            return AccountOutput(account_id=label, ok=False, message=_not_sent(
                f"Could not read the position before selling: {_short(e)}"))
        if held < qty:
            return AccountOutput(account_id=label, ok=False, message=(
                f"Skipped: this account holds {_fmt(held)} {sym}, not enough shares "
                f"to sell {_fmt(qty)} — nothing was sent"))

    tag = f"rsa-{uuid.uuid4().hex[:20]}"
    body = {"tradingAccountId": tid, "symbol": sym, "side": side, "type": "MARKET",
            "qty": _fmt(qty), "timeInForce": "DAY", "clientId": tag}

    note = ""
    try:
        pv = client.preview(body)
        errs = [str(e) for e in (pv.get("errors") or []) if str(e).strip()]
        if errs:
            return AccountOutput(account_id=label, ok=False, message=(
                f"Skipped: Aries' preview refused the order ({_short('; '.join(errs))})"
                f" — nothing was sent"))
        note = _preview_note(pv)
        _trace(f"{label}: preview {side} {_fmt(qty)} {sym}: {pv}")
    except Exception as e:
        _trace(f"{label}: preview failed ({e}); sending anyway")

    if dry_run:
        return AccountOutput(account_id=label, ok=True, message=_ticket(body, label, note),
                             order_id=tag)

    _trace(f"{label}: sending {side} {_fmt(qty)} {sym} ({tag})")
    kind, data = client.place(body)
    if kind == "not_sent":
        return AccountOutput(account_id=label, ok=False, message=_not_sent(data["why"]))
    if kind == "refused":
        return AccountOutput(account_id=label, ok=False, message=(
            f"Order rejected by Aries ({data['why']}) — nothing was sent"))
    if kind == "may_exist":
        return AccountOutput(account_id=label, ok=False, message=_verify(data["why"]))

    cl = str(data.get("clOrdId") or "")
    status = str(data.get("status") or "").upper()
    reason = _short(data.get("ordRejReason") or data.get("text") or "")
    if data.get("success") is False or status in _DEAD:
        return AccountOutput(account_id=label, ok=False, message=(
            f"Order rejected by Aries ({status or 'not accepted'}"
            + (f": {reason}" if reason else "") + ") — nothing was sent"))

    # A late rejection (EXCHANGE_CLOSED, buying power) shows up a moment
    # later on the order itself; a fill shows its price.
    if status not in ("FILLED",) and CONFIRM_WAIT > 0:
        time.sleep(CONFIRM_WAIT)
        o = client.find_order(tid, cl, tag)
        if o:
            data = {**data, **o, "status": o.get("ordStatus") or status}
            status = str(data.get("status") or "").upper()
            reason = _short(o.get("ordRejReason") or o.get("text") or "")
            if status == "REJECTED":
                return AccountOutput(account_id=label, ok=False, order_id=cl or None,
                                     message=(f"Order rejected by Aries"
                                              + (f": {reason}" if reason else "")
                                              + " — nothing was sent"))
    fill = _dec(data.get("avgPrice"))
    msg = f"order placed ({status or 'NEW'})"
    if fill is not None and fill > 0:
        msg += f", filled @ ${fill:.4f}".rstrip("0").rstrip(".")
    if note:
        msg += f" — Aries preview: {note}"
    extra: Dict[str, Any] = {"status": status}
    if fill is not None and fill > 0:
        extra["fill_price"] = float(fill)
    return AccountOutput(account_id=label, ok=True, message=msg,
                         order_id=cl or tag, extra=extra)


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False,
                  only_accounts: Optional[List[str]] = None,
                  **kwargs) -> BrokerOutput:
    """One DAY market order per Aries account.

    `only_accounts` narrows to those account labels (exactly as this module
    returns them) so the app can retry only the accounts that failed; a
    login's own name ("Aries", "Aries 2") stands for all of its accounts. A
    dry run previews each order with Aries and sends nothing.
    """
    side_norm = (side or "").strip().lower()
    if side_norm not in ("buy", "sell"):
        return BrokerOutput(broker=BROKER, state="failed", accounts=[],
                            message=f"Invalid side: {side!r}")
    sym = (symbol or "").strip().upper()
    if not sym:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[],
                            message="Invalid symbol")
    q = _dec(qty)
    if q is None or q <= 0:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[],
                            message=f"Invalid qty: {qty!r}")
    api_side = side_norm.upper()

    lgs = _logins()
    if not lgs:
        return BrokerOutput(broker=BROKER, state="failed", message=_NOT_SET_UP,
                            accounts=[AccountOutput(account_id=DISPLAY, ok=False,
                                                    message=_not_sent(_NOT_SET_UP))])
    only: Optional[Set[str]] = ({str(a).strip() for a in only_accounts if str(a).strip()}
                                if only_accounts else None)

    outs: List[AccountOutput] = []
    matched = False
    n = 0
    for lg in lgs:
        whole = only is not None and lg.name in only
        if lg.problem:
            if only is None or whole:
                outs.append(AccountOutput(account_id=lg.name, ok=False,
                                          message=_not_sent(lg.problem)))
                matched = matched or whole
            continue
        for tid, label in lg.accounts:
            if only is not None and not whole and label not in only:
                continue
            matched = True
            if n:
                time.sleep(random.uniform(0.5, 1.5))
            n += 1
            try:
                outs.append(_trade_one(lg.client, tid, label, api_side, q, sym,
                                       bool(dry_run)))
            except Exception as e:          # noqa: BLE001 -- never lose a row
                outs.append(AccountOutput(account_id=label, ok=False, message=_verify(
                    f"unexpected error around the order ({type(e).__name__}: {_short(e)})")))

    if only is not None and not matched:
        outs.append(AccountOutput(
            account_id=DISPLAY, ok=False,
            message=f"None of the requested accounts were found: {sorted(only)} — nothing was sent"))

    ok_ct = sum(1 for a in outs if a.ok)
    state = _state_from_counts(ok_ct, len(outs) - ok_ct)
    message = ""
    if dry_run:
        lines = ["DRY RUN — NO ORDER SUBMITTED", f"broker: {BROKER}",
                 f"time_et: {datetime.now(_ET).isoformat()}",
                 f"requested: side={api_side} symbol={sym} qty={_fmt(q)}", ""]
        for o in outs:
            lines += [f"[{o.account_id}] {'OK' if o.ok else 'FAILED'}", o.message, ""]
        try:
            message = f"DRY RUN — NO ORDER SUBMITTED | log: {_write_dry_run_log(chr(10).join(lines))}"
        except Exception:
            message = "DRY RUN — NO ORDER SUBMITTED"
    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=message)

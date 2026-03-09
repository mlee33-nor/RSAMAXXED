# modules/brokers/public/public.py
from __future__ import annotations

import os
import random
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from zoneinfo import ZoneInfo

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
    """
    Loads numbered tokens:
      PUBLIC_SECRET_TOKEN_1
      PUBLIC_SECRET_TOKEN_2
      PUBLIC_SECRET_TOKEN_3
    Returns list of (idx, token) skipping blanks.
    """
    out: List[Tuple[int, str]] = []
    for i in (1, 2, 3):
        s = _env(f"PUBLIC_SECRET_TOKEN_{i}")
        if s:
            out.append((i, s))
    return out


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

        r = requests.post(url, json=body, headers=self._headers(), timeout=30)
        if r.status_code >= 400:
            raise RuntimeError(f"Order failed: HTTP {r.status_code} - {r.text}")

        data = r.json() or {}
        return data.get("orderId") or oid


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
        return False, "Missing PUBLIC_SECRET_TOKEN_1/2/3 in credentials/brokers.env", []

    ready: List[Tuple[int, _PublicClient, List[Dict[str, Any]]]] = []
    last_err = ""

    for idx, secret in pairs:
        try:
            client = _get_client_for_secret(idx, secret)
            accounts = client.get_accounts()
            if not isinstance(accounts, list):
                raise RuntimeError("unexpected accounts response")
            ready.append((idx, client, accounts))
        except Exception as e:
            last_err = str(e)

    if not ready:
        return False, (last_err or "Auth failed"), []
    return True, "ok", ready


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

def bootstrap(*args, **kwargs) -> None:
    """
    Compatibility shim:
      - validates that secret token(s) can exchange for access token
      - validates we can fetch accounts successfully
    """
    ok, msg, _ready = _ensure_clients()
    if not ok:
        raise RuntimeError(msg or "Public auth failed")


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
            accounts=[AccountOutput(account_id="Public", ok=False, message=msg)],
            message=msg,
        )

    # Per-secret status lines
    for idx, _client, accounts in ready:
        label = f"Public {idx}"
        accs.append(AccountOutput(account_id=label, ok=True, message=f"ok (accounts={len(accounts)})"))

        write_log(
            ctx,
            broker=BROKER,
            action="healthcheck",
            label=str(idx),
            text=f"OK: accounts={len(accounts)}",
        )

    return BrokerOutput(broker=BROKER, state="success", accounts=accs, message="ok")


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

def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False, **kwargs) -> BrokerOutput:
    ok, msg, ready = _ensure_clients()
    if not ok:
        return BrokerOutput(broker=BROKER, state="failed", message=msg, accounts=[])

    api_side, qty_s, sym, err = _validate_trade_inputs(side, qty, symbol)
    if err:
        return err

    outs: List[AccountOutput] = []
    log_sections: List[str] = []
    _acct_i = 0

    log_sections.append("DRY RUN — NO ORDER SUBMITTED" if dry_run else "LIVE ORDER MODE")
    log_sections.append(f"broker: {BROKER}")
    log_sections.append(f"requested: side={api_side} symbol={sym} qty={qty_s}")
    log_sections.append(f"time_et: {datetime.now(_ET).isoformat()}")
    log_sections.append("")

    for pub_idx, client, accounts in ready:
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

            endpoint_path = f"/userapigateway/trading/{acct_id}/order"
            oid = str(uuid.uuid4())
            body = _build_public_market_order_body(
                order_id=oid,
                side=api_side,
                symbol=sym,
                quantity=qty_s,
                market_session="CORE",
                tif="DAY",
            )
            ticket = _format_preview_ticket(endpoint_path=endpoint_path, body=body)

            if dry_run:
                outs.append(AccountOutput(account_id=acct_label, ok=True, message=ticket, order_id=oid))
                log_sections.append(f"[{acct_label}]")
                log_sections.append(ticket)
                log_sections.append("")
                continue

            try:
                order_id = client.place_equity_market_order(
                    account_id=acct_id,
                    side=api_side,
                    symbol=sym,
                    quantity=qty_s,
                    market_session="CORE",
                    tif="DAY",
                    order_id=oid,
                )
                outs.append(AccountOutput(account_id=acct_label, ok=True, message="order placed", order_id=str(order_id) if order_id else oid))
            except Exception as e:
                outs.append(AccountOutput(account_id=acct_label, ok=False, message=str(e), order_id=None))

    ok_ct = sum(1 for a in outs if a.ok)
    fail_ct = sum(1 for a in outs if not a.ok)
    state = _state_from_counts(ok_ct, fail_ct)

    broker_msg = ""
    if dry_run:
        log_path = _write_dry_run_log(content="\n".join(log_sections).rstrip() + "\n")
        broker_msg = f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}"

    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=broker_msg)


def get_accounts(*args, **kwargs) -> BrokerOutput:
    ok, msg, ready = _ensure_clients()
    if not ok:
        return BrokerOutput(broker=BROKER, state="failed", message=msg, accounts=[])

    outs: List[AccountOutput] = []

    for pub_idx, client, accounts in ready:
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
        return BrokerOutput(broker=BROKER, state="failed", message=msg, accounts=[])

    outs: List[AccountOutput] = []
    total_value = Decimal("0")
    total_value_seen = False

    for pub_idx, client, accounts in ready:
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
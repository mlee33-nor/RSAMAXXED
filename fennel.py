# modules/brokers/fennel/fennel.py  (legacy-style session behavior)
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple, Dict
from zoneinfo import ZoneInfo
import uuid

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow
from modules._2fa_prompt import universal_2fa_prompt

BROKER = "fennel"
OtpProvider = Callable[[str, int], Optional[str]]

_ET = ZoneInfo("America/New_York")


# =============================================================================
# Safe discovery helpers (positions extras)
# =============================================================================

_DENY_KEY_SUBSTRS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "authorization",
    "bearer",
    "session",
    "ssn",
    "socialsecurity",
    "taxid",
    "ein",
    "routing",
    "iban",
    "swift",
)


def _is_safe_scalar(v: Any) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))


def _key_allowed(k: str) -> bool:
    kl = (k or "").strip().lower().replace(" ", "")
    if not kl:
        return False
    return not any(bad in kl for bad in _DENY_KEY_SUBSTRS)


def _flatten_safe(obj: Any, *, prefix: str = "", max_items: int = 120) -> Dict[str, Any]:
    """
    Flatten one level of dict -> safe scalars only.
    - Includes scalar values
    - Includes one-level nested dict scalars as key_subkey
    - Skips lists and deep nesting
    - Applies denylist to keys
    """
    out: Dict[str, Any] = {}
    if not isinstance(obj, dict):
        return out

    n = 0
    for k, v in obj.items():
        if n >= max_items:
            break
        if not isinstance(k, str):
            continue
        if not _key_allowed(k):
            continue

        key = f"{prefix}{k}" if prefix else k

        if _is_safe_scalar(v):
            out[key] = v
            n += 1
            continue

        if isinstance(v, dict):
            for kk, vv in v.items():
                if n >= max_items:
                    break
                if not isinstance(kk, str):
                    continue
                if not _key_allowed(kk):
                    continue
                if _is_safe_scalar(vv):
                    out[f"{key}_{kk}"] = vv
                    n += 1

    return out


def _safe_last4(v: Any) -> str:
    s = str(v or "").strip()
    if not s:
        return "----"
    return s[-4:] if len(s) >= 4 else (s or "----")


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _sessions_dir() -> Path:
    # keep default to avoid breaking existing installs
    d = _root_dir() / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _dry_run_log_dir() -> Path:
    d = datetime.now(_ET).strftime("%m.%d.%y")
    p = _root_dir() / "logs" / BROKER / d
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write_dry_run_log(*, content: str) -> str:
    rand = uuid.uuid4().hex[:10]
    path = _dry_run_log_dir() / f"test_order_{BROKER}_{rand}.log"
    path.write_text(content, encoding="utf-8")
    return str(path)


def _looks_like_2fa(exc_text: str) -> bool:
    """
    Legacy checked for '2FA' substring. We broaden slightly but keep it conservative.
    """
    t = (exc_text or "").lower()
    return ("2fa" in t) or ("two-factor" in t) or ("verification code" in t) or ("wait_for_code" in t)


def _otp_provider_terminal() -> OtpProvider:
    """OTP provider that prompts in the terminal."""
    def provider(label: str, timeout_s: int) -> Optional[str]:
        try:
            raw = input(universal_2fa_prompt(label) + " ").strip()
            digits = "".join(c for c in raw if c.isdigit())
            return digits if len(digits) == 6 else None
        except (EOFError, KeyboardInterrupt):
            return None
    return provider


@dataclass(frozen=True)
class FennelConfig:
    emails: List[str]
    sessions_dir: Path
    otp_timeout_s: int = 300

    @staticmethod
    def from_env() -> Optional["FennelConfig"]:
        # Back-compat: accept either FENNEL_EMAIL or legacy-like FENNEL
        raw = _env("FENNEL_EMAIL") or _env("FENNEL")
        if not raw:
            return None

        emails = [e.strip() for e in raw.split(",") if e.strip()]
        if not emails:
            return None

        sessions_dir = Path(os.getenv("FENNEL_SESSIONS_DIR") or _sessions_dir()).expanduser()
        otp_timeout_s = int(os.getenv("FENNEL_OTP_TIMEOUT_S") or "300")
        sessions_dir.mkdir(parents=True, exist_ok=True)

        return FennelConfig(emails=emails, sessions_dir=sessions_dir, otp_timeout_s=otp_timeout_s)


@dataclass
class _LoginSession:
    label: str
    email: str
    client: Any
    accounts: List[Tuple[str, str]]  # (account_name, account_id)
    pkl_name: str


class FennelBroker:
    """
    Legacy-parity behavior:
      - PKL naming: fennel1.pkl, fennel2.pkl, ...
      - ALWAYS call login() before using the client (PKL makes it silent if valid).
      - If 2FA is required, prompt OTP and login again with code.
    """

    def __init__(self, cfg: FennelConfig, otp_provider: Optional[OtpProvider] = None):
        self.cfg = cfg
        self.otp_provider = otp_provider
        self._sessions: List[_LoginSession] = []

    def _pkl_name(self, idx0: int) -> str:
        # Legacy naming
        return f"fennel{idx0 + 1}.pkl"

    def _make_client(self, idx0: int):
        try:
            from fennel_invest_api import Fennel  # type: ignore
        except Exception as e:
            raise RuntimeError("Missing dependency: fennel-invest-api") from e

        pkl = self._pkl_name(idx0)
        client = Fennel(filename=pkl, path=str(self.cfg.sessions_dir))
        return client, pkl

    def _get_accounts(self, client) -> List[Tuple[str, str]]:
        """
        Matches legacy: prefer get_full_accounts, fallback to get_account_ids.
        Also acts as a post-login verification.
        """
        try:
            full_accounts = client.get_full_accounts()
            out: List[Tuple[str, str]] = []
            for info in full_accounts:
                name = str(info.get("name") or "Account")
                acct_id = str(info["id"])
                out.append((name, acct_id))
            return out
        except Exception:
            pass

        acct_ids = client.get_account_ids()
        return [(f"Account {i + 1}", str(aid)) for i, aid in enumerate(acct_ids)]

    def ensure_authenticated(self) -> BrokerOutput:
        """
        Legacy rhythm:
          - for each email: call login()
          - if it throws 2FA and we have OTP provider: request OTP and login(code=...)
          - then fetch accounts to verify auth
        """
        accounts_out: List[AccountOutput] = []
        any_ok = False
        any_fail = False
        self._sessions.clear()

        for idx0, email in enumerate(self.cfg.emails):
            label = "Fennel" if len(self.cfg.emails) == 1 else f"Fennel {idx0 + 1}"
            try:
                client, pkl = self._make_client(idx0)

                if self.otp_provider is None:
                    # Console mode: exact legacy behavior
                    client.login(email=email, wait_for_code=True)
                else:
                    # OTP-provider mode: legacy behavior
                    try:
                        client.login(email=email, wait_for_code=False)
                    except Exception as e1:
                        # If 2FA required, get OTP and retry
                        if _looks_like_2fa(str(e1)):
                            code = self.otp_provider(label, self.cfg.otp_timeout_s)
                            if not code:
                                raise RuntimeError("OTP not received (timeout/cancelled)")
                            client.login(email=email, wait_for_code=False, code=code)
                        else:
                            raise

                acct_pairs = self._get_accounts(client)
                self._sessions.append(_LoginSession(label=label, email=email, client=client, accounts=acct_pairs, pkl_name=pkl))

                any_ok = True
                accounts_out.append(AccountOutput(account_id=label, ok=True, message=f"Authenticated. Accounts: {len(acct_pairs)}"))

            except Exception as e:
                any_fail = True
                accounts_out.append(AccountOutput(account_id=label, ok=False, message=f"Auth failed: {e}"))

        state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")
        return BrokerOutput(broker=BROKER, state=state, accounts=accounts_out, message="")

    # -------------------------------------------------------------------------
    # Trading / holdings
    # -------------------------------------------------------------------------

    def place_order_all(self, ticker: str, quantity: float, side: str, *, dry_run: bool = False) -> BrokerOutput:
        side = (side or "").strip().lower()
        if side not in ("buy", "sell"):
            return BrokerOutput(broker=BROKER, state="failed",
                                accounts=[AccountOutput(account_id="fennel", ok=False, message=f"Invalid side: {side!r}")],
                                message="")

        ticker = (ticker or "").strip().upper()
        if not ticker:
            return BrokerOutput(broker=BROKER, state="failed",
                                accounts=[AccountOutput(account_id="fennel", ok=False, message="Invalid symbol")],
                                message="")

        if quantity <= 0:
            return BrokerOutput(broker=BROKER, state="failed",
                                accounts=[AccountOutput(account_id="fennel", ok=False, message=f"Invalid qty: {quantity!r}")],
                                message="")

        if not self._sessions:
            return BrokerOutput(broker=BROKER, state="failed",
                                accounts=[AccountOutput(account_id="fennel", ok=False, message="Not authenticated.")],
                                message="Not authenticated")

        accounts_out: List[AccountOutput] = []
        any_ok = False
        any_fail = False

        log_lines: List[str] = []
        log_lines.append("DRY RUN — NO ORDER SUBMITTED" if dry_run else "LIVE ORDER MODE")
        log_lines.append(f"broker: {BROKER}")
        log_lines.append(f"time_et: {datetime.now(_ET).isoformat()}")
        log_lines.append(f"requested: side={side.upper()} symbol={ticker} qty={quantity}")
        log_lines.append("")

        for sess in self._sessions:
            for acct_name, acct_id in sess.accounts:
                account_label = f"{sess.label} · {acct_name}"

                ticket = (
                    ("DRY RUN — NO ORDER SUBMITTED\n" if dry_run else "LIVE SUBMIT\n")
                    + f"side: {side.upper()}\n"
                    + f"symbol: {ticker}\n"
                    + f"quantity: {quantity}\n"
                    + f"account_label: {account_label}\n"
                    + f"account_id: {acct_id}"
                )

                try:
                    resp = sess.client.place_order(
                        account_id=acct_id,
                        ticker=ticker,
                        quantity=quantity,
                        side=side,
                        dry_run=bool(dry_run),
                    )

                    if dry_run:
                        ok = bool(resp.get("dry_run_success", False))
                        msg = "Dry Run Success" if ok else "Dry Run Failed"
                        any_ok = any_ok or ok
                        any_fail = any_fail or (not ok)
                        accounts_out.append(AccountOutput(account_id=account_label, ok=ok, message=ticket + f"\nresult: {msg}", order_id=None))
                        log_lines.append(f"[{account_label}]")
                        log_lines.append(ticket)
                        log_lines.append(f"result: {msg}")
                        log_lines.append("")
                        continue

                    ok2, msg2, order_id = self._interpret_order_response(resp)
                    any_ok = any_ok or ok2
                    any_fail = any_fail or (not ok2)
                    accounts_out.append(AccountOutput(account_id=account_label, ok=ok2, message=msg2, order_id=order_id))

                except Exception as e:
                    any_fail = True
                    accounts_out.append(AccountOutput(account_id=account_label, ok=False, message=str(e), order_id=None))
                    if dry_run:
                        log_lines.append(f"[{account_label}]")
                        log_lines.append(ticket)
                        log_lines.append(f"ERROR: {e}")
                        log_lines.append("")

        state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")

        msg = ""
        if dry_run:
            log_path = _write_dry_run_log(content="\n".join(log_lines).rstrip() + "\n")
            msg = f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}"

        return BrokerOutput(broker=BROKER, state=state, accounts=accounts_out, message=msg)

    def _interpret_order_response(self, resp: dict) -> Tuple[bool, str, Optional[str]]:
        if not isinstance(resp, dict):
            return False, "Unexpected response type", None

        data = resp.get("data") or {}
        status = data.get("createOrder")

        if status == "pending":
            order_id = data.get("orderId") or resp.get("order_id") or None
            return True, "Success (pending)", str(order_id) if order_id else None

        if isinstance(status, str) and status:
            return False, status, None

        return False, "Unknown order response", None

    def get_holdings(self) -> BrokerOutput:
        if not self._sessions:
            return BrokerOutput(broker=BROKER, state="failed",
                                accounts=[AccountOutput(account_id="fennel", ok=False, message="Not authenticated.")],
                                message="Not authenticated")

        outs: List[AccountOutput] = []
        any_ok = False
        any_fail = False

        def _f(x) -> Optional[float]:
            try:
                if x is None:
                    return None
                return float(x)
            except Exception:
                return None

        broker_extra: Dict[str, Any] = {
            "sessions_count": int(len(self._sessions)),
        }

        for sess in self._sessions:
            for acct_name, acct_id in sess.accounts:
                account_label = f"{sess.label} · {acct_name}"
                try:
                    raw = sess.client.get_stock_holdings(acct_id) or []
                    if not isinstance(raw, list):
                        raw = []

                    rows: List[HoldingRow] = []
                    parsed = 0

                    for h in raw:
                        if not isinstance(h, dict):
                            continue
                        sec = h.get("security") or {}
                        inv = h.get("investment") or {}
                        if not isinstance(sec, dict):
                            sec = {}
                        if not isinstance(inv, dict):
                            inv = {}

                        sym = (sec.get("ticker") or "?").strip().upper() or "?"
                        sh = _f(inv.get("ownedShares"))
                        px = _f(sec.get("currentStockPrice"))

                        if sh is not None and sh == 0.0:
                            continue

                        hextra: Dict[str, Any] = {}
                        try:
                            hextra["keys"] = sorted([str(k) for k in h.keys()])[:200]
                            hextra.update(_flatten_safe(h, max_items=120))
                            hextra.update(_flatten_safe(sec, prefix="security_", max_items=80))
                            hextra.update(_flatten_safe(inv, prefix="investment_", max_items=80))
                        except Exception:
                            pass

                        if (sh is not None) and (px is not None):
                            try:
                                hextra["market_value_calc"] = float(sh) * float(px)
                            except Exception:
                                pass

                        rows.append(HoldingRow(symbol=sym, shares=sh, price=px, extra=hextra))
                        parsed += 1

                    acct_extra: Dict[str, Any] = {
                        "account_id_last4": _safe_last4(acct_id),
                        "raw_holdings_count": int(len(raw)),
                        "positions_parsed": int(parsed),
                    }

                    outs.append(AccountOutput(account_id=account_label, ok=True, message="", holdings=rows, extra=acct_extra))
                    any_ok = True

                except Exception as e:
                    outs.append(
                        AccountOutput(
                            account_id=account_label,
                            ok=False,
                            message=str(e),
                            holdings=[],
                            extra={"account_id_last4": _safe_last4(acct_id)},
                        )
                    )
                    any_fail = True

        state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")
        broker_extra["accounts_ok"] = int(sum(1 for a in outs if a.ok))
        broker_extra["accounts_failed"] = int(sum(1 for a in outs if not a.ok))

        return BrokerOutput(broker=BROKER, state=state, accounts=outs, message="", extra=broker_extra)


_BROKER: Optional[FennelBroker] = None


def _get_otp_provider() -> OtpProvider:
    return _otp_provider_terminal()


def _ensure_session_like_legacy() -> Tuple[Optional[FennelBroker], str]:
    """
    EXACT legacy behavior mapped into Idle Markets:
      - ALWAYS call login() (PKL makes it cheap when valid)
      - If 2FA required, prompt OTP and retry
    """
    global _BROKER

    cfg = FennelConfig.from_env()
    if cfg is None:
        return None, "Missing FENNEL_EMAIL (or FENNEL) in credentials/brokers.env"

    otp_provider = _get_otp_provider()

    b = FennelBroker(cfg=cfg, otp_provider=otp_provider)
    out = b.ensure_authenticated()
    if out.state in ("success", "partial") and b._sessions:
        _BROKER = b
        return _BROKER, "ok"

    # Best message
    msg = (out.message or "").strip() or "Auth failed"
    for a in (out.accounts or []):
        if not getattr(a, "ok", False) and (a.message or "").strip():
            msg = a.message.strip()
            break
    return None, msg


def bootstrap() -> None:
    b, msg = _ensure_session_like_legacy()
    if b is None:
        raise RuntimeError(msg)


def get_holdings() -> BrokerOutput:
    b, why = _ensure_session_like_legacy()
    if b is None:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[AccountOutput(account_id="fennel", ok=False, message=why)], message=why)
    return b.get_holdings()


def get_accounts() -> BrokerOutput:
    return get_holdings()


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False) -> BrokerOutput:
    b, why = _ensure_session_like_legacy()
    if b is None:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[AccountOutput(account_id="fennel", ok=False, message=why)], message=why)

    try:
        q = float(qty)
        if q <= 0:
            raise ValueError()
    except Exception:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[AccountOutput(account_id="fennel", ok=False, message=f"Invalid qty: {qty!r}")], message="Invalid qty")

    tick = (symbol or "").strip().upper()
    if not tick:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[AccountOutput(account_id="fennel", ok=False, message="Invalid symbol")], message="Invalid symbol")

    return b.place_order_all(ticker=tick, quantity=q, side=side, dry_run=dry_run)


def healthcheck() -> BrokerOutput:
    """
    Kept as probe-only (non-interactive). Does not call login().
    """
    cfg = FennelConfig.from_env()
    if cfg is None:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Fennel", ok=False, message="Missing FENNEL_EMAIL (or FENNEL)")],
            message="Missing credentials",
        )

    try:
        from fennel_invest_api import Fennel  # type: ignore
    except Exception as e:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Fennel", ok=False, message=f"Missing dependency: fennel-invest-api ({e})")],
            message="Missing dependency",
        )

    outs: List[AccountOutput] = []
    any_ok = False
    any_fail = False

    for idx0, email in enumerate(cfg.emails):
        label = "Fennel" if len(cfg.emails) == 1 else f"Fennel {idx0 + 1}"
        pkl = f"fennel{idx0 + 1}.pkl"
        try:
            client = Fennel(filename=pkl, path=str(cfg.sessions_dir))
            # probe by hitting accounts without login
            try:
                _ = client.get_full_accounts()
            except Exception:
                _ = client.get_account_ids()
            outs.append(AccountOutput(account_id=label, ok=True, message="cached session ok"))
            any_ok = True
        except Exception as e:
            outs.append(AccountOutput(account_id=label, ok=False, message=str(e)))
            any_fail = True

    state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")
    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message="ok" if any_ok else "failed")

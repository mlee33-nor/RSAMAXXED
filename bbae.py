from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional, List, Tuple, Dict
from datetime import datetime
from zoneinfo import ZoneInfo
import uuid

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow
from modules._2fa_prompt import universal_2fa_prompt

BROKER = "bbae"

_CLIENT: Any = None
_ACCOUNT_LABEL: str = ""
_ACCOUNT_NUMBER: str = ""


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
    "accountnumber",
    "account_number",
    "acctnumber",
    "acct_number",
)


def _is_safe_scalar(v: Any) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))


def _key_allowed(k: str) -> bool:
    kl = (k or "").strip().lower().replace(" ", "")
    if not kl:
        return False
    return not any(bad in kl for bad in _DENY_KEY_SUBSTRS)


def _flatten_safe(obj: Any, *, prefix: str = "", max_items: int = 80) -> Dict[str, Any]:
    """Flatten one level of dict -> safe scalars only. No lists, no deep nesting."""
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

        # One-level flatten for nested dict scalars
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


def _as_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except Exception:
        try:
            return float(str(v))
        except Exception:
            return None


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _sessions_dir() -> Path:
    d = _root_dir() / "sessions" / "bbae"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _local_otp_prompt(broker: str, prompt: str) -> Optional[str]:
    """Prompt for OTP code in the terminal."""
    try:
        code = input(f"{prompt} ").strip()
        digits = "".join(c for c in code if c.isdigit())
        return digits if digits else None
    except (EOFError, KeyboardInterrupt):
        return None


def _local_captcha(broker: str, img) -> Optional[str]:
    """Save CAPTCHA image to disk and prompt for code in terminal."""
    import subprocess, sys
    sess_dir = _sessions_dir()
    path = sess_dir / "captcha.png"
    img.save(str(path))
    # Try to auto-open the image
    try:
        if sys.platform == "win32":
            subprocess.Popen(["start", "", str(path)], shell=True)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        pass
    try:
        code = input(f"CAPTCHA saved to {path}. Enter code: ").strip()
        return code if code else None
    except (EOFError, KeyboardInterrupt):
        return None


def _set_account_identity_from_info(info: dict) -> None:
    global _ACCOUNT_LABEL, _ACCOUNT_NUMBER
    acct_num = str(((info.get("Data") or {}).get("accountNumber")) or "")
    _ACCOUNT_NUMBER = acct_num
    last4 = acct_num[-4:] if acct_num else "----"
    _ACCOUNT_LABEL = f"Individual (****{last4})"


def _probe_client(bb) -> None:
    """
    Lightweight authenticated probe. Raises if not authenticated.
    """
    info = bb.get_account_info() or {}
    if isinstance(info, dict):
        outcome = info.get("Outcome")
        if outcome and outcome != "Success":
            raise RuntimeError(f"Outcome={outcome}")
    _set_account_identity_from_info(info)


def _rehydrate_from_disk(*, user: str, pw: str) -> Any:
    """
    Non-interactive restore: load cached PKL session and probe.
    Raises on failure.
    """
    from bbae_invest_api import BBAEAPI  # type: ignore

    sess_dir = _sessions_dir()
    bb = BBAEAPI(user, pw, filename="bbae.pkl", creds_path=str(sess_dir))
    try:
        bb.make_initial_request()
    except Exception:
        pass

    _probe_client(bb)
    return bb


def _interactive_login(*, user: str, pw: str) -> Any:
    """
    Interactive login (OTP/CAPTCHA) via terminal prompts.
    Raises on failure.
    """
    from bbae_invest_api import BBAEAPI  # type: ignore

    use_email = "@" in user
    sess_dir = _sessions_dir()

    bb = BBAEAPI(user, pw, filename="bbae.pkl", creds_path=str(sess_dir))
    bb.make_initial_request()

    ticket_resp = bb.generate_login_ticket_email() if use_email else bb.generate_login_ticket_sms()
    if (ticket_resp or {}).get("Data") is None:
        raise RuntimeError("Invalid response generating login ticket")

    data = (ticket_resp or {}).get("Data") or {}

    if data.get("needSmsVerifyCode", False):
        # CAPTCHA may be required first (and typically triggers the code flow)
        if data.get("needCaptchaCode", False):
            img = bb.request_captcha()
            if img is None:
                raise RuntimeError("Failed to request CAPTCHA image")

            captcha_code = _local_captcha(BROKER, img)

            if not captcha_code:
                raise RuntimeError("CAPTCHA not received")

            resp = bb.request_email_code(captcha_input=captcha_code) if use_email else bb.request_sms_code(captcha_input=captcha_code)
            if (resp or {}).get("Message") == "Incorrect verification code.":
                raise RuntimeError("Incorrect CAPTCHA code")
        else:
            bb.request_email_code() if use_email else bb.request_sms_code()

        # OTP
        otp = _local_otp_prompt(BROKER, universal_2fa_prompt("BBAE"))

        if not otp:
            raise RuntimeError("OTP not received")

        ticket_resp = bb.generate_login_ticket_email(sms_code=otp) if use_email else bb.generate_login_ticket_sms(sms_code=otp)
        if (ticket_resp or {}).get("Message") == "Incorrect verification code.":
            raise RuntimeError("Incorrect OTP code")

    ticket = ((ticket_resp or {}).get("Data") or {}).get("ticket")
    if not ticket:
        raise RuntimeError("No login ticket returned")

    login_resp = bb.login_with_ticket(ticket)
    if (login_resp or {}).get("Outcome") != "Success":
        raise RuntimeError(f"Login failed: {login_resp}")

    _probe_client(bb)
    return bb


def _ensure_session() -> Tuple[bool, str]:
    """
    Session behavior:
      1) use in-memory if valid
      2) rehydrate from disk without OTP if possible
      3) interactive login via terminal prompts
    """
    global _CLIENT

    user = _env("BBAE_USER")
    pw = _env("BBAE_PASSWORD")
    if not user or not pw:
        return False, "Missing BBAE_USER or BBAE_PASSWORD"

    try:
        from bbae_invest_api import BBAEAPI  # type: ignore
        _ = BBAEAPI
    except Exception as e:
        return False, f"Missing dependency bbae_invest_api: {e}"

    # 1) in-memory probe
    if _CLIENT is not None:
        try:
            _probe_client(_CLIENT)
            return True, "ok"
        except Exception:
            _CLIENT = None

    # 2) disk restore probe (no OTP)
    try:
        bb = _rehydrate_from_disk(user=user, pw=pw)
        _CLIENT = bb
        return True, "rehydrated"
    except Exception:
        pass

    # 3) interactive login via terminal
    try:
        bb = _interactive_login(user=user, pw=pw)
        _CLIENT = bb
        return True, "logged in"
    except Exception as e:
        _CLIENT = None
        return False, f"Login failed: {e}"


def bootstrap(*args, **kwargs):
    """
    Kept for compatibility, but NOT required.
    It simply forces an inline session ensure.
    """
    ok, detail = _ensure_session()
    if ok:
        return BrokerOutput(
            broker=BROKER,
            state="success",
            accounts=[AccountOutput(account_id="BBAE", ok=True, message=detail)],
            message=detail,
        )
    return BrokerOutput(
        broker=BROKER,
        state="failed",
        accounts=[AccountOutput(account_id="BBAE", ok=False, message=detail)],
        message=detail,
    )


def get_holdings(*args, **kwargs) -> BrokerOutput:
    ok, why = _ensure_session()
    if not ok:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="BBAE", ok=False, message=why)],
            message=why,
        )

    try:
        pos = _CLIENT.get_account_holdings() or {}

        # Broker-level discovery extras (safe scalars only)
        broker_extra: Dict[str, Any] = {}
        try:
            broker_extra.update(_flatten_safe(pos, prefix="payload_", max_items=120))
            if isinstance(pos, dict):
                broker_extra["payload_keys"] = sorted([str(k) for k in pos.keys()])[:200]
        except Exception:
            pass

        data = pos.get("Data") or []
        if not isinstance(data, list):
            data = []

        rows: List[HoldingRow] = []
        total_mv_calc = 0.0
        mv_calc_seen = False

        for h in data:
            if not isinstance(h, dict):
                continue

            # Per-position discovery extras (safe scalars only)
            hextra: Dict[str, Any] = {}
            try:
                hextra.update(_flatten_safe(h, max_items=120))
                hextra["keys"] = sorted([str(k) for k in h.keys()])[:200]
            except Exception:
                pass

            qty = _as_float(h.get("CurrentAmount"))
            if qty is None:
                qty = 0.0
            if qty == 0.0:
                continue

            sym = (h.get("displaySymbol") or "UNKNOWN")
            sym = (str(sym).strip().upper() if sym is not None else "UNKNOWN") or "UNKNOWN"

            px = _as_float(h.get("Last"))

            # Helpful computed fields (safe)
            if px is not None:
                mv = float(qty) * float(px)
                hextra["market_value_calc"] = mv
                total_mv_calc += mv
                mv_calc_seen = True

            rows.append(HoldingRow(symbol=sym, shares=float(qty), price=px, extra=hextra))

        acct_line = _ACCOUNT_LABEL or "BBAE"
        last4 = (_ACCOUNT_NUMBER[-4:] if _ACCOUNT_NUMBER else "----")

        acct_extra: Dict[str, Any] = {
            "account_last4": last4,
            "raw_holdings_count": int(len(data)),
            "positions_count": int(len(rows)),
        }
        if mv_calc_seen:
            acct_extra["total_market_value_calc"] = float(total_mv_calc)

        return BrokerOutput(
            broker=BROKER,
            state="success",
            accounts=[
                AccountOutput(
                    account_id=acct_line,
                    ok=True,
                    message="",
                    holdings=rows,
                    extra=acct_extra,
                )
            ],
            message="",
            extra=broker_extra,
        )
    except Exception as e:
        acct_line = _ACCOUNT_LABEL or "BBAE"
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id=acct_line, ok=False, message=str(e))],
            message=str(e),
        )


def get_accounts(*args, **kwargs) -> BrokerOutput:
    return get_holdings(*args, **kwargs)


_ET = ZoneInfo("America/New_York")

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

def _ticket_lines(**kv) -> str:
    lines = []
    for k, v in kv.items():
        if v is None or v == "":
            continue
        lines.append(f"{k}: {v}")
    return "\n".join(lines)


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False, **kwargs) -> BrokerOutput:
    ok, why = _ensure_session()
    if not ok:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="BBAE", ok=False, message=why)],
            message=why,
        )

    side_norm = (side or "").strip().lower()
    if side_norm not in ("buy", "sell"):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="BBAE", ok=False, message=f"Invalid side: {side!r}")],
            message="Invalid side",
        )

    sym = (symbol or "").strip().upper()
    if not sym:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="BBAE", ok=False, message="Invalid symbol")],
            message="Invalid symbol",
        )

    try:
        q = float(qty)
        if q <= 0:
            raise ValueError()
    except Exception:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="BBAE", ok=False, message=f"Invalid qty: {qty!r}")],
            message="Invalid qty",
        )

    acct_line = _ACCOUNT_LABEL or "BBAE"
    acct_num = _ACCOUNT_NUMBER or None

    log_sections: List[str] = []
    log_sections.append("DRY RUN — NO ORDER SUBMITTED" if dry_run else "LIVE ORDER MODE")
    log_sections.append(f"broker: {BROKER}")
    log_sections.append(f"time_et: {datetime.now(_ET).isoformat()}")
    log_sections.append(f"requested: side={side_norm} symbol={sym} qty={q}")
    log_sections.append("")

    try:
        if side_norm == "buy":
            order_type = "MARKET"
            entrust_price = None

            info = _CLIENT.get_simple_stock_info(sym) or {}
            if info.get("Data") and info["Data"].get("data"):
                meta = info["Data"].get("meta") or []
                data = info["Data"]["data"][0] if info["Data"]["data"] else []
                try:
                    exchange_idx = meta.index("lastExchangeShortName")
                    price_idx = meta.index("Last")
                    exchange = data[exchange_idx]
                    last_price = data[price_idx]
                    if "OTC" in (exchange or ""):
                        order_type = "LIMIT"
                        entrust_price = last_price
                except Exception:
                    pass

            val = _CLIENT.validate_buy(
                symbol=sym,
                amount=q,
                order_side=1,
                account_number=acct_num,
                order_type=order_type,
                entrust_price=entrust_price,
            )
            if (val or {}).get("Outcome") != "Success":
                raise RuntimeError((val or {}).get("Message") or "Buy validation failed")

            ticket = _ticket_lines(
                side="BUY",
                symbol=sym,
                quantity=q,
                order_type=order_type,
                tif="DAY",
                session="CORE",
                entrust_price=entrust_price,
                note="DRY RUN — NO ORDER SUBMITTED" if dry_run else "LIVE SUBMIT",
            )

            log_sections.append(f"[{acct_line}]")
            log_sections.append(ticket)
            log_sections.append("")

            if dry_run:
                resp = _CLIENT.execute_buy(
                    symbol=sym,
                    amount=q,
                    account_number=acct_num,
                    dry_run=True,
                    validation_response=val,
                )
                msg = (resp or {}).get("Message") or "dry run ok"
                out_msg = ticket + f"\nresult: {msg}"
                log_sections.append(f"[{acct_line}] api_result: {msg}")
                log_sections.append("")
                log_path = _write_dry_run_log(content="\n".join(log_sections).rstrip() + "\n")
                return BrokerOutput(
                    broker=BROKER,
                    state="success",
                    accounts=[AccountOutput(account_id=acct_line, ok=True, message=out_msg)],
                    message=f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}",
                )

            resp = _CLIENT.execute_buy(
                symbol=sym,
                amount=q,
                account_number=acct_num,
                dry_run=False,
                validation_response=val,
            )
            msg = (resp or {}).get("Message") or "order placed"
            return BrokerOutput(
                broker=BROKER,
                state="success",
                accounts=[AccountOutput(account_id=acct_line, ok=True, message=msg)],
                message="",
            )

        else:
            hold = _CLIENT.check_stock_holdings(symbol=sym, account_number=acct_num)
            if (hold or {}).get("Outcome") != "Success":
                raise RuntimeError((hold or {}).get("Message") or "Holdings check failed")
            avail = float(((hold.get("Data") or {}).get("enableAmount")) or 0.0)
            if q > avail:
                raise RuntimeError(f"Not enough shares (available {avail})")

            val = _CLIENT.validate_sell(symbol=sym, amount=q, account_number=acct_num)
            if (val or {}).get("Outcome") != "Success":
                raise RuntimeError((val or {}).get("Message") or "Sell validation failed")

            entrust_price = ((val.get("Data") or {}).get("entrustPrice"))

            ticket = _ticket_lines(
                side="SELL",
                symbol=sym,
                quantity=q,
                order_type="MARKET",
                tif="DAY",
                session="CORE",
                entrust_price=entrust_price,
                available_shares=avail,
                note="DRY RUN — NO ORDER SUBMITTED" if dry_run else "LIVE SUBMIT",
            )

            log_sections.append(f"[{acct_line}]")
            log_sections.append(ticket)
            log_sections.append("")

            if dry_run:
                resp = _CLIENT.execute_sell(
                    symbol=sym,
                    amount=q,
                    account_number=acct_num,
                    entrust_price=entrust_price,
                    dry_run=True,
                )
                msg = (resp or {}).get("Message") or "dry run ok"
                out_msg = ticket + f"\nresult: {msg}"
                log_sections.append(f"[{acct_line}] api_result: {msg}")
                log_sections.append("")
                log_path = _write_dry_run_log(content="\n".join(log_sections).rstrip() + "\n")
                return BrokerOutput(
                    broker=BROKER,
                    state="success",
                    accounts=[AccountOutput(account_id=acct_line, ok=True, message=out_msg)],
                    message=f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}",
                )

            resp = _CLIENT.execute_sell(
                symbol=sym,
                amount=q,
                account_number=acct_num,
                entrust_price=entrust_price,
                dry_run=False,
            )
            msg = (resp or {}).get("Message") or "order placed"
            return BrokerOutput(
                broker=BROKER,
                state="success",
                accounts=[AccountOutput(account_id=acct_line, ok=True, message=msg)],
                message="",
            )

    except Exception as e:
        if dry_run:
            log_sections.append(f"[{acct_line}] ERROR: {e}")
            log_sections.append("")
            try:
                log_path = _write_dry_run_log(content="\n".join(log_sections).rstrip() + "\n")
                msg = f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}"
            except Exception:
                msg = "DRY RUN — NO ORDER SUBMITTED"
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id=acct_line, ok=False, message=str(e))],
                message=msg,
            )

        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id=acct_line, ok=False, message=str(e))],
            message=str(e),
        )


def healthcheck(*args, **kwargs) -> BrokerOutput:
    """
    Deprecated in orchestration (no longer used).
    Keep as non-interactive probe for manual/testing usage.
    """
    ok, why = _ensure_session()
    if ok:
        return BrokerOutput(
            broker=BROKER,
            state="success",
            accounts=[AccountOutput(account_id="BBAE", ok=True, message="ok")],
            message="ok",
        )
    return BrokerOutput(
        broker=BROKER,
        state="failed",
        accounts=[AccountOutput(account_id="BBAE", ok=False, message=why)],
        message=why,
    )

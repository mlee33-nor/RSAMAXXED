"""Local file-based broker logging."""
from __future__ import annotations

import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _log_dir(ctx: Dict[str, Any]) -> Path:
    d = Path(ctx.get("log_dir", "logs"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _redact(text: str, secrets: Optional[List[Any]]) -> str:
    if not secrets:
        return text
    out = text
    for s in secrets:
        if s and isinstance(s, str) and len(s) > 2:
            out = out.replace(s, "***")
    return out


def write_log(
    ctx: Dict[str, Any],
    *,
    broker: str,
    action: str,
    label: str,
    filename_prefix: str = "log",
    text: str = "",
    secrets: Optional[List[Any]] = None,
) -> Optional[Path]:
    """Write a log entry to a local file. Returns the path written."""
    try:
        d = _log_dir(ctx)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        fname = f"{filename_prefix}_{broker}_{label}_{ts}.log"
        p = d / fname
        content = _redact(text, secrets)
        p.write_text(f"[{ts}] {broker}/{action}/{label}\n{content}\n", encoding="utf-8")
        return p
    except Exception:
        return None


def log_exception(
    ctx: Dict[str, Any],
    *,
    broker: str,
    action: str,
    label: str,
    exc: BaseException,
    secrets: Optional[List[Any]] = None,
) -> Optional[Path]:
    """Log an exception to a local file."""
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return write_log(
        ctx,
        broker=broker,
        action=action,
        label=label,
        filename_prefix="exception",
        text=f"{type(exc).__name__}: {exc}\n{tb}",
        secrets=secrets,
    )

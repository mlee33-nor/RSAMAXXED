"""Local 2FA / OTP prompt helper.

Returns a plain-text prompt string that the caller can print or send.
"""
from __future__ import annotations


def universal_2fa_prompt(broker: str, extra: str = "") -> str:
    """Build a human-readable OTP prompt string."""
    parts = [f"[{broker}] Enter your 2FA / OTP code"]
    if extra:
        parts.append(f"({extra})")
    parts.append(":")
    return " ".join(parts)

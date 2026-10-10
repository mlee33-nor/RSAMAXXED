"""Account labels are stored masked: no account number, full or last-4.

The desktop app (cloud_sync.mask_account_id) masks every label before upload
with a salt that never leaves the device, e.g.

    "Fidelity Individual (Z12345678)"  ->  "Fidelity Individual #kqzvbm"

The server applies the SAME shape to anything that still carries a 4+ digit
run -- rows stored before the desktop masked, and uploads from a desktop that
has not been updated -- using an HMAC under SECRET_KEY, so the number is never
stored and two accounts still stay two accounts. A masked label has no digit
run (the hash is letters only), so masking is idempotent: running it again,
here or at startup, changes nothing.
"""
from __future__ import annotations

import hashlib
import hmac
import re

from . import config

_DIGIT_RUN = re.compile(r"\d{4,}")
# Keep in step with cloud_sync._ACCT_BRACKETED / _ACCT_TOKEN.
_BRACKETED = re.compile(r"\s*[\(\[\{][^()\[\]{}]*\d{4,}[^()\[\]{}]*[\)\]\}]")
_TOKEN = re.compile(r"\S*\d{4,}\S*")
_ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def needs_mask(raw: str | None) -> bool:
    return bool(raw) and bool(_DIGIT_RUN.search(raw))


def mask_account_id(raw: str | None) -> str:
    """`raw` with every 4+ digit run (and its bracket) replaced by a keyed hash."""
    text = str(raw or "")
    if not needs_mask(text):
        return text[:160]
    digest = hmac.new(config.SECRET_KEY.encode("utf-8"), text.encode("utf-8"),
                      hashlib.sha256).digest()
    tag = "".join(_ALPHABET[b % 26] for b in digest[:6])
    label = _TOKEN.sub("", _BRACKETED.sub("", text))
    label = re.sub(r"\s+", " ", label).strip(" -:·#")
    return (f"{label} #{tag}" if label else f"#{tag}")[:160]

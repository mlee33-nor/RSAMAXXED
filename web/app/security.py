"""Password hashing, bearer tokens, pairing codes, CSRF.

Passwords use stdlib scrypt (memory-hard, no native build step). Tokens are
random 256-bit strings stored only as SHA-256 digests, compared in constant
time. A leaked database therefore yields no usable credential.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

# scrypt cost. n must be a power of two. Memory used is 128 * n * r bytes,
# so n=2**15, r=8 costs ~33 MB and ~90 ms per hash.
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_DK_LEN = 32


def _maxmem(n: int, r: int) -> int:
    """OpenSSL caps scrypt at 32 MB unless told otherwise, and n=2**15 needs
    more than that — without this, hashing raises "memory limit exceeded".
    Doubling the theoretical requirement leaves room for bookkeeping."""
    return 2 * 128 * n * r


def hash_password(password: str) -> str:
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_DK_LEN,
        maxmem=_maxmem(_SCRYPT_N, _SCRYPT_R),
    )
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    """Parameters come from the stored hash, so raising the cost later still
    verifies passwords hashed under the old settings."""
    try:
        scheme, n_s, r_s, p_s, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        candidate = hashlib.scrypt(
            password.encode("utf-8"), salt=salt,
            n=n, r=r, p=p, dklen=len(expected), maxmem=_maxmem(n, r),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


# ------------------------------------------------------------------- tokens

def new_token() -> str:
    """A fresh bearer token. Shown to its holder once, never stored raw."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Tokens are already full-entropy random, so a plain SHA-256 is correct
    here — there is nothing to brute force, and lookups stay indexable."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ------------------------------------------------------------ pairing codes

# No 0/O, 1/I/L, or U — the pairs a customer would most often misread aloud or
# off a screen. 30 symbols ** 6 = 729M codes, each valid for 10 minutes.
_CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
_CODE_LEN = 6


def new_pairing_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LEN))


def normalize_code(raw: str) -> str:
    """Uppercase and drop separators, so "k7m2-qx" and "K7M2 QX" both pair."""
    return "".join(ch for ch in (raw or "").upper() if ch.isalnum())


def hash_code(code: str) -> str:
    return hashlib.sha256(normalize_code(code).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------- CSRF

def new_csrf() -> str:
    return secrets.token_urlsafe(24)


def csrf_ok(session_token: str | None, form_token: str | None) -> bool:
    if not session_token or not form_token:
        return False
    return hmac.compare_digest(session_token, form_token)

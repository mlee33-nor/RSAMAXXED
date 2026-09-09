"""Every broker login this install has, and what the user calls it.

A household runs more than one set of accounts. Three Public logins are "myles";
another three belong to someone else; the same is true at every other broker.
Until now half the brokers could hold exactly one login and none of them could
be given a name, so the second person's accounts had nowhere to live.

This module is the single place that knows how each broker stores its
credentials, so nothing else has to. Everything else — the ten broker modules,
the Brokers page — asks for `logins("chase")` and gets the same shape back.

THREE STORAGE STYLES, AND WHY THEY ALL STILL EXIST

They are not a design; they are what four different authors did on four
different days, and every one of them is already in a customer's .env:

  * `list`  — FIDELITY=user:pass:totp,user2:pass2:totp2 in one variable
  * `csv`   — FENNEL_EMAIL=a@x.com,b@y.com, one field per login
  * `keyed` — PUBLIC_SECRET_TOKEN_1, _2, _3: one variable per login per field

Rewriting the lot into one convention would be tidy and would also log every
existing user out of every broker at once. So the styles stay, this module
hides them, and the UI above it shows one Add login button per broker.

THE RULE THAT OUTRANKS TIDINESS: LOGIN 1 KEEPS ITS OLD KEYS

For a broker that has only ever held one login, login 1 reads and writes
CHASE_USERNAME exactly as before, and only login 2 and up get the numbered
CHASE_USERNAME_2 form. An upgrade must be invisible: nobody re-enters a
password or re-does a 2FA dance because we added a feature they did not ask
for yet.

The same rule governs account labels, and there it is not politeness but
correctness. `trades.json` records the account_id that `execute_trade`
returned, and `_leg_open_accounts` nets buys against sells on that exact
string. Change what login 1's accounts are called and every open position's
buy stops matching its sell — the Exits board fills with positions that can
never close. Hence `label_prefix`, which is empty for login 1 and only
disambiguates the logins that did not exist before.

TAGS ARE METADATA, NEVER PART OF AN IDENTIFIER

A tag is what a human calls a login: "myles", "mum", "roth stuff". It groups
and filters in the UI and it is stored beside the credentials — it never
reaches an account_id, an order, or the journal. Rename a tag from "myles" to
"Myles" and nothing anywhere breaks, which is the whole point of keeping it
out of the identifiers.
"""

from __future__ import annotations

import os
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

#: A login index above this is a typo or a runaway loop, not a portfolio.
MAX_LOGINS = 50


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


# ---------------------------------------------------------------------------
# What one login is made of, per broker
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Field:
    """One secret on a login form."""

    name: str                 # canonical, stable across brokers: 'username'
    env: str                  # the historical env key for login 1
    label: str                # what the UI calls it
    secret: bool = True       # masked in the UI, never logged
    required: bool = True


@dataclass(frozen=True)
class Schema:
    """How one broker keeps its logins on disk."""

    broker: str               # app key: 'chase'
    display: str              # 'Chase'
    style: str                # 'list' | 'csv' | 'keyed'
    fields: Tuple[Field, ...]
    blob: str = ""            # list/csv style: the one variable holding them all
    sep: str = ":"            # list style: separator between a login's fields

    @property
    def field_names(self) -> Tuple[str, ...]:
        return tuple(f.name for f in self.fields)


def _f(name: str, env: str, label: str, **kw) -> Field:
    return Field(name=name, env=env, label=label, **kw)


SCHEMAS: Dict[str, Schema] = {
    "bbae": Schema(
        broker="bbae", display="BBAE", style="keyed",
        fields=(_f("username", "BBAE_USER", "Email / Username", secret=False),
                _f("password", "BBAE_PASSWORD", "Password"))),
    "chase": Schema(
        broker="chase", display="Chase", style="keyed",
        # Not an email — see the chase-login-silent-reject note. Saying so on
        # the field is cheaper than another four-minute silent timeout.
        fields=(_f("username", "CHASE_USERNAME", "Username (not your email)",
                   secret=False),
                _f("password", "CHASE_PASSWORD", "Password"))),
    "dspac": Schema(
        broker="dspac", display="DSPAC", style="keyed",
        fields=(_f("username", "DSPAC_USER", "Email / Username", secret=False),
                _f("password", "DSPAC_PASSWORD", "Password"))),
    "fennel": Schema(
        broker="fennel", display="Fennel", style="csv", blob="FENNEL_EMAIL",
        fields=(_f("email", "FENNEL_EMAIL", "Email", secret=False),)),
    "fidelity": Schema(
        broker="fidelity", display="Fidelity", style="list", blob="FIDELITY",
        fields=(_f("username", "FIDELITY_USERNAME", "Username", secret=False),
                _f("password", "FIDELITY_PASSWORD", "Password"),
                _f("totp", "FIDELITY_TOTP_SECRET", "TOTP secret (optional)",
                   required=False))),
    "public": Schema(
        # Public has always numbered from 1, so there is no bare key to
        # preserve — PUBLIC_SECRET_TOKEN_1 IS login 1's historical key.
        broker="public", display="Public", style="keyed",
        fields=(_f("token", "PUBLIC_SECRET_TOKEN", "Secret token"),)),
    "robinhood": Schema(
        broker="robinhood", display="Robinhood", style="list", blob="ROBINHOOD",
        fields=(_f("username", "ROBINHOOD_USERNAME", "Username", secret=False),
                _f("password", "ROBINHOOD_PASSWORD", "Password"))),
    "schwab": Schema(
        broker="schwab", display="Schwab", style="list", blob="SCHWAB",
        fields=(_f("username", "SCHWAB_USERNAME", "Username", secret=False),
                _f("password", "SCHWAB_PASSWORD", "Password"),
                _f("totp", "SCHWAB_TOTP_SECRET", "TOTP secret (optional)",
                   required=False))),
    "sofi": Schema(
        broker="sofi", display="SoFi", style="keyed",
        fields=(_f("username", "SOFI_USERNAME", "Username", secret=False),
                _f("password", "SOFI_PASSWORD", "Password"),
                _f("totp", "SOFI_TOTP_SECRET", "TOTP secret (optional)",
                   required=False))),
    "wellsfargo": Schema(
        broker="wellsfargo", display="Wells Fargo", style="keyed",
        fields=(_f("username", "WELLSFARGO_USERNAME", "Username", secret=False),
                _f("password", "WELLSFARGO_PASSWORD", "Password"))),
}

#: Public is the exception to "login 1 keeps the bare key": its historical key
#: is already numbered, so every login including the first is `_<i>`.
_ALWAYS_NUMBERED = {"public"}


# ---------------------------------------------------------------------------
# One login
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Login:
    """One set of credentials at one broker, and the name a human gave it."""

    broker: str
    idx: int                                  # 1-based, matches the env keys
    tag: str = ""                             # "" when the user never named it
    values: Dict[str, str] = field(default_factory=dict)

    @property
    def schema(self) -> Schema:
        return SCHEMAS[self.broker]

    @property
    def label(self) -> str:
        """The positional name: 'Fidelity 1'. Stable, never user-editable."""
        return f"{self.schema.display} {self.idx}"

    @property
    def display(self) -> str:
        """What to show a human: their tag, falling back to the position."""
        return self.tag or self.label

    @property
    def label_prefix(self) -> str:
        """What to prepend to this login's account labels — '' for login 1.

        Login 1 must produce byte-identical account_ids to the single-login
        version of this broker or the journal loses track of every open
        position. See the module docstring.
        """
        return "" if self.idx == 1 else f"{self.schema.display} {self.idx} · "

    def get(self, name: str) -> str:
        return str(self.values.get(name, "") or "").strip()

    @property
    def complete(self) -> bool:
        """Every required field filled in."""
        return all(self.get(f.name) for f in self.schema.fields if f.required)

    def describe(self) -> str:
        """Safe to log: the tag and the non-secret fields, never a password."""
        shown = [self.get(f.name) for f in self.schema.fields
                 if not f.secret and self.get(f.name)]
        who = ", ".join(shown)
        return f"{self.display}" + (f" ({who})" if who else "")


# ---------------------------------------------------------------------------
# Env keys
# ---------------------------------------------------------------------------

def env_key(broker: str, field_name: str, idx: int) -> str:
    """The variable holding one field of one login.

    'chase', 'username', 1 -> CHASE_USERNAME      (historical, unchanged)
    'chase', 'username', 2 -> CHASE_USERNAME_2    (new)
    'public', 'token',    1 -> PUBLIC_SECRET_TOKEN_1  (always numbered)
    """
    schema = SCHEMAS[broker]
    base = next(f.env for f in schema.fields if f.name == field_name)
    if idx == 1 and broker not in _ALWAYS_NUMBERED:
        return base
    return f"{base}_{idx}"


def tag_key(broker: str, idx: int) -> str:
    """Where one login's name lives: CHASE_TAG_1, CHASE_TAG_2, ...

    Numbered from 1 for every broker including the first login, because a tag
    has no history to preserve — it never existed before.
    """
    return f"{SCHEMAS[broker].display.upper().replace(' ', '')}_TAG_{idx}"


def _tag(broker: str, idx: int) -> str:
    return _env(tag_key(broker, idx))


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def _split_list(raw: str, schema: Schema) -> List[Dict[str, str]]:
    """'user:pass:totp,user2:pass2' -> a values dict per login."""
    out: List[Dict[str, str]] = []
    for item in (p.strip() for p in raw.split(",")):
        if not item:
            continue
        parts = item.split(schema.sep)
        values = {}
        for i, f in enumerate(schema.fields):
            values[f.name] = (parts[i].strip() if i < len(parts) else "")
        out.append(values)
    return out


def _read_keyed(schema: Schema) -> List[Tuple[int, Dict[str, str]]]:
    """Numbered variables, keeping each login's own index and skipping gaps.

    THE INDEX IS NOT A POSITION IN A LIST, it is part of the account label —
    Public builds "Public 3 BROKERAGE (1234)" out of it, and that string is the
    key trades.json nets buys against sells on. Someone whose token 2 is blank
    while token 3 is set must keep getting "Public 3", so this scans the whole
    range and preserves the number rather than closing the gap.

    That is also why it cannot stop at the first empty slot the way a tidier
    loop would: it would drop token 3 entirely and take the position with it.
    """
    out: List[Tuple[int, Dict[str, str]]] = []
    for idx in range(1, MAX_LOGINS + 1):
        values = {f.name: _env(env_key(schema.broker, f.name, idx))
                  for f in schema.fields}
        if any(values.values()):
            out.append((idx, values))
    return out


def logins(broker: str) -> List[Login]:
    """Every configured login at one broker, in index order.

    A login with nothing filled in is not a login and never appears here, so
    `len(logins(b))` is the honest count for "how many sets of credentials do
    I have at this broker".
    """
    schema = SCHEMAS.get(broker)
    if schema is None:
        return []

    rows: List[Tuple[int, Dict[str, str]]] = []
    if schema.style in ("list", "csv"):
        raw = _env(schema.blob)
        if raw:
            values = (_split_list(raw, schema) if schema.style == "list"
                      else [{schema.fields[0].name: v.strip()}
                            for v in raw.split(",") if v.strip()])
            # Positional by construction: the blob's comma order IS the
            # numbering these brokers have always labelled accounts with.
            rows = list(enumerate(values, 1))
        # No blob at all: fall back to the single-login keys, which is how
        # every one of these brokers was first set up.
        if not rows:
            rows = _read_keyed(schema)
    else:
        rows = _read_keyed(schema)

    return [Login(broker=broker, idx=idx, tag=_tag(broker, idx), values=values)
            for idx, values in rows if any(values.values())]


def login_count(broker: str) -> int:
    return len(logins(broker))


def all_logins() -> Dict[str, List[Login]]:
    """Every login at every broker — what the Brokers page renders."""
    return {b: logins(b) for b in SCHEMAS}


def tags() -> List[str]:
    """Every distinct tag in use, in first-seen order.

    The list a filter offers. Untagged logins contribute nothing, so an install
    that never names anything shows no filter at all rather than an empty one.
    """
    seen: List[str] = []
    for rows in all_logins().values():
        for login in rows:
            if login.tag and login.tag not in seen:
                seen.append(login.tag)
    return seen


def logins_tagged(tag: str) -> Dict[str, List[Login]]:
    """Every login carrying one tag, by broker. Empty brokers are dropped."""
    want = (tag or "").strip().casefold()
    out: Dict[str, List[Login]] = {}
    for broker, rows in all_logins().items():
        hit = [r for r in rows if r.tag.casefold() == want]
        if hit:
            out[broker] = hit
    return out


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def env_updates(broker: str, rows: Sequence[Dict[str, str]]) -> Dict[str, str]:
    """The full set of variables to write for one broker's logins.

    `rows` is what the editor holds: one dict per login, its field names plus
    an optional 'tag' and, for a login that already exists, the 'idx' it was
    read at. Returns {ENV_KEY: value} for the caller to hand to _save_env_file
    — including EMPTY values for the keys a removed login used to occupy,
    because a delete that only stops writing a key leaves the old password on
    disk and the broker still logging in with it.

    A row that carries its 'idx' is written back at that index, so editing the
    tag on Public 3 does not quietly make it Public 2 and orphan every open
    position recorded under the old label. New rows take the lowest free slot.
    Deleting therefore leaves a gap, which is the correct outcome: the numbers
    that remain still mean what they meant this morning.
    """
    schema = SCHEMAS.get(broker)
    if schema is None:
        return {}

    kept = [r for r in rows
            if any(str(r.get(f.name, "") or "").strip() for f in schema.fields)]
    updates: Dict[str, str] = {}

    if schema.style == "list":
        parts = []
        for r in kept:
            vals = [str(r.get(f.name, "") or "").strip() for f in schema.fields]
            while vals and not vals[-1]:        # don't write trailing ':'
                vals.pop()
            parts.append(schema.sep.join(vals))
        updates[schema.blob] = ",".join(parts)
        # The single-login keys would otherwise shadow nothing but confuse the
        # next reader — the blob wins, so leave them exactly as they are.
    elif schema.style == "csv":
        name = schema.fields[0].name
        updates[schema.blob] = ",".join(
            str(r.get(name, "") or "").strip() for r in kept)
    else:
        placed = _place(kept)
        for idx in range(1, MAX_LOGINS + 1):
            row = placed.get(idx)
            for f in schema.fields:
                key = env_key(broker, f.name, idx)
                if row is None:
                    # Only blank keys that actually exist, so a save does not
                    # append fifty empty variables to everyone's .env.
                    if _env(key):
                        updates[key] = ""
                else:
                    updates[key] = str(row.get(f.name, "") or "").strip()
        kept = [placed[i] for i in sorted(placed)]

    by_idx = _place(kept) if schema.style not in ("list", "csv") else {
        i: r for i, r in enumerate(kept, 1)}
    for idx in range(1, MAX_LOGINS + 1):
        key = tag_key(broker, idx)
        row = by_idx.get(idx)
        if row is not None:
            updates[key] = str(row.get("tag", "") or "").strip()
        elif _env(key):
            updates[key] = ""

    return updates


def _place(rows: Sequence[Dict[str, str]]) -> Dict[int, Dict[str, str]]:
    """{index: row}, honouring the index a row already has.

    An existing login keeps its number so its account labels — and the journal
    keys built from them — stay put. Anything new drops into the lowest free
    slot, which is what makes "Add login" predictable after a delete.
    """
    out: Dict[int, Dict[str, str]] = {}
    fresh: List[Dict[str, str]] = []
    for row in rows:
        try:
            idx = int(row.get("idx") or 0)
        except (TypeError, ValueError):
            idx = 0
        if 1 <= idx <= MAX_LOGINS and idx not in out:
            out[idx] = dict(row)
        else:
            fresh.append(dict(row))

    nxt = 1
    for row in fresh:
        while nxt in out:
            nxt += 1
        if nxt > MAX_LOGINS:
            break
        out[nxt] = row
    return out


def as_rows(broker: str) -> List[Dict[str, str]]:
    """Current logins in the editor's shape — values, 'tag' and 'idx'.

    'idx' is what the editor hands back on save so an existing login keeps its
    number. Dropping it is how an edit silently renumbers a broker.
    """
    out: List[Dict[str, str]] = []
    for login in logins(broker):
        row = dict(login.values)
        row["tag"] = login.tag
        row["idx"] = str(login.idx)
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# For the broker modules
# ---------------------------------------------------------------------------

def session_suffix(idx: int) -> str:
    """What to append to a per-login session directory: '' for login 1.

    Login 1 keeps `sessions/chase/profile` and its cookie jar, so upgrading an
    install does not silently log anyone out and hand them a 2FA prompt they
    were not expecting. Login 2 gets `profile_2`.
    """
    return "" if idx == 1 else f"_{idx}"


# ---------------------------------------------------------------------------
# Running a single-login broker module once per login
# ---------------------------------------------------------------------------
#
# Five of these modules — BBAE, Chase, DSPAC, SoFi, Wells Fargo — were written
# around exactly one set of credentials: module-global clients, one cookie jar,
# one browser profile, one `bbae.pkl`. Teaching each of them to loop internally
# means five separate rewrites of five working login flows, and a broker login
# is the one thing in this app that cannot be tested without a real account.
#
# So none of them are rewritten. Each keeps its single-login body exactly as it
# is, and this driver runs that body once per login with the environment and
# the session directory pointed at that login. One mechanism, tested here,
# instead of five hand-rolled loops.
#
# WHAT MAKES IT SAFE: with one login configured, `fan_out` calls the original
# function once, with the environment untouched and no label prefix — the same
# call the module has always received. The new behaviour only exists from the
# second login onwards.

_active: Dict[str, int] = {}
_locks: Dict[str, threading.Lock] = {}


def active_idx(broker: str) -> int:
    """Which login the module is currently serving. 1 unless fanning out.

    Broker modules read this to pick a session directory: login 1 keeps the
    original path so an upgrade never logs anyone out.
    """
    return _active.get(broker, 1)


def active_suffix(broker: str) -> str:
    """`session_suffix` for whichever login is being served right now."""
    return session_suffix(active_idx(broker))


def _lock(broker: str) -> threading.Lock:
    return _locks.setdefault(broker, threading.Lock())


@contextmanager
def activated(login: "Login", module=None):
    """Make one login the one the broker module sees.

    Its credentials go into the plain env keys the module already reads, and
    `active_idx` points its session directory at that login. Both are restored
    afterwards, so a module that reads the env at import time or caches a path
    is no worse off than before.

    The env is process-global, which is why the caller holds a per-broker lock:
    two logins at the SAME broker must never be in flight together or one would
    read the other's password. Different brokers touch different keys and stay
    parallel, which is how the app fans out its refresh.

    A module that caches a signed-in client in a module global gets told to
    swap it, through an optional `_on_login_switch(idx)`. Without that hook the
    in-memory session check in these modules would hand login 2 the client that
    is already signed in as login 1 — the fan-out would read the first set of
    accounts twice and never touch the second.
    """
    schema = login.schema
    saved: Dict[str, Optional[str]] = {}
    prev = _active.get(login.broker, 1)
    switch = getattr(module, "_on_login_switch", None) if module else None
    try:
        for f in schema.fields:
            saved[f.env] = os.environ.get(f.env)
            os.environ[f.env] = login.get(f.name)
        _active[login.broker] = login.idx
        if switch:
            switch(login.idx)
        yield login
    finally:
        for key, val in saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        _active[login.broker] = prev
        if switch:
            switch(prev)


def _prefixed(out, prefix: str):
    """The same BrokerOutput with every account label prefixed.

    Login 1's prefix is empty, so its account_ids — the strings trades.json
    nets buys against sells on — come through untouched.
    """
    if not prefix:
        return out
    for acct in (getattr(out, "accounts", None) or []):
        try:
            acct.account_id = f"{prefix}{acct.account_id}"
        except Exception:                      # frozen or exotic: leave it be
            pass
    return out


def _merge(broker: str, parts: List, module) -> object:
    """Fold one BrokerOutput per login into the single one callers expect."""
    BrokerOutput = module.BrokerOutput
    accounts: List = []
    states: List[str] = []
    messages: List[str] = []
    extra: Dict[str, object] = {}

    for idx, out in parts:
        accounts.extend(getattr(out, "accounts", None) or [])
        states.append(str(getattr(out, "state", "") or "").lower())
        msg = str(getattr(out, "message", "") or "").strip()
        if msg:
            messages.append(f"[{idx}] {msg}" if len(parts) > 1 else msg)
        for key, val in (getattr(out, "extra", None) or {}).items():
            extra[f"login_{idx}_{key}"] = val

    good = [s for s in states if s in ("success", "partial")]
    if not good:
        state = "failed"
    elif len(good) == len(states) and all(s == "success" for s in states):
        state = "success"
    else:
        # Some logins worked and some did not. "partial" is the honest answer
        # and the one lifecycle.resolve treats as readable-but-incomplete,
        # which is what stops a dead second login being read as "you hold
        # nothing" at the first.
        state = "partial"

    extra["logins_configured"] = len(parts)
    extra["logins_ok"] = len(good)
    return BrokerOutput(broker=getattr(module, "BROKER", broker), state=state,
                        accounts=accounts, message="; ".join(messages), extra=extra)


def fan_out(broker: str, module, fn, *args, **kwargs):
    """Call a single-login `fn` once per configured login and merge the results.

    With zero or one login this is a straight pass-through — including the
    zero case, so a module's own "Missing BBAE_USER" error still reaches the
    user in its own words rather than being replaced by a generic one here.
    """
    rows = logins(broker)
    if len(rows) <= 1:
        if len(rows) == 1:
            with _lock(broker), activated(rows[0], module):
                return fn(*args, **kwargs)
        return fn(*args, **kwargs)

    parts = []
    with _lock(broker):
        for login in rows:
            with activated(login, module):
                try:
                    out = fn(*args, **kwargs)
                except Exception as exc:       # noqa: BLE001
                    # One login blowing up must not cost the others. It is
                    # reported as its own failed account rather than swallowed.
                    out = module.BrokerOutput(
                        broker=getattr(module, "BROKER", broker), state="failed",
                        accounts=[module.AccountOutput(
                            account_id=login.label, ok=False, message=str(exc))],
                        message=str(exc))
            parts.append((login.idx, _prefixed(out, login.label_prefix)))
    return _merge(broker, parts, module)

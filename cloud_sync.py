"""Cloud sync client — links this copy of RSAMAXXED to a web account and pushes the
trade journal so the dashboard at RSAMAXXED Cloud can show it on any device.

What leaves this machine: rows from trades.json (broker, a MASKED account
label, side, symbol, qty, fill price, timestamp) and, optionally, holdings
snapshots with the same masked labels. What never leaves: account numbers --
full or last-4 -- broker usernames, passwords, cookies, session files, 2FA
secrets. This module does not import any broker module and never reads .env or
sessions/.

Account labels are masked by `mask_account_id`: the readable part is kept and
every run of 4+ digits (with whatever is bracketed around it) is replaced by a
short salted hash, e.g. "Fidelity Individual (Z12345678)" ->
"Fidelity Individual #kqzvbm". The salt is random per device and lives only in
cloud_state.json, so the server can tell accounts apart without being able to
recover, or brute-force, the numbers.

Pairing, from the app's point of view:

    state = CloudSync()
    pending = state.begin_pairing()      # -> PendingPair(code="K7M2QX", ...)
    # show pending.code in the GUI, then poll:
    state.poll_pairing(pending)          # -> "pending" | "claimed" | "expired"

Once claimed, the device token is saved to cloud_state.json and every later
call to push_trades()/push_holdings() authenticates with it.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import secrets
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    from modules import atomic
    _replace = atomic.replace
    _write_text = atomic.write_text
except ImportError:
    # The web tests load this file by path, where the repo root cannot go on
    # sys.path (its app.py would shadow the web app's `app` package). The
    # desktop app always has `modules`; this fallback only serves that test.
    _replace = os.replace

    def _write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
        fd, tmp = tempfile.mkstemp(prefix=f".{Path(path).name}.", suffix=".tmp",
                                   dir=str(Path(path).parent))
        try:
            with os.fdopen(fd, "w", encoding=encoding) as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

_log = logging.getLogger(__name__)

import requests

# Where the hosted dashboard lives. Override with RSAMAXXED_CLOUD_URL for local
# dev or a self-hosted deployment. This is the only thing baked into the EXE, and
# it is public information — no secret ships with the build.
#
# The apex domain, not the platform hostname it happens to sit behind today: a
# copy of this app pulled from GitHub reaches whatever the domain points at, and
# survives the host being renamed or moved. Pointing it at the generated
# *.up.railway.app name is what made a fresh clone silently receive no plays at
# all — every feed call 404'd against a hostname that no longer existed.
DEFAULT_BASE_URL = "https://rsamaxxed.com"

_ROOT = Path(__file__).resolve().parent
_STATE_FILE = _ROOT / "cloud_state.json"
_TRADES_FILE = _ROOT / "trades.json"

_TIMEOUT = 20            # seconds per HTTP call
_CHUNK = 400             # trades per request; server caps at 500
_POLL_INTERVAL = 3.0     # seconds between pairing polls
_FEED_CHUNK = 300        # play rows per ingest request; server caps at 500

# Publishing the play feed is an OPERATOR action, not a customer one. Only the
# machine holding this key can write alerts that every subscriber then reads;
# a customer's copy has it unset and simply never publishes.
_FEED_KEY_ENV = "RSAMAXXED_FEED_KEY"

# READING the feed without an account takes the shared board password — the same
# one that opens rsamaxxed.com/plays. A subscriber pastes it here once; a paired
# device never needs it, because its token already identifies the account.
_PLAYS_KEY_ENV = "RSAMAXXED_PLAYS_KEY"


class CloudError(RuntimeError):
    """Any failure that the GUI should surface to the user verbatim."""


class CloudAuthError(CloudError):
    """This machine has no valid board password.

    Kept apart from a plain CloudError because the two need opposite advice. A
    transport failure is transient and the honest thing to say is "we'll retry,
    do nothing". This one never fixes itself: the feed will stay empty until
    the user pastes their password into .env. Telling them to sit and wait —
    which is what a shared error path did — leaves them staring at an empty
    Watchlist forever, sure the app is broken.
    """


@dataclass
class PendingPair:
    code: str
    poll_token: str
    expires_at: str
    pair_url: str


def _machine_id() -> str:
    """A stable, non-identifying id for this install.

    Deliberately NOT a hardware serial or MAC: it's a random UUID generated once
    and kept in cloud_state.json. It exists only so the Devices page can tell two
    of your own machines apart.
    """
    mid = _read_state().get("machine_id")
    if mid:
        return mid
    new = uuid.uuid4().hex
    out: dict[str, str] = {}

    def put(state: dict[str, Any]) -> None:
        out["mid"] = state.setdefault("machine_id", new)

    # An unreadable state file is not rewritten (that would drop the token);
    # this run then just uses a fresh id.
    return out["mid"] if _update_state(put) else new


def _device_name() -> str:
    try:
        return f"{platform.node() or 'Desktop'} ({platform.system()})"[:120]
    except Exception:
        return "Desktop"


class _StateUnreadable(Exception):
    """cloud_state.json exists but could not be opened."""


_STATE_ATTEMPTS = 4
_STATE_DELAY = 0.05
_state_lock = threading.RLock()


def _read_state_strict() -> dict[str, Any]:
    """The state file, or {} when there is none. Raises _StateUnreadable when
    it exists but stays locked through a few retries (Drive, antivirus).

    A file that opens but does not parse is kept aside and treated as empty:
    its token is already unrecoverable, and refusing every write would leave
    the device unable to re-pair.
    """
    if not _STATE_FILE.exists():
        return {}
    err: Exception | None = None
    for attempt in range(_STATE_ATTEMPTS):
        if attempt:
            time.sleep(_STATE_DELAY * (2 ** (attempt - 1)))
        try:
            data = json.loads(_STATE_FILE.read_text("utf-8-sig"))
        except FileNotFoundError:
            return {}
        except OSError as e:
            err = e
            continue
        except ValueError as e:
            err = e
            continue
        return data if isinstance(data, dict) else {}
    if isinstance(err, ValueError):
        try:
            atomic.quarantine(_STATE_FILE)          # type: ignore[name-defined]
        except Exception:
            pass
        _log.warning("cloud_state.json is corrupt (%s); starting it afresh", err)
        return {}
    raise _StateUnreadable(str(err))


def _read_state() -> dict[str, Any]:
    """For reads: an unreadable file reads as empty (not linked, no key)."""
    try:
        return _read_state_strict()
    except _StateUnreadable:
        return {}


def _write_state(state: dict[str, Any]) -> None:
    # atomic; a crash mid-write can't corrupt the token
    _write_text(_STATE_FILE, json.dumps(state, indent=2))


def _update_state(fn: Callable[[dict[str, Any]], None]) -> bool:
    """Read-modify-write cloud_state.json. Returns False -- and writes NOTHING --
    when the file exists but cannot be read.

    _read_state() returns {} for a locked file, and writing `{} + one field`
    back is how a Drive lock used to unlink the device: the device token was
    dropped from the file without a word.
    """
    with _state_lock:
        try:
            state = _read_state_strict()
        except _StateUnreadable as e:
            _log.warning("cloud_state.json could not be read (%s); not "
                         "rewriting it", e)
            return False
        fn(state)
        _write_state(state)
        return True


# ------------------------------------------------------------ account masking

#: Bumped when the masking changes, so the next push re-sends every trade and
#: the server replaces the labels it already holds. See push_trades.
#:   1  the whole label hashed
#:   2  the ACCOUNT hashed (trade_journal.account_key of the canonical label),
#:      so a label that drifts ('Individual' -> 'FinTec', 'Robinhood 1 | ' ->
#:      bare) keeps its token and the web nets it as one account
_MASK_VERSION = 2

# A bracketed group with 4+ digits in it: "(Z12345678)", "[...1234]", "(0001)".
_ACCT_BRACKETED = re.compile(r"\s*[\(\[\{][^()\[\]{}]*\d{4,}[^()\[\]{}]*[\)\]\}]")
# Any other whitespace-delimited token with 4+ digits: "Z12345678", "xxxx1234".
_ACCT_TOKEN = re.compile(r"\S*\d{4,}\S*")
_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def _hash_token(salt: str, raw: str) -> str:
    """Six LETTERS from a salted hash -- letters only, so a masked label never
    contains a digit run and masking it again (here or on the server) is a
    no-op."""
    digest = hashlib.sha256(f"{salt}\x00{raw}".encode("utf-8")).digest()
    return "".join(_TOKEN_ALPHABET[b % 26] for b in digest[:6])


# --- account identity: a port of trade_journal.canonical_account/account_key.
# Ported, not imported: the web tests load this file by path, where the repo
# root (and trade_journal) cannot be on sys.path. tests/test_fix4_sell.py
# checks the two agree.
_LOGIN1_ALIASES = (
    ("robinhood", "Robinhood 1 | ", ""),
    ("schwab", "Schwab 1 (", "Schwab ("),
    ("fennel", "Fennel 1 · ", "Fennel · "),
)
_ACCT_NUM_RE = re.compile(r"\(([^)]*\d[^)]*)\)\s*$")
_LOGIN_RE = re.compile(r"^\s*[A-Za-z][A-Za-z .&'-]*?\s+(\d{1,2})(?=\D|$)")


def _canonical_account(broker: Any, account_id: Any) -> str:
    acct = str(account_id or "")
    b = str(broker or "").lower()
    for ab, old, new in _LOGIN1_ALIASES:
        if b == ab and acct.startswith(old):
            return new + acct[len(old):]
    return acct


def _account_key(label: Any) -> str:
    text = str(label or "").split(" = ")[0].strip()
    m = _ACCT_NUM_RE.search(text)
    if m:
        key = "".join(c for c in m.group(1) if c.isalnum()).upper()
        if key:
            lm = _LOGIN_RE.match(text[:m.start()])
            idx = int(lm.group(1)) if lm else 1
            return f"L{idx}:{key}" if idx > 1 else key
    return text.casefold()


def mask_account_id(raw: Any, salt: str, broker: Any = None) -> str:
    """The account label with its number replaced by a stable salted hash.

    "Fidelity Individual (Z12345678)"  -> "Fidelity Individual #kqzvbm"
    "Public 1 BROKERAGE (0001)"        -> "Public 1 BROKERAGE #pwhtxa"

    The hash is of the ACCOUNT, not the label: the canonical label's
    account_key (its trailing number, plus the login when it is not login 1).
    A label that drifts while the account does not -- Fidelity renaming
    'Individual' to 'FinTec', an old 'Robinhood 1 | ' prefix -- keeps its
    token, and the web nets per token exactly as the desktop nets per
    account_key; hashed on the whole label, a drifted sell met no buy there.
    Two accounts stay two, one account stays one. A label with no 4+ digit run
    carries no number and is uploaded as it is (canonicalized).
    """
    text = _canonical_account(broker, raw) if broker else str(raw or "")
    if not re.search(r"\d{4,}", text):
        return text[:160]
    label = _ACCT_BRACKETED.sub("", text)
    label = _ACCT_TOKEN.sub("", label)
    label = re.sub(r"\s+", " ", label).strip(" -:\u00b7#")
    tok = _hash_token(salt, "acct\x00" + _account_key(text))
    out = f"{label} #{tok}" if label else f"#{tok}"
    return out[:160]


def _account_salt() -> str | None:
    """This device's masking salt, created once and kept in cloud_state.json.

    None when the state file cannot be read or written -- the caller must then
    send nothing rather than an unmasked or inconsistently masked label.
    """
    salt = _read_state().get("account_salt")
    if salt:
        return str(salt)
    out: dict[str, str] = {}

    def put(state: dict[str, Any]) -> None:
        out["salt"] = state.setdefault("account_salt", secrets.token_hex(16))

    try:
        if _update_state(put):
            return out["salt"]
    except OSError:
        pass
    return None


class CloudSync:
    def __init__(self, base_url: str | None = None) -> None:
        # Unset points at the hosted service; set it to run against a local or
        # self-hosted deployment instead.
        self.base_url = (base_url
                         or os.environ.get("RSAMAXXED_CLOUD_URL")
                         or DEFAULT_BASE_URL).rstrip("/")
        self._lock = threading.Lock()

    # ------------------------------------------------------------- plumbing

    def _url(self, path: str) -> str:
        return f"{self.base_url}/api/v1{path}"

    def _post(self, path: str, payload: dict, auth: bool = False,
              extra_headers: dict | None = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if auth:
            token = self.device_token
            if not token:
                raise CloudError("This device isn't linked to an RSAMAXXED Cloud account yet.")
            headers["Authorization"] = f"Bearer {token}"
        headers.update(extra_headers or {})
        try:
            r = requests.post(self._url(path), json=payload, headers=headers, timeout=_TIMEOUT)
        except requests.RequestException as exc:
            raise CloudError(f"Can't reach RSAMAXXED Cloud: {exc}") from exc

        if r.status_code == 401 and auth:
            # The token was revoked from the website. Forget it so the GUI can
            # offer to re-pair instead of retrying forever.
            self.unlink(local_only=True)
            raise CloudError("This device was unlinked. Generate a new pairing code.")
        if r.status_code >= 400:
            detail = ""
            try:
                detail = r.json().get("detail", "")
            except ValueError:
                detail = r.text[:200]
            raise CloudError(f"RSAMAXXED Cloud returned {r.status_code}: {detail}")
        return r.json()

    # ----------------------------------------------------------- link state

    @property
    def device_token(self) -> str | None:
        return _read_state().get("device_token")

    @property
    def is_linked(self) -> bool:
        return bool(self.device_token)

    @property
    def linked_email(self) -> str | None:
        return _read_state().get("user_email")

    def unlink(self, local_only: bool = False) -> None:
        """Forget the token on this machine. `local_only` is used when the server
        has already rejected it. To revoke properly, use the website."""
        def drop(state: dict[str, Any]) -> None:
            state.pop("device_token", None)
            state.pop("user_email", None)
            state.pop("synced_ids", None)
            state.pop("synced_sig", None)

        _update_state(drop)

    # -------------------------------------------------------------- pairing

    def begin_pairing(self) -> PendingPair:
        """Ask the server for a code. The server invents it, not us — that's what
        makes it verifiable when the user types it into the website."""
        data = self._post(
            "/devices/pair/start",
            {"machine_id": _machine_id(), "device_name": _device_name()},
        )
        return PendingPair(
            code=data["code"],
            poll_token=data["poll_token"],
            expires_at=data["expires_at"],
            pair_url=data.get("pair_url", f"{self.base_url}/app/devices"),
        )

    def poll_pairing(self, pending: PendingPair) -> str:
        """One poll. Returns 'pending' | 'claimed' | 'expired' | 'consumed'.
        On 'claimed' the device token is persisted before we return."""
        data = self._post("/devices/pair/poll", {"poll_token": pending.poll_token})
        status = data.get("status", "pending")
        if status == "claimed":
            mid = _machine_id()

            def link(state: dict[str, Any]) -> None:
                state["device_token"] = data["device_token"]
                state["machine_id"] = mid

            if not _update_state(link):
                return "not saved: cloud_state.json could not be read, try again"
            try:
                email = self.whoami().get("user_email")
                _update_state(lambda st: st.__setitem__("user_email", email))
            except CloudError:
                pass  # token is saved; the email is cosmetic
        return status

    def await_pairing(
        self,
        pending: PendingPair,
        should_stop: Callable[[], bool] = lambda: False,
        on_tick: Callable[[int], None] | None = None,
    ) -> str:
        """Blocking poll loop for a background thread. Returns the final status."""
        deadline = time.monotonic() + 10 * 60
        elapsed = 0
        while time.monotonic() < deadline:
            if should_stop():
                return "cancelled"
            status = self.poll_pairing(pending)
            if status != "pending":
                return status
            time.sleep(_POLL_INTERVAL)
            elapsed += int(_POLL_INTERVAL)
            if on_tick:
                on_tick(elapsed)
        return "expired"

    def whoami(self) -> dict:
        token = self.device_token
        if not token:
            raise CloudError("Not linked.")
        try:
            r = requests.get(
                self._url("/me"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise CloudError(f"Can't reach RSAMAXXED Cloud: {exc}") from exc
        if r.status_code == 401:
            self.unlink(local_only=True)
            raise CloudError("This device was unlinked.")
        if r.status_code >= 400:
            raise CloudError(f"RSAMAXXED Cloud returned {r.status_code}")
        return r.json()

    # ----------------------------------------------------------------- push

    def push_trades(self, trades: Iterable[dict] | None = None, force: bool = False,
                    renames: dict[str, str] | None = None) -> dict:
        """Upload trades. Idempotent: the server keys on each trade's UUID, so a
        re-push of the whole journal inserts nothing new.

        We still track what was synced locally to avoid shipping 876 rows on
        every launch. `force=True` ignores that and re-sends everything, which
        is the right move after re-linking to a different account.

        EDITS ARE RE-SENT. Each synced row's upload is fingerprinted
        (synced_sig), and a row whose upload would now differ -- a price
        backfilled after a push raced the worker's quote lookup
        (set_fill_prices, backfill_basis.py), a rename learnt since -- goes
        again; the server updates fill_price, symbol and account_id on a uuid
        it already holds. A DELETED row is still not removed from the server.

        Symbols go up RENAME-FOLDED (`renames`, default the stored board's):
        the web has no board, and a buy under AGAE with its sell under AIFA
        otherwise read there as an open position plus a sale with no basis.
        """
        with self._lock:
            if trades is None:
                trades = self._load_trades()
            trades = _fold_for_upload(list(trades), renames)

            salt = _account_salt()
            if salt is None:
                raise CloudError("cloud_state.json could not be read; nothing "
                                 "was uploaded.")
            state = _read_state()
            # Trades uploaded before account labels were masked are re-sent
            # once, so the server replaces the raw labels it holds with the
            # masked ones (and one account keeps one label).
            remask = state.get("account_mask") != _MASK_VERSION
            sigs: dict[str, str] = ({} if (force or remask)
                                    else dict(state.get("synced_sig") or {}))
            cleaned = {t["id"]: _clean(t, salt) for t in trades if t.get("id")}
            want = {cid: _upload_sig(row) for cid, row in cleaned.items()}
            # A row synced before fingerprints existed has no sig and is sent
            # once more; after that only a real change re-sends it.
            queue = [cid for cid, sig in want.items() if sigs.get(cid) != sig]
            if not queue:
                if remask:
                    _update_state(lambda st: st.__setitem__("account_mask", _MASK_VERSION))
                return {"sent": 0, "inserted": 0, "updated": 0, "total": len(trades)}

            sent = inserted = updated = 0
            for i in range(0, len(queue), _CHUNK):
                batch = queue[i:i + _CHUNK]
                result = self._post("/sync/trades",
                                    {"trades": [cleaned[cid] for cid in batch]},
                                    auth=True)
                inserted += result.get("inserted", 0)
                updated += result.get("updated", 0)
                sent += len(batch)
                # Persist progress per chunk: a network drop halfway through a
                # 900-trade backfill shouldn't restart from zero.
                sigs.update((cid, want[cid]) for cid in batch)
                done = i + _CHUNK >= len(queue)

                def mark(st: dict[str, Any], done: bool = done) -> None:
                    st["synced_sig"] = dict(sorted(sigs.items()))
                    # The pre-fingerprint list: superseded, and big.
                    st.pop("synced_ids", None)
                    st["last_sync"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    if done and remask:
                        st["account_mask"] = _MASK_VERSION

                _update_state(mark)

            return {"sent": sent, "inserted": inserted, "updated": updated,
                    "total": len(trades)}

    def push_holdings(self, accounts: Iterable[Any]) -> dict:
        """Upload one snapshot. `accounts` is whatever get_holdings() returned:
        objects with .broker/.account_id/.holdings, or plain dicts."""
        salt = _account_salt()
        if salt is None:
            raise CloudError("cloud_state.json could not be read; nothing was "
                             "uploaded.")
        rows: list[dict] = []
        for acct in accounts:
            broker = _attr(acct, "broker", "")
            account_id = _attr(acct, "account_id", "") or _attr(acct, "account_number", "")
            for h in _attr(acct, "holdings", []) or []:
                rows.append({
                    "broker": str(broker or "")[:40],
                    "account_id": mask_account_id(account_id, salt, broker),
                    "symbol": str(_attr(h, "symbol", "") or "")[:24],
                    "qty": _num(_attr(h, "quantity", _attr(h, "qty", 0))),
                    "value": _opt_num(_attr(h, "value", _attr(h, "market_value", None))),
                })
        rows = [r for r in rows if r["symbol"]]
        if not rows:
            return {"rows": 0}
        return self._post("/sync/holdings", {"holdings": rows}, auth=True)

    # ----------------------------------------------------------- play feed

    @property
    def feed_key(self) -> str:
        """Set only on the operator's machine. Empty everywhere else."""
        return (os.environ.get(_FEED_KEY_ENV) or "").strip()

    @property
    def can_publish_feed(self) -> bool:
        return bool(self.feed_key)

    def publish_feed(self, batch: dict) -> dict:
        """Push parsed alerts to the cloud so every subscriber sees them.

        `batch` is `rsa_feed.FeedBatch.to_json()`. Idempotent server-side on
        each row's `source_id`, so re-publishing the same daily pull inserts
        nothing — which means this can run on every import without care.
        """
        key = self.feed_key
        if not key:
            raise CloudError(
                "No feed key on this machine. Publishing the play feed is an "
                f"operator action — set {_FEED_KEY_ENV} to enable it."
            )

        buys = list(batch.get("buys") or [])
        sells = list(batch.get("sells") or [])
        roundups = list(batch.get("roundups") or [])
        lifecycle = list(batch.get("lifecycle") or [])
        if not (buys or sells or roundups or lifecycle):
            return {"buys": 0, "sells": 0, "roundups": 0, "lifecycle": 0}

        totals = {"buys": 0, "sells": 0, "roundups": 0, "lifecycle": 0}
        # Chunk across all streams together so one huge backfill can't exceed
        # the server's per-request cap.
        for chunk in _chunk_batch(buys, sells, roundups, lifecycle, _FEED_CHUNK):
            result = self._post("/plays/ingest", chunk, extra_headers={"X-Feed-Key": key})
            for k, v in (result.get("inserted") or {}).items():
                totals[k] = totals.get(k, 0) + v
        return totals

    def fetch_export(self) -> dict:
        """EVERY feed row, for the local archive. Operator key required.

        Deliberately not `fetch_feed`: that one is windowed for a terminal, so
        an archive built from it loses everything older than the window.
        """
        key = self.feed_key
        if not key:
            raise CloudError(
                f"Exporting the feed is an operator action — set {_FEED_KEY_ENV}.")
        try:
            r = requests.get(self._url("/plays/export"),
                             headers={"X-Feed-Key": key}, timeout=_TIMEOUT)
        except requests.RequestException as exc:
            raise CloudError(f"Can't reach RSAMAXXED Cloud: {exc}") from exc
        if r.status_code >= 400:
            raise CloudError(f"RSAMAXXED Cloud returned {r.status_code}")
        return r.json()

    def fetch_feed(self) -> dict:
        """The whole feed, already divided into buys / closed / sells / roundups."""
        return self._get("/plays")

    def fetch_sells(self) -> list[dict]:
        """Recent exits, in the shape the desktop's sells.json already holds.

        The third stream a customer cannot get on their own. Rows carry a
        source_id so the terminal can merge them into whatever it already has
        instead of replacing it — an install that once read the feed keeps its
        history when it switches to the feed.
        """
        data = self._get("/plays")
        rows = (data or {}).get("sells") if isinstance(data, dict) else None
        return rows if isinstance(rows, list) else []

    def fetch_lifecycle(self) -> list[dict]:
        """The TRACK board, for a subscriber with no access to the alert channels.

        This is the whole point of putting the board in the cloud: reading it
        from the channels needs a personal user token with access to them, and
        a paying customer has neither. Without this their Exits page is empty
        and they have no way to know which of their positions resolved.
        """
        data = self._get("/plays/lifecycle")
        return data if isinstance(data, list) else []

    def fetch_picks(self) -> list[dict]:
        """Open plays in the three-key shape picks.json has always held.

        This is what lets a customer's terminal read the feed they pay for
        instead of a public JSON blob anyone could rewrite.
        """
        data = self._get("/plays/picks")
        return data if isinstance(data, list) else []

    @property
    def plays_key(self) -> str:
        """The shared board password, for a machine with no account.

        Read from the environment first so a subscriber can paste it into their
        .env, then from cloud_state.json so the GUI can save it once. Empty on a
        machine that has neither, which is the same as having no feed.
        """
        env = (os.environ.get(_PLAYS_KEY_ENV) or "").strip()
        if env:
            return env
        return str(_read_state().get("plays_key") or "").strip()

    def check_plays_key(self, key: str) -> bool:
        """Is this password one the feed accepts? Saves nothing either way.

        Takes the key as an argument rather than reading the stored one on
        purpose: the setup prompt must be able to test what the user just typed
        WITHOUT writing it first. Storing then rolling back would leave a bad
        key on disk if the check died mid-flight, and that is the one state
        that looks identical to a working install from the outside.
        """
        cleaned = (key or "").strip()
        if not cleaned:
            return False
        try:
            r = requests.get(
                self._url("/public/plays/picks"),
                headers={"X-Plays-Key": cleaned},
                timeout=_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise CloudError(f"Can't reach RSAMAXXED Cloud: {exc}") from exc
        if r.status_code == 401:
            return False
        if r.status_code >= 400:
            raise CloudError(f"RSAMAXXED Cloud returned {r.status_code}")
        return True

    def set_plays_key(self, key: str) -> None:
        """Remember the board password on this machine."""
        cleaned = (key or "").strip()

        def put(state: dict[str, Any]) -> None:
            if cleaned:
                state["plays_key"] = cleaned
            else:
                state.pop("plays_key", None)

        _update_state(put)

    def _get(self, path: str) -> Any:
        """Read the feed, with or without an account.

        An unlinked machine reads the same route on the password door instead of
        raising. That is what makes a checkout work without signing up: the
        plays are sold, but they are sold as a password, so anyone who has been
        given one is a customer as far as this call is concerned.

        A linked machine still uses its token, so the server can attribute the
        read and the trade-sync side keeps working exactly as before.
        """
        token = self.device_token
        if not token:
            return self._get_public(path)
        try:
            r = requests.get(
                self._url(path),
                headers={"Authorization": f"Bearer {token}"},
                timeout=_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise CloudError(f"Can't reach RSAMAXXED Cloud: {exc}") from exc
        if r.status_code == 401:
            self.unlink(local_only=True)
            # Don't strand the user on a revoked or stale token: the feed is
            # open, so fall through to it rather than going dark until they
            # notice and re-pair.
            return self._get_public(path)
        if r.status_code == 403:
            return self._get_public(path)
        if r.status_code >= 400:
            raise CloudError(f"RSAMAXXED Cloud returned {r.status_code}")
        return r.json()

    def _get_public(self, path: str) -> Any:
        """The same route, on the shared-password door. See /public/* in
        web/app/routes/api.py.

        A 401 here means one specific, fixable thing, so it says so rather than
        surfacing a bare status code: this machine has no board password, or the
        one it has is wrong.
        """
        key = self.plays_key
        headers = {"X-Plays-Key": key} if key else {}
        try:
            r = requests.get(self._url(f"/public{path}"), headers=headers, timeout=_TIMEOUT)
        except requests.RequestException as exc:
            raise CloudError(f"Can't reach RSAMAXXED Cloud: {exc}") from exc
        if r.status_code == 401:
            raise CloudAuthError(
                "The play feed needs the board password on this machine. Set "
                f"{_PLAYS_KEY_ENV} in your .env (or link this device to your account)."
            )
        if r.status_code >= 400:
            raise CloudError(f"RSAMAXXED Cloud returned {r.status_code}")
        return r.json()

    # ------------------------------------------------------------- internal

    @staticmethod
    def _load_trades() -> list[dict]:
        if not _TRADES_FILE.exists():
            return []
        try:
            return json.loads(_TRADES_FILE.read_text("utf-8-sig"))
        except (json.JSONDecodeError, OSError):
            return []


def _chunk_batch(buys: list, sells: list, roundups: list, lifecycle: list, size: int):
    """Split the parallel streams into requests of at most `size` rows total.

    Yields at least one payload only when there is something to send; an empty
    batch never reaches the network.
    """
    streams = [("buys", buys), ("sells", sells),
               ("roundups", roundups), ("lifecycle", lifecycle)]

    def _empty() -> dict[str, list]:
        return {"buys": [], "sells": [], "roundups": [], "lifecycle": []}

    payload = _empty()
    count = 0
    for name, rows in streams:
        for row in rows:
            payload[name].append(row)
            count += 1
            if count >= size:
                yield payload
                payload = _empty()
                count = 0
    if count:
        yield payload


_ALLOWED = ("id", "timestamp", "broker", "account_id", "side", "symbol", "qty", "fill_price")


def _fold_for_upload(rows: list[dict], renames: dict[str, str] | None) -> list[dict]:
    """Rows with every renamed ticker filed under the name it was bought as.

    A port of trade_journal.fold_renames (the web tests load this file alone).
    `renames` is CURRENT -> bought-under; None reads the stored board, and a
    board that cannot be read folds nothing rather than failing the push.
    """
    if renames is None:
        try:
            import lifecycle
            renames = lifecycle.saved_renames()
        except Exception:                       # noqa: BLE001 — best effort
            renames = {}
    m = {str(k).upper(): str(v).upper() for k, v in (renames or {}).items() if k and v}
    if not m:
        return rows
    out = []
    for t in rows:
        sym = str(t.get("symbol") or "").upper()
        old = m.get(sym)
        out.append(dict(t, symbol=old, executed_symbol=t.get("symbol"))
                   if old and old != sym else t)
    return out


def _upload_sig(row: dict) -> str:
    """A short fingerprint of what one row uploads as. Changes when anything
    the server would store changes (a backfilled price, a folded symbol, a
    re-masked label)."""
    blob = json.dumps(row, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


def _clean(t: dict, salt: str | None = None) -> dict:
    """Whitelist the fields we upload. If trades.json ever grows a field that
    shouldn't be public, it stays home unless it's added here on purpose.

    account_id is in the whitelist but never leaves as it is: Fidelity rows
    carry the FULL account number, the rest a last-4. It is masked with this
    device's salt (push_trades always passes one; the fallback is a fresh
    random salt, which still never uploads a number).
    """
    out = {k: t.get(k) for k in _ALLOWED}
    out["account_id"] = mask_account_id(out.get("account_id"),
                                        salt or secrets.token_hex(16),
                                        out.get("broker"))
    return out


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _opt_num(v: Any) -> float | None:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None

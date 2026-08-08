"""Cloud sync client — links this copy of RSAMAXXED to a web account and pushes the
trade journal so the dashboard at RSAMAXXED Cloud can show it on any device.

What leaves this machine: rows from trades.json (broker, account label, side,
symbol, qty, fill price, timestamp) and, optionally, holdings snapshots. What
never leaves: broker usernames, passwords, cookies, session files, 2FA secrets.
This module does not import any broker module and never reads .env or sessions/.

Pairing, from the app's point of view:

    state = CloudSync()
    pending = state.begin_pairing()      # -> PendingPair(code="K7M2QX", ...)
    # show pending.code in the GUI, then poll:
    state.poll_pairing(pending)          # -> "pending" | "claimed" | "expired"

Once claimed, the device token is saved to cloud_state.json and every later
call to push_trades()/push_holdings() authenticates with it.
"""
from __future__ import annotations

import json
import os
import platform
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

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
    state = _read_state()
    mid = state.get("machine_id")
    if not mid:
        mid = uuid.uuid4().hex
        state["machine_id"] = mid
        _write_state(state)
    return mid


def _device_name() -> str:
    try:
        return f"{platform.node() or 'Desktop'} ({platform.system()})"[:120]
    except Exception:
        return "Desktop"


def _read_state() -> dict[str, Any]:
    if not _STATE_FILE.exists():
        return {}
    try:
        return json.loads(_STATE_FILE.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_state(state: dict[str, Any]) -> None:
    tmp = _STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(_STATE_FILE)  # atomic; a crash mid-write can't corrupt the token


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
        state = _read_state()
        state.pop("device_token", None)
        state.pop("user_email", None)
        state.pop("synced_ids", None)
        _write_state(state)

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
            state = _read_state()
            state["device_token"] = data["device_token"]
            state["machine_id"] = _machine_id()
            _write_state(state)
            try:
                state["user_email"] = self.whoami().get("user_email")
                _write_state(state)
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

    def push_trades(self, trades: Iterable[dict] | None = None, force: bool = False) -> dict:
        """Upload trades. Idempotent: the server keys on each trade's UUID, so a
        re-push of the whole journal inserts nothing new.

        We still track synced ids locally to avoid shipping 876 rows on every
        launch. `force=True` ignores that cache and re-sends everything, which is
        the right move after re-linking to a different account.
        """
        with self._lock:
            if trades is None:
                trades = self._load_trades()
            trades = list(trades)

            state = _read_state()
            synced: set[str] = set() if force else set(state.get("synced_ids", []))
            queue = [t for t in trades if t.get("id") and t["id"] not in synced]
            if not queue:
                return {"sent": 0, "inserted": 0, "total": len(trades)}

            sent = inserted = 0
            for i in range(0, len(queue), _CHUNK):
                batch = queue[i:i + _CHUNK]
                result = self._post("/sync/trades", {"trades": [_clean(t) for t in batch]}, auth=True)
                inserted += result.get("inserted", 0)
                sent += len(batch)
                # Persist progress per chunk: a network drop halfway through a
                # 900-trade backfill shouldn't restart from zero.
                synced.update(t["id"] for t in batch)
                state = _read_state()
                state["synced_ids"] = sorted(synced)
                state["last_sync"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                _write_state(state)

            return {"sent": sent, "inserted": inserted, "total": len(trades)}

    def push_holdings(self, accounts: Iterable[Any]) -> dict:
        """Upload one snapshot. `accounts` is whatever get_holdings() returned:
        objects with .broker/.account_id/.holdings, or plain dicts."""
        rows: list[dict] = []
        for acct in accounts:
            broker = _attr(acct, "broker", "")
            account_id = _attr(acct, "account_id", "") or _attr(acct, "account_number", "")
            for h in _attr(acct, "holdings", []) or []:
                rows.append({
                    "broker": str(broker or "")[:40],
                    "account_id": str(account_id or "")[:160],
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
        instead of replacing it — an install that once read Discord keeps its
        history when it switches to the feed.
        """
        data = self._get("/plays")
        rows = (data or {}).get("sells") if isinstance(data, dict) else None
        return rows if isinstance(rows, list) else []

    def fetch_lifecycle(self) -> list[dict]:
        """The TRACK board, for a subscriber who is not in the alert Discord.

        This is the whole point of putting the board in the cloud: reading it
        from Discord needs a personal user token with access to the channel, and
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

    def set_plays_key(self, key: str) -> None:
        """Remember the board password on this machine."""
        state = _read_state()
        cleaned = (key or "").strip()
        if cleaned:
            state["plays_key"] = cleaned
        else:
            state.pop("plays_key", None)
        _write_state(state)

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
            return json.loads(_TRADES_FILE.read_text("utf-8"))
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


def _clean(t: dict) -> dict:
    """Whitelist the fields we upload. If trades.json ever grows a field that
    shouldn't be public, it stays home unless it's added here on purpose."""
    return {k: t.get(k) for k in _ALLOWED}


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

"""Reading the RSA alert channels off Discord.

The transport half of the pick pipeline: this module knows how to *get* the
messages, `rsa_feed` knows how to *read* them. Nothing here parses an alert and
nothing here decides what to do with one.

It exists as its own file so the desktop GUI and the headless publisher
(`publish_feed.py`) share one implementation. The publisher runs on a server
with no display, so it can't import `app.py` — before this split it would have
needed a second copy of the fetch logic, and the two would have drifted the
first time Discord changed a header.

Stdlib only, no side effects on import.

NOTE: these calls authenticate with a *user* token, which is against Discord's
ToS. Personal use, low poll rate — the same caveat the GUI shows.

    msgs, err = fetch(channel_id, token, limit=50)
    cid, guild, err = resolve_channel(token, "BUY")
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Optional

__all__ = ["API", "fetch", "api_get", "resolve_channel", "message_text"]

API = "https://discord.com/api/v10"

_TIMEOUT = 10

# Discord rejects the default urllib agent outright, so every request claims a
# browser. The token goes in bare — a user token carries no 'Bot ' prefix.
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Shared status-code wording, so the GUI and the job report a bad token the
# same way. `fetch` overrides a couple with channel-specific phrasing.
_HTTP_ERRORS = {
    401: "Invalid token (401)",
    403: "Forbidden (403)",
    404: "Not found (404)",
    429: "Rate limited (429)",
}


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": (token or "").strip(),
        "User-Agent": _UA,
        "Content-Type": "application/json",
    }


def api_get(url: str, token: str) -> tuple:
    """Generic authenticated GET -> (data, error). Never raises."""
    req = urllib.request.Request(url, headers=_headers(token))
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as e:
        return None, _HTTP_ERRORS.get(e.code, f"HTTP error {e.code}")
    except Exception as e:
        return None, str(e)[:80]


def fetch(channel_id: str, token: str, after: Optional[str] = None,
          limit: int = 50) -> tuple:
    """Return (messages, error). Messages come back newest-first.

    `after` is a message id — pass the last one seen to poll incrementally.
    Omit it to re-read the tail of the channel, which is what a stateless
    scheduled job wants: publishing is idempotent, so re-reading is free.
    """
    token = (token or "").strip()
    channel_id = (channel_id or "").strip()
    if not token or not channel_id:
        return [], "Enter your Discord token and channel ID first."

    url = f"{API}/channels/{channel_id}/messages?limit={int(limit)}"
    if after:
        url += f"&after={after}"

    req = urllib.request.Request(url, headers=_headers(token))
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        return (data, None) if isinstance(data, list) else ([], "Unexpected response")
    except urllib.error.HTTPError as e:
        return [], {
            403: "No access to that channel (403)",
            404: "Channel not found (404)",
            429: "Rate limited (429) — try again shortly",
        }.get(e.code, _HTTP_ERRORS.get(e.code, f"HTTP error {e.code}"))
    except Exception as e:
        return [], str(e)[:80]


def resolve_channel(token: str, channel: str, server: str = "") -> tuple:
    """Resolve a channel NAME (e.g. 'BUY') to its numeric id by scanning the
    user's guilds. Returns (channel_id, guild_name, error).

    A numeric input is returned as-is, so callers can accept either without
    caring which they were given. Pass a server name to narrow the search —
    it saves one request per guild that doesn't match.
    """
    channel = (channel or "").strip().lstrip("#")
    if not channel:
        return None, None, "No channel specified"
    if channel.isdigit():
        return channel, None, None

    name = channel.lower()
    server = (server or "").strip().lower()
    guilds, err = api_get(f"{API}/users/@me/guilds", token)
    if err:
        return None, None, err
    if not isinstance(guilds, list):
        return None, None, "Could not list your servers"

    for g in guilds:
        if server and server not in (g.get("name", "") or "").lower():
            continue
        chans, e2 = api_get(f"{API}/guilds/{g['id']}/channels", token)
        if e2 or not isinstance(chans, list):
            continue
        for c in chans:
            # 0 = text, 5 = announcement
            if c.get("type") in (0, 5) and (c.get("name", "") or "").lower() == name:
                return str(c["id"]), g.get("name", ""), None

    where = f" in '{server}'" if server else " in your servers"
    return None, None, f"No #{channel} channel found{where}"


def message_text(msg: dict[str, Any]) -> str:
    """Flatten a message's content plus any embed text.

    Only useful for channels the bot doesn't drive — `rsa_feed` reads embeds
    field by field and never wants them squashed into one blob.
    """
    parts = [msg.get("content", "") or ""]
    for e in msg.get("embeds", []) or []:
        parts.append(e.get("title", "") or "")
        parts.append(e.get("description", "") or "")
        for f in e.get("fields", []) or []:
            parts.append(f.get("name", "") or "")
            parts.append(f.get("value", "") or "")
        parts.append((e.get("footer", {}) or {}).get("text", "") or "")
    return "\n".join(p for p in parts if p)

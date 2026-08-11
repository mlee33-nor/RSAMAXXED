#!/usr/bin/env python3
"""Desktop GUI for broker automation — RSAMAXXED.

Manages all 10 brokers: credentials, bootstrap, holdings, trades, P/L.
Uses only tkinter (ships with Python) — no extra dependencies.

EXE packaging:
    pip install pyinstaller && pyinstaller --onefile --windowed app.py
"""
from __future__ import annotations

import builtins
import hashlib
import importlib
import json
import os
import queue
import re
import threading
import tkinter as tk
import winsound
from datetime import datetime, timezone
from pathlib import Path
from tkinter import ttk, messagebox
from typing import Any, Dict, List, Optional, Tuple

import urllib.request
import urllib.error

import customtkinter as ctk
from dotenv import load_dotenv

from modules.outputs import BrokerOutput, log_event
import discord_feed
import lifecycle
import logo
import mirror_journal
import rsa_feed
import trade_journal

# Optional cloud dashboard sync. Deliberately best-effort: RSAMAXXED must run and
# trade whether or not the cloud exists, is reachable, or has ever been paired.
# Nothing below this import is allowed to gate execution.
try:
    import cloud_sync
    CLOUD_AVAILABLE = True
except Exception:  # missing module, missing requests, anything at all
    cloud_sync = None  # type: ignore[assignment]
    CLOUD_AVAILABLE = False

# Quick Picks used to sync through a public jsonblob URL: unauthenticated, and
# writable by anyone holding the link — which meant every copy of this app, since
# the link was hard-coded right here. Any user (or anyone who read the source)
# could rewrite or wipe the pick list for everybody. It now syncs through the
# authenticated cloud feed instead; see _fetch_quick_picks / _push_picks_remote.

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent
ENV_FILE = ROOT_DIR / ".env"
LOG_DIR = ROOT_DIR / "logs"  # persistent trade_results.log lives here
CUSTOM_ACCOUNTS_FILE = ROOT_DIR / "custom_accounts.json"
MIRROR_STATE_FILE = ROOT_DIR / "mirror_state.json"
AUTOSELL_STATE_FILE = ROOT_DIR / "autosell_state.json"

# How many plays one TRACK pull is allowed to auto-sell.
#
# A cap, not a throttle. If a pull ever reports fifteen plays going fractional
# at once, the likely cause is a parsing change or a board rebuild rather than
# fifteen real corporate actions — and the failure mode of "sell everything it
# thinks it sees" is unrecoverable. Anything over the cap is logged and left for
# a human, which is the right way round.
AUTOSELL_MAX_PER_PULL = 4

# The queue polls every 5s while a trade is in flight. 120 ticks = 10 minutes,
# after which it stops waiting and says which plays it abandoned. A browser
# broker can genuinely take minutes, so this is well past slow — it is the
# ceiling on "something is wedged", and the alternative is a queue that waits
# in silence for the life of the process, which looks exactly like auto-sell
# being switched off.
AUTOSELL_WAIT_TICKS = 120

# How many times one play may be handed back before auto-sell stops trying.
#
# Every hand-back re-queues the play, and re-queuing it drives another holdings
# read, and a holdings read is a broker LOGIN. A broker that cannot authenticate
# at all — SoFi behind a Turnstile human check — therefore turns an unbounded
# retry into an unbounded login loop against that broker. Three is enough to
# ride out a dropped session and few enough that a real blocker escalates to a
# human instead of hammering the door.
AUTOSELL_MAX_ATTEMPTS = 3

load_dotenv(ENV_FILE)


def _load_custom_accounts() -> List[Dict[str, Any]]:
    if not CUSTOM_ACCOUNTS_FILE.exists():
        return []
    try:
        import json
        return json.loads(CUSTOM_ACCOUNTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_custom_accounts(accounts: List[Dict[str, Any]]) -> None:
    import json
    CUSTOM_ACCOUNTS_FILE.write_text(json.dumps(accounts, indent=2), encoding="utf-8")

BROKER_MODULES = {
    "bbae": "bbae",
    "chase": "chase",
    "dspac": "dspac",
    "fennel": "fennel",
    "fidelity": "fidelity",
    "public": "public",
    "robinhood": "robinhood",
    "schwab": "schwab",
    "sofi": "sofi",
    "wellsfargo": "wellsfargo",
}

# Brokers that use zendriver (headless Chrome) — must be serialized to avoid conflicts
_BROWSER_BROKERS = {"chase", "fidelity", "sofi", "wellsfargo"}
# Each browser broker gets its OWN Chrome slot so different brokers run
# concurrently (Wells Fargo need not wait for Fidelity) — safe because each uses
# a distinct Chrome profile dir and cleanup_orphaned_chrome only touches its own
# profile. The per-broker lock still serializes two ops on the SAME broker
# (same profile would collide). Acquire is bounded so a stuck same-broker op
# can't starve a later one forever — past the backstop it fails with a clear
# message instead of hanging.
_browser_locks: Dict[str, threading.Lock] = {b: threading.Lock() for b in _BROWSER_BROKERS}
_BROWSER_LOCK_TIMEOUT = 1800  # seconds (30 min) — deadlock backstop, not a normal wait
_BROWSER_BUSY_MSG = ("browser busy too long — another operation on this broker may be "
                     "stuck; restart the app and retry")


def _browser_slot(broker: str) -> Optional[threading.Lock]:
    """Per-broker Chrome lock (None for API brokers that don't use a browser)."""
    return _browser_locks.get(broker)

# Known sub-account counts per broker (avoids re-scraping just for the count)
_KNOWN_ACCOUNT_COUNTS: Dict[str, int] = {
    "fidelity": 10,
    "wellsfargo": 10,
    "robinhood": 3,
}

BROKER_ENV_KEYS: Dict[str, List[str]] = {
    "bbae":       ["BBAE_USER", "BBAE_PASSWORD"],
    "chase":      ["CHASE_USERNAME", "CHASE_PASSWORD"],
    "dspac":      ["DSPAC_USER", "DSPAC_PASSWORD"],
    "fennel":     ["FENNEL_EMAIL"],
    "fidelity":   ["FIDELITY_USERNAME", "FIDELITY_PASSWORD", "FIDELITY_TOTP_SECRET"],
    "public":     ["PUBLIC_SECRET_TOKEN_1", "PUBLIC_SECRET_TOKEN_2", "PUBLIC_SECRET_TOKEN_3"],
    "robinhood":  ["ROBINHOOD_USERNAME", "ROBINHOOD_PASSWORD"],
    "schwab":     ["SCHWAB_USERNAME", "SCHWAB_PASSWORD", "SCHWAB_TOTP_SECRET"],
    "sofi":       ["SOFI_USERNAME", "SOFI_PASSWORD", "SOFI_TOTP_SECRET"],
    "wellsfargo": ["WELLSFARGO_USERNAME", "WELLSFARGO_PASSWORD"],
}

# ---------------------------------------------------------------------------
# Modern SaaS Color Palette
# ---------------------------------------------------------------------------

def _blend(c1: str, c2: str, t: float) -> str:
    """Linear-blend two #rrggbb colors. t=0 -> c1, t=1 -> c2.

    Tk has no alpha channel, so 8-digit "#rrggbbaa" colors raise TclError.
    Any "translucent" tint is pre-blended against its backdrop here and
    stored as a solid 6-digit hex string.
    """
    a = c1.lstrip("#")
    b = c2.lstrip("#")
    r = round(int(a[0:2], 16) * (1 - t) + int(b[0:2], 16) * t)
    g = round(int(a[2:4], 16) * (1 - t) + int(b[2:4], 16) * t)
    bl = round(int(a[4:6], 16) * (1 - t) + int(b[4:6], 16) * t)
    return f"#{r:02x}{g:02x}{bl:02x}"


# ── Monochrome "fintech terminal" surfaces — true-black base, cool graphite
#    steps for depth. The ONLY saturated colors are the single pop ACCENT and
#    the semantic GREEN/RED/YELLOW. Everything else is greyscale.
BG_PRIMARY   = "#08090c"   # app background — near-black, faint cool cast
BG_SECONDARY = "#0c0e13"   # secondary panels / rails
BG_CARD      = "#101218"   # card surfaces
BG_CARD_ALT  = "#161922"   # card hover / alternate rows
BG_INPUT     = "#13151c"   # input fields
BG_ELEVATED  = "#1b1f2a"   # elevated / popover surfaces
BORDER       = "#1f2330"   # hairline borders
BORDER_LIGHT = "#2c3140"   # hover / focus borders

TEXT_PRIMARY   = "#f3f4f8"  # main text (near-white)
TEXT_SECONDARY = "#8b90a0"  # muted labels
TEXT_MUTED     = "#565b6b"  # disabled / placeholder

# The single "pop" — electric indigo-violet. Used sparingly: brand, active
# nav, selected chips, primary buttons, key chart highlight.
ACCENT         = "#7c78ff"  # primary pop
ACCENT_HOVER   = "#928fff"  # lighter hover
ACCENT_PRESS   = "#6360e6"  # pressed state

GREEN          = "#34d39e"  # success / profit
RED            = "#fb6f84"  # error / loss
YELLOW         = "#f2c14e"  # warning
# Non-semantic hues collapsed to cool greys so the palette stays monochrome.
BLUE           = "#7f8aa6"  # steel (was info blue)
ORANGE         = "#a39fb0"  # graphite (was orange)
PINK           = "#9aa0b5"  # graphite (was pink)

# Pre-blended tints (Tk has no alpha channel — see _blend)
GREEN_DIM      = _blend(GREEN, BG_CARD, 0.80)   # fill under positive curve
RED_DIM        = _blend(RED, BG_CARD, 0.80)     # fill under negative curve
ACCENT_DIM     = _blend(ACCENT, BG_CARD, 0.80)
ACCENT_GLOW    = _blend(ACCENT, BG_PRIMARY, 0.80)
ACCENT_SEL     = _blend(ACCENT, BG_CARD, 0.68)  # table row selection
GREEN_SOFT     = _blend(GREEN, BG_CARD, 0.86)   # subtle positive panel tint
RED_SOFT       = _blend(RED, BG_CARD, 0.86)     # subtle negative panel tint
GRID_LINE      = _blend(BORDER, BG_CARD, 0.30)  # chart gridlines
BG_HERO        = _blend(ACCENT, BG_CARD, 0.92)  # indigo-washed hero panel

SIDEBAR_BG     = "#0a0b0f"  # sidebar background
SIDEBAR_HOVER  = "#14171f"  # sidebar item hover
SIDEBAR_ACTIVE = _blend(ACCENT, SIDEBAR_BG, 0.88)  # active sidebar item bg

# Monochrome chart ramp — graphite tones anchored by the pop accent, so
# multi-series charts stay on-brand instead of rainbow.
CHART_PALETTE = [ACCENT, "#aeb3c2", "#7c8294", "#565b6b",
                 "#b7adff", "#9095a6", "#cdd1db", "#3f4452"]

# Fonts
FONT_FAMILY = "Segoe UI"
FONT_MONO   = "Cascadia Code"  # fallback to Consolas — tabular figures for $ values

# ---------------------------------------------------------------------------
# CustomTkinter appearance
# ---------------------------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


def _widget_bg(widget) -> Optional[str]:
    """Best-effort background hex of any tk/CTk widget — used so CTk-backed
    cards/buttons blend their rounded corners into the parent surface."""
    try:
        return widget.cget("bg")
    except Exception:
        pass
    try:
        fg = widget.cget("fg_color")
        if isinstance(fg, (list, tuple)):
            fg = fg[1] if ctk.get_appearance_mode() == "Dark" else fg[0]
        if isinstance(fg, str) and fg.startswith("#"):
            return fg
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Iconography — native Windows 11 line icons (verified code points)
# ---------------------------------------------------------------------------
ICON_FONT = "Segoe Fluent Icons"
ICONS = {
    "dashboard": "", "watchlist": "", "positions": "",
    "trade": "", "automation": "", "analytics": "",
    "brokers": "", "activity": "", "settings": "",
    "search": "", "bell": "", "refresh": "",
    "clock": "", "globe": "", "profile": "",
    "add": "", "export": "", "up": "", "down": "",
    "chevright": "", "chevdown": "", "check": "",
    "error": "", "warning": "", "info": "",
    "lightning": "", "starfill": "", "eye": "",
    "pie": "", "edit": "", "delete": "", "bulb": "",
    "more": "", "history": "", "close": "",
}


# Built with chr() rather than pasted: these are Private-Use code points
# that do not survive a copy/paste round-trip through tooling.
ICONS["lock"] = chr(0xE72E)
ICONS["unlock"] = chr(0xE785)


def icon(name: str) -> str:
    return ICONS.get(name, "")


# ---------------------------------------------------------------------------
# Market data — live quotes + watchlist + session status
# ---------------------------------------------------------------------------
WATCHLIST_FILE = ROOT_DIR / "watchlist.json"
# The watchlist is driven by the reverse-split (RSA) Quick Picks — the tickers we
# actually buy. watchlist.json only holds optional ad-hoc EXTRA symbols the user
# pins on top; it is NOT seeded with blue chips.
DEFAULT_WATCHLIST: List[str] = []


def _load_watchlist() -> List[str]:
    try:
        if WATCHLIST_FILE.exists():
            data = json.loads(WATCHLIST_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                seen, out = set(), []
                for s in data:
                    s = str(s).upper().strip()
                    if s and s not in seen:
                        seen.add(s)
                        out.append(s)
                return out
    except Exception:
        pass
    return list(DEFAULT_WATCHLIST)


def _save_watchlist(symbols: List[str]) -> None:
    try:
        WATCHLIST_FILE.write_text(json.dumps(symbols, indent=2), encoding="utf-8")
    except Exception:
        pass


def _fetch_quote(symbol: str) -> Optional[Dict[str, Any]]:
    """Live quote from Yahoo Finance: price, prior close, change, %, sparkline."""
    try:
        url = (f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}"
               f"?range=1d&interval=5m")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        result = data["chart"]["result"][0]
        meta = result["meta"]
        price = float(meta.get("regularMarketPrice"))
        prev = meta.get("chartPreviousClose") or meta.get("previousClose") or price
        prev = float(prev)
        spark: List[float] = []
        try:
            closes = result["indicators"]["quote"][0]["close"]
            spark = [float(c) for c in closes if c is not None]
        except Exception:
            spark = []
        chg = price - prev
        pct = (chg / prev * 100.0) if prev else 0.0
        return {"symbol": symbol.upper(), "price": price, "prev": prev,
                "change": chg, "pct": pct, "spark": spark}
    except Exception:
        return None


def _market_status() -> tuple:
    """Return (state, label, now) for the US equity session. state in
    {open, pre, closed}. Approximate — ignores half-days/holidays."""
    now = datetime.now()
    try:
        from zoneinfo import ZoneInfo
        now = datetime.now(ZoneInfo("America/New_York"))
    except Exception:
        pass
    if now.weekday() >= 5:
        return ("closed", "Markets closed", now)
    mins = now.hour * 60 + now.minute
    if mins < 9 * 60 + 30:
        return ("pre", "Pre-market", now)
    if mins >= 16 * 60:
        return ("closed", "After hours", now)
    return ("open", "Markets open", now)


# Mirror trading checks the pick feed on a fixed intraday schedule rather than
# polling every minute. Hourly through the session: an alert that lands just
# after a check waits an hour to be bought instead of most of the day, and the
# feed request count is still trivial.
#
# :45 rather than on the hour — the first slot deliberately sits 15 minutes
# after the open, past the opening auction, and the last sits 15 minutes before
# the close so a fill still has room. An import triggers its own immediate
# check (_mirror_after_import), so this schedule is the floor, not the only
# path to a buy.
MIRROR_CHECK_TIMES_ET: List[Tuple[int, int]] = [
    (9, 45), (10, 45), (11, 45), (12, 45), (13, 45), (14, 45), (15, 45),
]
MIRROR_HEARTBEAT_MS = 300_000  # 5 min wall-clock re-check — NOT a feed poll

# Pick notes mirror will act on. Everything else (conditional, OTC) is a
# deliberate pass — see _mirror_skip_reason.
MIRROR_NOTES = ("reg alert", "alert", "early access")

# Brokers whose execute_trade() accepts only_accounts=[...] and will trade just
# those. Anything not listed here re-runs its whole account list, so the
# "retry the accounts that failed" action deliberately won't offer it — a retry
# that quietly re-buys the accounts that already filled is worse than no retry.
RETRYABLE_ACCOUNT_BROKERS = ("wellsfargo", "fidelity")


def _mirror_due_slot(now: datetime) -> Optional[str]:
    """Key of the most recent scheduled check `now` has reached, or None when
    the market day hasn't opened one yet.

    A slot stays 'due' until the next one, so a machine that was asleep at
    12:30 still runs that check the moment it wakes instead of skipping the
    window entirely. Weekends have no slots.
    """
    if now.weekday() >= 5:
        return None
    mins = now.hour * 60 + now.minute
    if mins >= 16 * 60:
        return None  # session over — don't fire a catch-up buy after hours
    due: Optional[Tuple[int, int]] = None
    for hh, mm in MIRROR_CHECK_TIMES_ET:
        if mins >= hh * 60 + mm:
            due = (hh, mm)
    if due is None:
        return None
    return f"{now:%Y-%m-%d}@{due[0]:02d}:{due[1]:02d}"


def _mirror_schedule_label() -> str:
    """The schedule in words, for the Mirror page and the activity log.

    Listing seven slots reads as noise, so an evenly spaced run collapses to
    "hourly, 09:45-15:45 ET". Anything irregular still lists every time, which
    is what makes an odd schedule obvious rather than hidden behind a summary.
    """
    times = list(MIRROR_CHECK_TIMES_ET)
    if len(times) >= 3:
        mins = [hh * 60 + mm for hh, mm in times]
        gaps = {b - a for a, b in zip(mins, mins[1:])}
        if len(gaps) == 1:
            gap = gaps.pop()
            if gap == 60:
                every = "hourly"
            elif gap % 60 == 0:
                every = f"every {gap // 60}h"
            else:
                every = f"every {gap}m"
            return (f"{every}, {times[0][0]:02d}:{times[0][1]:02d}"
                    f"-{times[-1][0]:02d}:{times[-1][1]:02d} ET")
    return ", ".join(f"{hh:02d}:{mm:02d}" for hh, mm in times) + " ET"


def _mirror_skip_reason(note: str) -> str:
    """Plain English for why a pick was passed over, from its note.

    Mirror only ever buys a plain Reg Alert. Everything else is a deliberate
    pass with a specific cause, and the Mirror page shows the cause rather than
    a bare 'skipped' — 'the split isn't declared yet' and 'OTC, buy it by hand'
    call for completely different action from the user.
    """
    n = (note or "").lower()
    if "conditional" in n:
        return "conditional — split not declared yet"
    if "otc" in n:
        return "OTC — mirror doesn't auto-buy these"
    if not n:
        return "no alert type on the pick"
    return f"note is '{note}', not a Reg Alert"


# ---------------------------------------------------------------------------
# Discord pick feed — read the RSA-alert channels with the user's own token and
# auto-extract plays (no bot/webhook needed; you just have to be a member).
# NOTE: automating a *user* token is against Discord ToS — personal use, low
# poll rate. Stored in .env (DISCORD_TOKEN / DISCORD_CHANNEL_ID).
#
# TWO channels, because the feed reports a play's life in two places:
#   BUY   rich 'RSA Alert' embeds  -> what to open   -> Quick Picks / Mirror
#   SELL  plain text + 'Round Up Successful' embeds -> what closed, and proof
#         the fraction actually rounded up
# All the message-format knowledge lives in rsa_feed.py; this file only decides
# which channels to read and what to do with the result.
# ---------------------------------------------------------------------------
#
# The HTTP half lives in discord_feed.py so the headless publisher can share it
# (see publish_feed.py); these names are kept as aliases because every call
# site below already uses them.
DISCORD_API = discord_feed.API
_discord_fetch = discord_feed.fetch
_discord_api_get = discord_feed.api_get
_discord_resolve_channel = discord_feed.resolve_channel

DISCORD_STATE_FILE = ROOT_DIR / "discord_state.json"


def _load_discord_state() -> Dict[str, Any]:
    try:
        if DISCORD_STATE_FILE.exists():
            return json.loads(DISCORD_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"enabled": False, "last_id": None, "last_sell_id": None}


def _save_discord_state(state: Dict[str, Any]) -> None:
    try:
        DISCORD_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Design tokens (enterprise design system — 8pt grid, type & radius scales)
# ---------------------------------------------------------------------------
# Spacing scale (px, 4/8 grid)
SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL, SP_3XL = 4, 8, 12, 16, 20, 24, 32
# Corner-radius scale
RAD_SM, RAD_MD, RAD_LG = 10, 14, 18
# Type scale (point sizes)
FS_DISPLAY = 40   # hero numbers
FS_H1      = 22   # page title
FS_H2      = 14   # card title
FS_H3      = 12   # sub-card title
FS_VALUE   = 22   # metric value
FS_BODY    = 10
FS_LABEL   = 9    # uppercase micro-label
FS_MICRO   = 9
FS_NANO    = 8    # axis ticks / captions

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_broker(name: str) -> Any:
    return importlib.import_module(BROKER_MODULES[name])


def _env(key: str) -> str:
    return os.getenv(key, "").strip()


def _broker_has_creds(broker: str) -> bool:
    keys = BROKER_ENV_KEYS.get(broker, [])
    return any(_env(k) for k in keys)


def _public_token_indices() -> List[int]:
    """Indices (1..3) of configured (non-blank) Public API secret tokens.
    Public runs one independent login per token, so each becomes its own
    P1/P2/P3 row in the Command Center broker-status card."""
    return [i for i in (1, 2, 3) if _env(f"PUBLIC_SECRET_TOKEN_{i}")]


def _save_env_file(updates: Dict[str, str]) -> None:
    lines: List[str] = []
    if ENV_FILE.exists():
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()

    existing_keys: set = set()
    new_lines: List[str] = []
    for line in lines:
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=", line)
        if m and m.group(1) in updates:
            key = m.group(1)
            new_lines.append(f"{key}={updates[key]}")
            existing_keys.add(key)
        else:
            new_lines.append(line)

    for key, val in updates.items():
        if key not in existing_keys:
            new_lines.append(f"{key}={val}")

    ENV_FILE.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    for key, val in updates.items():
        os.environ[key] = val


# ---------------------------------------------------------------------------
# Custom Widgets
# ---------------------------------------------------------------------------

class RoundedFrame(ctk.CTkFrame):
    """Premium rounded card backed by CustomTkinter (real anti-aliased corners
    + hairline border). Exposes ``.inner`` — a plain tk.Frame inset just inside
    the rounding — so every existing pack/grid call-site keeps working as-is.
    Children set ``bg=bg_color`` explicitly, matching the card surface.
    """

    def __init__(self, parent, bg_color=BG_CARD, border_color=BORDER,
                 radius=RAD_MD, border_width=1, height=None, **kw):
        kw.pop("width", None)
        parent_bg = _widget_bg(parent)
        super().__init__(
            parent, fg_color=bg_color, border_color=border_color,
            corner_radius=radius, border_width=border_width,
            bg_color=parent_bg if parent_bg else "transparent",
        )
        self._bg_color = bg_color
        # Inset the inner frame so its square corners fall inside the radius.
        inset = border_width + 3
        self._inner = tk.Frame(self, bg=bg_color)
        self._inner.pack(fill="both", expand=True, padx=inset, pady=inset)

    @property
    def inner(self) -> tk.Frame:
        return self._inner


class PillButton(ctk.CTkButton):
    """Pill-shaped button backed by CustomTkinter (smooth hover, real rounded
    corners). Drop-in for the old Canvas button: the ``bg_color`` arg is the
    button *fill* and ``fg_color`` is the *text* color (legacy naming).
    """

    def __init__(self, parent, text="", command=None, bg_color=ACCENT,
                 hover_color=ACCENT_HOVER, fg_color=TEXT_PRIMARY,
                 width=120, height=36, font_size=10, press_color=None):
        parent_bg = _widget_bg(parent)
        super().__init__(
            parent, text=text, command=command,
            width=width, height=height, corner_radius=height // 2,
            fg_color=bg_color, hover_color=hover_color, text_color=fg_color,
            bg_color=parent_bg if parent_bg else "transparent",
            border_width=0, border_spacing=0,
            font=ctk.CTkFont(family=FONT_FAMILY, size=font_size + 1, weight="bold"),
        )

    def configure_text(self, text: str) -> None:
        self.configure(text=text)


class StatusDot(tk.Canvas):
    """Tiny glowing status indicator."""

    def __init__(self, parent, color=TEXT_MUTED, size=10):
        try:
            bg = parent.cget("bg")
        except Exception:
            bg = BG_CARD
        super().__init__(parent, width=size + 6, height=size + 6,
                         highlightthickness=0, bg=bg)
        self._size = size
        self._pad = 3
        self.set_color(color)

    def set_color(self, color: str) -> None:
        self.delete("all")
        s, p = self._size, self._pad
        # glow
        self.create_oval(p - 2, p - 2, p + s + 2, p + s + 2,
                         fill="", outline=color, width=1)
        # solid dot
        self.create_oval(p, p, p + s, p + s, fill=color, outline="")


# Access code that unlocks the Discord Pick Feed settings. The feed ships
# pre-configured so a downloaded copy just works; the lock keeps a stray
# edit from breaking it. It is a fumble-guard, not a secret — the values it
# protects sit in .env in plain text next to this file.
#
# Because it is NOT a secret, the default below must never be a real
# credential. This file is committed to a public repository, so anything
# literal here is published to everyone who clones it. A broker password was
# once used as this code; that published the password. Override the value with
# RSAMAXXED_CONFIG_UNLOCK in .env if you want a different one — and pick a
# string you do not use to log in anywhere.
DISCORD_CONFIG_UNLOCK = os.environ.get(
    "RSAMAXXED_CONFIG_UNLOCK", "").strip() or "unlock-feed-settings"

SELLS_FILE = ROOT_DIR / "sells.json"

# How many days of exits the dashboard SELL card shows. Exits stay useful only
# while you might still be holding the position.
SELL_MAX_AGE_DAYS = 10


def _load_sells() -> List[Dict[str, Any]]:
    """Recorded SELL alerts, newest first. [] if the file is missing/unreadable."""
    try:
        data = json.loads(SELLS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    rows = [s for s in data if isinstance(s, dict)]
    rows.sort(key=lambda s: (str(s.get("sell_date") or ""),
                             str(s.get("posted_at") or "")), reverse=True)
    return rows


def _save_sells(sells: List[Dict[str, Any]]) -> None:
    try:
        SELLS_FILE.write_text(json.dumps(sells, indent=2), encoding="utf-8")
    except OSError:
        pass


def _merge_sells(existing: List[Dict[str, Any]],
                 incoming: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Union on source_id, newest first, aged out past SELL_MAX_AGE_DAYS.

    Discord pulls overlap (the same message can arrive twice after a re-import),
    so dedup on the feed's own message id rather than symbol — the same ticker
    legitimately exits more than once.
    """
    from datetime import timedelta
    cutoff = (datetime.now() - timedelta(days=SELL_MAX_AGE_DAYS)).strftime("%Y-%m-%d")
    by_id: Dict[str, Dict[str, Any]] = {}
    for s in list(existing) + list(incoming):
        if not isinstance(s, dict):
            continue
        sid = str(s.get("source_id") or "")
        key = sid or f"{s.get('symbol')}:{s.get('sell_date')}"
        by_id[key] = s
    rows = [s for s in by_id.values()
            if not s.get("sell_date") or str(s.get("sell_date")) >= cutoff]
    rows.sort(key=lambda s: (str(s.get("sell_date") or ""),
                             str(s.get("posted_at") or "")), reverse=True)
    return rows


def _sell_legs_text(sell: Dict[str, Any]) -> str:
    """'Robinhood x3 · Fidelity x10' — which brokerage the alert says to sell on.

    This is the whole point of the SELL card: the Discord text names the
    brokerages, and that detail was previously parsed and thrown away.
    """
    parts = []
    for leg in sell.get("legs") or []:
        if not isinstance(leg, dict):
            continue
        broker = str(leg.get("broker") or "").strip()
        if not broker:
            continue
        low = int(leg.get("accounts_low") or 0)
        high = int(leg.get("accounts_high") or low)
        n = f"{low}-{high}" if high > low else str(low)
        parts.append(f"{broker} x{n}" if low else broker)
    return "  ·  ".join(parts)


PICKS_FILE = ROOT_DIR / "picks.json"

# Picks auto-expire this many days after their alert date — stale RSA alerts are
# removed automatically on load (locally + pushed back to the shared remote).
# A pick we actually BOUGHT is exempt: it is no longer an alert, it is a record
# of an open RSA position, and the Purchased tab is the only place it lives.
PICK_MAX_AGE_DAYS = 4


# How far back to look when working out how many accounts we actually
# trade. Long enough to survive a quiet week, short enough to drop
# accounts that were renamed or closed.
ACCOUNT_UNIVERSE_WINDOW_DAYS = 60


PICKS_DONE_FILE = ROOT_DIR / "picks_done.json"


def _load_done_picks() -> set:
    """(SYMBOL, date) for picks the user has manually called finished.

    Coverage can't always reach 100%: a broker may be down, an account may be
    restricted, or a name may simply be unbuyable somewhere. Without a manual
    override such a pick would sit in Partial forever.
    """
    try:
        data = json.loads(PICKS_DONE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    out = set()
    for row in data if isinstance(data, list) else []:
        if isinstance(row, (list, tuple)) and len(row) == 2:
            out.add((str(row[0]).upper(), str(row[1])))
    return out


def _save_done_picks(keys: set) -> None:
    try:
        PICKS_DONE_FILE.write_text(
            json.dumps(sorted([list(k) for k in keys]), indent=2), encoding="utf-8")
    except OSError:
        pass


COVERAGE_READ_FILE = ROOT_DIR / "coverage_read.json"


def _coverage_fingerprint(rows: List[tuple]) -> str:
    """Identity of a set of coverage warnings — their text, not their presence.

    Keyed on the wording because the wording carries the numbers: a new symbol,
    a changed dollar amount, or one more unpriced buy all produce a different
    fingerprint. That is the point of dismissing by content rather than by a
    plain hidden/shown flag.
    """
    joined = "\n".join(text for _colour, text in rows)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _load_coverage_read() -> str:
    try:
        data = json.loads(COVERAGE_READ_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    return str(data.get("fingerprint", "")) if isinstance(data, dict) else ""


def _save_coverage_read(fingerprint: str) -> None:
    try:
        COVERAGE_READ_FILE.write_text(
            json.dumps({"fingerprint": fingerprint}, indent=2), encoding="utf-8")
    except OSError:
        pass


TRADE_RESULTS_LOG = ROOT_DIR / "logs" / "trade_results.log"

_TRADE_HEAD_RE = re.compile(
    r"^\[(?P<ts>[\d\-]+ [\d:]+)\]\s+(?P<side>BUY|SELL)\s+\S+\s+(?P<sym>\S+)\s+on\s+"
    r"(?P<broker>\S+)\s*->", re.I)
_TRADE_ROW_RE = re.compile(r"^\s+\[(?P<st>OK|FAIL)\]\s+(?P<acct>.+?):\s*(?P<msg>.*)$")
_ACCT_NUM_RE = re.compile(r"\(([^)]+)\)\s*$")

_trade_attempts_cache: Dict[str, Any] = {"mtime": None, "data": {}}


def _account_key(label: str) -> str:
    """Stable identity for an account across the journal and the trade log.

    The human label drifts — encoding damage ('Fidelity 1 � ETFs'), renames,
    different masking per broker — but the trailing "(number)" does not, so
    match on that.
    """
    label = str(label or "").strip()
    m = _ACCT_NUM_RE.search(label)
    raw = m.group(1) if m else label
    return "".join(c for c in raw if c.isalnum()).upper().lstrip("*") or label.upper()


def _load_trade_attempts() -> Dict[tuple, Dict[str, Any]]:
    """(SYMBOL, broker, account_key) -> {ok, msg, ts, label} from the trade log.

    Failures are not recorded in the journal (only fills are), so this log is
    the only place that remembers *why* an account did not get filled.
    """
    try:
        mtime = TRADE_RESULTS_LOG.stat().st_mtime
    except OSError:
        return {}
    if _trade_attempts_cache["mtime"] == mtime:
        return _trade_attempts_cache["data"]

    out: Dict[tuple, Dict[str, Any]] = {}
    sym = broker = ts = None
    try:
        text = TRADE_RESULTS_LOG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    for line in text.splitlines():
        head = _TRADE_HEAD_RE.match(line)
        if head:
            sym = head.group("sym").upper()
            broker = head.group("broker").lower()
            ts = head.group("ts")
            continue
        row = _TRADE_ROW_RE.match(line)
        if row and sym:
            # Later entries win: a retry that succeeded should not keep showing
            # the earlier rejection.
            out[(sym, broker, _account_key(row.group("acct")))] = {
                "ok": row.group("st") == "OK",
                "msg": row.group("msg").strip(),
                "ts": ts,
                "label": row.group("acct").strip(),
            }
    _trade_attempts_cache["mtime"] = mtime
    _trade_attempts_cache["data"] = out
    return out


def _universe_accounts() -> List[tuple]:
    """(broker, account_id) for every account we have traded recently."""
    from datetime import timedelta
    cutoff = (datetime.now() - timedelta(days=ACCOUNT_UNIVERSE_WINDOW_DAYS)
              ).strftime("%Y-%m-%d")
    try:
        rows = trade_journal.get_trades()
    except Exception:
        return []
    return sorted({(str(t.get("broker") or ""), str(t.get("account_id") or ""))
                   for t in rows if t.get("side") == "buy"
                   and str(t.get("timestamp") or "")[:10] >= cutoff})


def _pick_missing_accounts(symbol: str, pick_date: str) -> List[Dict[str, str]]:
    """Accounts with no confirmed buy of this pick, and why — newest reason wins.

    status is 'failed' when the trade log has a rejection for that account and
    symbol, otherwise 'not attempted'.
    """
    symbol = str(symbol or "").upper()
    bought = set()
    try:
        for t in trade_journal.get_trades():
            if (t.get("side") == "buy"
                    and str(t.get("symbol") or "").upper() == symbol
                    and str(t.get("timestamp") or "")[:10] >= str(pick_date)):
                bought.add((str(t.get("broker") or ""), str(t.get("account_id") or "")))
    except Exception:
        return []

    attempts = _load_trade_attempts()
    missing: List[Dict[str, str]] = []
    for broker, acct in _universe_accounts():
        if (broker, acct) in bought:
            continue
        rec = attempts.get((symbol, broker, _account_key(acct)))
        if rec and not rec.get("ok"):
            missing.append({"broker": broker, "account": acct,
                            "status": "failed", "reason": str(rec.get("msg") or "")})
        else:
            missing.append({"broker": broker, "account": acct,
                            "status": "not attempted", "reason": ""})
    return missing


def _tidy_reason(msg: str, limit: int = 150) -> str:
    """Squeeze a broker rejection into one readable line."""
    msg = re.sub(r"\s+", " ", str(msg or "")).strip()
    # Public wraps the useful part in a JSON blob.
    m = re.search(r'"message"\s*:\s*"([^"]+)"', msg)
    if m:
        msg = m.group(1)
    msg = re.sub(r"^(Skipped|Order failed|Preview failed)\s*:\s*", "", msg, flags=re.I)
    msg = re.sub(r"^.*?HARD Error for \w+\s*:\s*(Error:)?\s*", "", msg, flags=re.I)
    return msg[:limit] + ("…" if len(msg) > limit else "")


def _account_universe_static() -> int:
    """Total accounts we can buy into — the coverage denominator, computed
    without a live App instance.

    _KNOWN_ACCOUNT_COUNTS is only a rough guess (it defaults unlisted brokers
    to 1, so Public's dozen counted as one) and a too-small denominator makes
    a half-filled pick look complete. The journal knows every account we have
    ever actually traded, so take whichever is larger.
    """
    known = sum(_KNOWN_ACCOUNT_COUNTS.get(b, 1) if _broker_has_creds(b) else 0
                for b in BROKER_MODULES)
    try:
        from datetime import timedelta
        # Recent buys only. Over all time the journal also holds accounts that
        # were since renamed or closed (Wells Fargo shows 20 distinct labels
        # for 10 real accounts), and that inflated denominator means no pick
        # ever reads as fully bought.
        cutoff = (datetime.now() - timedelta(days=ACCOUNT_UNIVERSE_WINDOW_DAYS)
                  ).strftime("%Y-%m-%d")
        seen = len({(t.get("broker"), t.get("account_id"))
                    for t in trade_journal.get_trades()
                    if t.get("side") == "buy"
                    and str(t.get("timestamp") or "")[:10] >= cutoff})
    except Exception:
        seen = 0
    return max(known, seen)


def _pick_coverage(picks: List[Dict[str, str]]) -> Dict[tuple, int]:
    """(SYMBOL, pick_date) -> how many distinct accounts hold a confirmed buy.

    A buy counts toward a pick when it is dated on or after the alert date.
    Counting *accounts* (broker + account_id) rather than brokers is what makes
    "bought on 7 of 22" mean something when one broker holds ten accounts.
    """
    cov: Dict[tuple, int] = {}
    try:
        all_trades = trade_journal.get_trades()
    except Exception:
        return cov
    buys: Dict[str, List[tuple]] = {}
    for t in all_trades:
        if t.get("side") != "buy":
            continue
        sym = str(t.get("symbol") or "").upper()
        if not sym:
            continue
        buys.setdefault(sym, []).append(
            (str(t.get("timestamp") or "")[:10],
             str(t.get("broker") or ""), str(t.get("account_id") or "")))
    for pick in picks:
        sym = str(pick.get("symbol") or "").upper()
        pick_date = str(pick.get("date") or "")
        if not sym or not pick_date:
            continue
        cov[(sym, pick_date)] = len({
            (b, a) for (d, b, a) in buys.get(sym, []) if d and d >= pick_date})
    return cov


def _pick_broker_map(picks: List[Dict[str, str]]) -> Dict[tuple, set]:
    """(SYMBOL, pick_date) -> the brokers holding a confirmed buy for it.

    Same rule as _pick_coverage (a buy counts from the alert date on), but keyed
    by broker rather than counted, because "has THIS broker already bought it"
    and "has anyone bought it" are different questions. Mirror needs the first:
    a name bought by hand at Chase says nothing about whether Public holds it.
    """
    out: Dict[tuple, set] = {}
    try:
        all_trades = trade_journal.get_trades()
    except Exception:
        return out
    buys: Dict[str, List[tuple]] = {}
    for t in all_trades:
        if t.get("side") != "buy":
            continue
        sym = str(t.get("symbol") or "").upper()
        if not sym:
            continue
        buys.setdefault(sym, []).append(
            (str(t.get("timestamp") or "")[:10], str(t.get("broker") or "")))
    for pick in picks:
        sym = str(pick.get("symbol") or "").upper()
        pick_date = str(pick.get("date") or "")
        if not sym or not pick_date:
            continue
        out[(sym, pick_date)] = {b for (d, b) in buys.get(sym, [])
                                 if b and d and d >= pick_date}
    return out


def _touched_pick_keys(picks: List[Dict[str, str]]) -> set:
    """Picks with at least one confirmed buy — i.e. real open positions.

    Used where losing the pick would lose history (stale-pick pruning, the
    local/remote merge). Deliberately NOT the Purchased test: a pick bought on
    one broker is still owed on the others.
    """
    return {k for k, n in _pick_coverage(picks).items() if n > 0}


def _purchased_pick_keys(picks: List[Dict[str, str]]) -> set:
    """(SYMBOL, pick_date) for every pick with a confirmed buy in the journal.

    Purchased is the *record* of what we have bought, so any confirmed buy puts
    a pick here. Gating this on full coverage instead emptied the tab, because
    one unreachable broker (Chase, SoFi) means nothing ever reaches 100%.
    Picks still owed accounts also appear under Partial, which is the
    actionable worklist; this tab is the history.
    """
    return _touched_pick_keys(picks) | (set(_pick_coverage(picks)) & _load_done_picks())


def _fully_covered_pick_keys(picks: List[Dict[str, str]]) -> set:
    """Picks held in every account we trade, or manually marked done."""
    universe = _account_universe_static()
    cov = _pick_coverage(picks)
    done = _load_done_picks()
    if universe <= 0:
        return {k for k, n in cov.items() if n > 0} | (set(cov) & done)
    return {k for k, n in cov.items() if n >= universe} | (set(cov) & done)


def _partial_pick_keys(picks: List[Dict[str, str]]) -> set:
    """Bought on some accounts but not all — the top-up worklist.

    Kept out of Quick Picks (which is only work not yet started) so a pick that
    mirror bought on one broker can't hide there, and surfaced separately from
    Purchased so it is obvious which positions still owe accounts.
    """
    return _touched_pick_keys(picks) - _fully_covered_pick_keys(picks)


def _prune_stale_picks(picks: List[Dict[str, str]],
                       max_age_days: int = PICK_MAX_AGE_DAYS) -> tuple:
    """Return (kept, removed_count), dropping picks older than max_age_days.

    Age is measured from each pick's ``date`` field (YYYY-MM-DD). Picks with a
    missing or unparseable date are kept — we can't safely age them out. Picks
    we have already bought are kept forever: expiry exists to clear the
    *available* list, and deleting a bought pick silently wipes the Purchased
    tab and the account-coverage history that goes with it.
    """
    from datetime import date as _date
    today = _date.today()
    # Any confirmed buy exempts a pick from expiry — a partially covered pick
    # is an open position we still owe brokers on, not a stale alert.
    purchased = _touched_pick_keys(picks)
    kept: List[Dict[str, str]] = []
    removed = 0
    for p in picks:
        raw = p.get("date")
        try:
            pd = datetime.strptime(str(raw), "%Y-%m-%d").date()
        except (ValueError, TypeError):
            kept.append(p)  # undated — keep
            continue
        if (str(p.get("symbol") or "").upper(), str(raw)) in purchased:
            kept.append(p)  # bought — never expires
        elif (today - pd).days > max_age_days:
            removed += 1
        else:
            kept.append(p)
    return kept, removed


def _pick_is_fresh(pick: Dict[str, str],
                   max_age_days: int = PICK_MAX_AGE_DAYS) -> bool:
    """True while a pick is still inside its buying window.

    Undated picks count as fresh, matching _prune_stale_picks — we can't age
    out what we can't date, and dropping them silently would be worse than
    considering them.
    """
    from datetime import date as _date
    try:
        pd = datetime.strptime(str(pick.get("date")), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return True
    return (_date.today() - pd).days <= max_age_days


def _merge_picks(*lists: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Union of pick lists on (date, SYMBOL), earlier lists winning on conflict."""
    merged: List[Dict[str, str]] = []
    seen: set = set()
    for picks in lists:
        for p in picks or []:
            key = (str(p.get("date") or ""), str(p.get("symbol") or "").upper())
            if key not in seen:
                seen.add(key)
                merged.append(p)
    merged.sort(key=lambda p: str(p.get("date") or ""))
    return merged


def _local_picks() -> List[Dict[str, str]]:
    """Whatever is in the local cache right now, unpruned. [] if unreadable."""
    if PICKS_FILE.exists():
        try:
            data = json.loads(PICKS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


# Set when the feed refused us for want of a board password, cleared on any
# successful read. Module-level because _cloud_picks() is a plain function that
# the App instance calls, not a method.
_PICKS_AUTH_ERROR: Optional[str] = None


def _cloud_picks() -> Optional[List[Dict[str, str]]]:
    """Open plays from the cloud feed, or None if this copy couldn't read it.

    No account required. An unlinked install reads the open feed (see
    CloudSync._get), which is what lets a fresh checkout show plays on its very
    first launch instead of an empty screen.

    None and [] mean different things here: None is "no answer, keep what you
    have", [] is "the feed says nothing is open". Collapsing them would blank a
    customer's Quick Picks every time their wifi dropped.
    """
    global _PICKS_AUTH_ERROR
    if not CLOUD_AVAILABLE:
        return None
    try:
        picks = cloud_sync.CloudSync().fetch_picks()
    except cloud_sync.CloudAuthError as exc:
        # Still None — the cache is right to survive this. But remember WHY, so
        # the empty state can say "paste your password" instead of "sit tight".
        _PICKS_AUTH_ERROR = str(exc)
        return None
    except Exception:
        return None          # CloudError, or anything the transport threw
    _PICKS_AUTH_ERROR = None
    return picks if isinstance(picks, list) else None


def _push_picks_remote(picks: List[Dict[str, str]]) -> bool:
    """Publish picks to the cloud feed. Operator-only; True if anything was sent.

    Only a machine holding RSAMAXXED_FEED_KEY can write the feed every
    subscriber reads. On a customer's copy this is a no-op that never touches
    the network — which is the point of the change: the build this replaced PUT
    the pick list to a public, keyless URL hard-coded in this file, so any copy
    of the app could rewrite or wipe everyone's picks, ours included.

    Ingest is insert-only and keyed on source_id, so re-publishing the same
    picks costs one round trip and changes nothing.
    """
    if not CLOUD_AVAILABLE or not picks:
        return False
    try:
        client = cloud_sync.CloudSync()
        if not client.can_publish_feed:
            return False
        buys = [b for b in (rsa_feed.from_pick(p) for p in picks) if b is not None]
        if not buys:
            return False
        client.publish_feed(rsa_feed.FeedBatch(buys=buys).to_json())
        return True
    except Exception:
        return False


def _fetch_quick_picks() -> List[Dict[str, str]]:
    """The live pick list: the cloud feed when this copy is linked, the local
    cache when it isn't.

    The feed decides what is *live*, but it can never delete history — a pick we
    have already bought is merged back in from the local cache. Without that, a
    play the server has aged out would silently take the Purchased tab and its
    account-coverage history with it, and those are open positions we still owe
    brokers on.

    Picks older than PICK_MAX_AGE_DAYS are pruned on load and the trimmed list
    written back to disk, which doubles as the offline cache.
    """
    local = _local_picks()
    local_bought = [p for p in local
                    if (str(p.get("symbol") or "").upper(), str(p.get("date") or ""))
                    in _touched_pick_keys(local)]

    remote = _cloud_picks()

    # An EMPTY feed is never allowed to erase a populated cache. The server
    # stores the feed on a disk its host replaces on every deploy, so "no plays
    # at all" is far more often a wiped database than a genuinely quiet day —
    # and the old behaviour wrote that emptiness straight to disk, destroying
    # the only other copy the customer had. Keeping what we hold is safe in
    # both readings: if the feed really is empty, these picks age out on their
    # own within PICK_MAX_AGE_DAYS.
    if remote == [] and any(p for p in local if p not in local_bought):
        data, removed = _prune_stale_picks(local)
        if removed:
            try:
                PICKS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except Exception:
                pass
        return data

    if remote is not None:
        data = _merge_picks(remote, local_bought)
        data, _ = _prune_stale_picks(data)
        try:
            PICKS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass
        return data

    # No feed reachable — the local cache is all we have.
    data, removed = _prune_stale_picks(local)
    if removed:
        try:
            PICKS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass
    return data


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        # First, because the `after` override below reads it and a worker can
        # hand back work before the rest of __init__ has finished.
        self._ui_queue: "queue.Queue[tuple]" = queue.Queue()
        self._ui_pump_id: Optional[str] = None
        # Feed health, surfaced in the status bar and used to back off retries.
        self._feed_last_ok: Optional[datetime] = None
        self._feed_fail_streak: int = 0
        self._feed_retry_id: Optional[str] = None
        self.title("RSAMAXXED Terminal — Multi-Broker Execution")
        # Windows shows the default Python feather without this. Best-effort:
        # a missing icon must never stop the terminal from opening.
        try:
            ico = logo.ico_path()
            if ico:
                self.iconbitmap(ico)
        except Exception:
            pass
        self.geometry("1480x900")
        self.configure(fg_color=BG_PRIMARY)
        self.minsize(1240, 780)

        # ---- runtime state ----
        self._log_lines: List[tuple] = []
        # Execution / live-activity state (Activity page + double-submit guard)
        self._trade_in_flight: bool = False   # a Trade Desk batch is running
        self._live_batches: List[dict] = []   # batches currently shown live
        self._live_anim_id: Optional[str] = None
        self._live_frame: int = 0
        self._active_nav: Optional[str] = None
        # Watchlist = RSA Quick Pick symbols (+ optional user-pinned extras).
        self._quick_picks: List[Dict[str, str]] = []
        self._user_watchlist: List[str] = _load_watchlist()
        self._pick_symbols: List[str] = []
        self._watchlist: List[str] = list(self._user_watchlist)
        self._quotes: Dict[str, Dict[str, Any]] = {}
        # Bumped on every quote merge. Pages fingerprint against it instead of
        # hashing the whole quote dict on every tab switch.
        self._quotes_rev: int = 0
        # Last-rendered fingerprint per page — see _page_signature.
        self._page_sig: Dict[str, Any] = {}
        self._notifications: List[Dict[str, Any]] = []
        self._notif_unread: int = 0
        self._notif_popup: Optional[tk.Toplevel] = None
        self._palette: Optional[tk.Toplevel] = None
        self._quote_loop_id: Optional[str] = None
        self._toasts: List[tk.Toplevel] = []
        # Round-up radar: open positions whose quote has exploded past our
        # recorded cost — the reverse split almost certainly executed.
        self._roundup_flagged: set = set()
        # TRACK board (the Exits page). Populated by the hourly poll; must exist
        # before _build_frames because the page renders from it on first build.
        self._track_rows: List[Any] = []
        self._track_error: str = ""
        self._track_pulled_at: str = ""
        self._track_busy: bool = False
        self._track_loop_id: Optional[str] = None
        self._exit_busy: bool = False   # a holdings read for an exit is running

        # Auto-sell. Restored from disk but ALWAYS re-armed deliberately in the
        # sense that matters: `sold` is what stops a restart re-selling a play
        # the previous run already closed. Built here, before _build_frames,
        # because the Exits page renders the toggles.
        _as = self._load_autosell_state()
        self._autosell_enabled = tk.BooleanVar(value=bool(_as.get("enabled")))
        self._autosell_dry_run = tk.BooleanVar(value=bool(_as.get("dry_run", True)))
        self._autosell_roundups = tk.BooleanVar(value=bool(_as.get("include_roundups")))
        self._autosell_sold: set = set(_as.get("sold") or [])
        self._autosell_queue: List[Any] = []
        self._autosell_waits: int = 0     # pump ticks spent behind a busy trade
        # play key -> hand-backs so far. Not persisted: a restart is a fair
        # reason to try a broker again, and it is the WITHIN-session loop that
        # hammers a login.
        self._autosell_fails: Dict[str, int] = {}

        self._configure_styles()
        self._build_shell()
        self._build_notification_bar()
        self._build_frames()
        self._install_input_hook()
        self._install_shortcuts()
        self._show_frame("dashboard")

        self._tick_clock()
        # Drains work a background thread could not hand to Tk directly. Must be
        # running before the first worker starts — see `after` below.
        self.after(120, self._ui_pump)
        self.after(300, self._start_quote_loop)
        # Auto-refresh non-browser brokers on startup (browser brokers need manual bootstrap)
        self.after(700, self._startup_refresh)
        # TRACK board: runs on its own hourly timer, not the Discord toggle.
        self.after(2500, self._track_loop)
        # No plays-password prompt on startup: the hosted feed is open, so a
        # fresh install has nothing to enter and asking would invent friction
        # that the product does not have. _prompt_plays_key stays reachable
        # from the picks screen for anyone pointed at a self-hosted deployment
        # that gates its own feed.

    # ---- Worker -> UI handoff ----------------------------------------------

    def after(self, ms, func=None, *args):
        """Tk's `after`, made safe to call from a worker thread.

        `_tkinter` lets a non-main thread register a callback only while the
        interpreter is actively dispatching; it waits about a second and then
        raises RuntimeError("main thread is not in main loop"). Startup renders
        for longer than that, so a worker that finished quickly — which is
        exactly what happens on a fresh install, where there are no cached picks
        to fetch and no quotes to look up — had its `after` call raise, and the
        exception killed the thread. The first pick render and the first quote
        refresh were dropped on the floor, leaving a new user staring at an
        empty Watchlist with nothing in the log to explain it.

        Rather than lose the update, hand it to a queue the main thread drains
        (`_ui_pump`). Ordering is preserved and the callback runs as soon as the
        event loop is free. Calls from the main thread take the normal path, so
        timers and their return ids behave exactly as before.
        """
        if threading.current_thread() is threading.main_thread():
            return super().after(ms, func, *args)
        try:
            return super().after(ms, func, *args)
        except RuntimeError:
            if callable(func):
                self._ui_queue.put((func, args))
            return None

    def _ui_pump(self) -> None:
        """Main-thread drain for work handed over by `after` above."""
        while True:
            try:
                func, args = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                func(*args)
            except Exception as exc:      # one bad callback must not stop the pump
                self._log(f"UI update failed: {exc}", "warn")
        self._ui_pump_id = super().after(100, self._ui_pump)

    # ---- Shell scaffolding ------------------------------------------------

    def _build_shell(self) -> None:
        """Global top command bar + live ticker tape + (sidebar | content)
        + bottom status bar."""
        self._build_topbar()
        self._build_ticker_tape()
        tk.Frame(self, bg=BORDER, height=1).pack(side="top", fill="x")
        self._build_statusbar()

        body = tk.Frame(self, bg=BG_PRIMARY)
        body.pack(side="top", fill="both", expand=True)
        self._build_sidebar(body)
        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")
        self._build_content_area(body)

    def _build_statusbar(self) -> None:
        """Thin terminal-style status strip along the bottom edge."""
        bar = tk.Frame(self, bg=BG_SECONDARY, height=26)
        bar.pack(side="bottom", fill="x")
        bar.pack_propagate(False)
        tk.Frame(self, bg=BORDER, height=1).pack(side="bottom", fill="x")

        left = tk.Frame(bar, bg=BG_SECONDARY)
        left.pack(side="left", fill="y", padx=(16, 0))
        StatusDot(left, color=GREEN, size=6).pack(side="left", padx=(0, 6), pady=6)
        n_conn = sum(1 for b in BROKER_MODULES if _broker_has_creds(b))
        tk.Label(left, text=f"OPERATIONAL   ·   {n_conn} BROKER"
                            f"{'S' if n_conn != 1 else ''} LINKED",
                 bg=BG_SECONDARY, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 7, "bold")).pack(side="left")

        right = tk.Frame(bar, bg=BG_SECONDARY)
        right.pack(side="right", fill="y", padx=(0, 16))
        self._status_journal = tk.Label(right, text="", bg=BG_SECONDARY,
                                        fg=TEXT_MUTED, font=(FONT_MONO, 7))
        self._status_journal.pack(side="right", padx=(16, 0))
        self._status_quotes = tk.Label(right, text="QUOTES · AWAITING FIRST SYNC",
                                       bg=BG_SECONDARY, fg=TEXT_MUTED,
                                       font=(FONT_MONO, 7))
        self._status_quotes.pack(side="right", padx=(16, 0))
        # The plays are the product, so their freshness gets a permanent
        # readout. Quotes already had one and they matter far less.
        self._feed_status_lbl = tk.Label(right, text="FEED  ·  connecting…",
                                         bg=BG_SECONDARY, fg=TEXT_MUTED,
                                         font=(FONT_MONO, 7))
        self._feed_status_lbl.pack(side="right")

    # ---- Notification bar -------------------------------------------------

    def _build_notification_bar(self) -> None:
        """Alert bar that appears at top of content when a broker needs attention."""
        self._notif_bar = tk.Frame(self._content.master, bg=YELLOW, height=0)
        self._notif_label = tk.Label(self._notif_bar, text="", bg=YELLOW,
                                     fg=BG_PRIMARY, font=(FONT_FAMILY, 10, "bold"))
        self._notif_label.pack(padx=16, pady=6)
        self._notif_visible = False

    def _show_notification(self, message: str, color: str = YELLOW) -> None:
        """Show the notification bar with a message and play alert sound."""
        def _show():
            self._notif_bar.configure(bg=color)
            self._notif_label.configure(text=message, bg=color)
            if not self._notif_visible:
                self._notif_bar.pack(fill="x", padx=28, pady=(0, 4),
                                     before=self._content)
                self._notif_visible = True
            # flash the taskbar and play sound
            try:
                self.bell()
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass
            # bring window to front
            self.attributes("-topmost", True)
            self.after(500, lambda: self.attributes("-topmost", False))
        self.after(0, _show)

    def _hide_notification(self) -> None:
        def _hide():
            if self._notif_visible:
                self._notif_bar.pack_forget()
                self._notif_visible = False
        self.after(0, _hide)

    # ---- GUI input hook (replaces terminal input() for 2FA/OTP) -----------

    def _ask_inline(self, title: str, prompt: str, *,
                    show: Optional[str] = None) -> Optional[str]:
        """Modal text prompt drawn INSIDE the main window.

        A tk popup is a separate OS window. Maximised, full-screen, or on a
        second monitor it can open behind the terminal or off to one side, and
        an unseen 2FA prompt is a login that dies on a code that expired while
        it sat there. This one is placed over the app itself, so it is on
        whichever screen the user is already looking at.

        Blocks on `wait_variable` — the same nested event loop `simpledialog`
        runs — so callers keep the ask-and-wait shape they already had.
        """
        result: List[Optional[str]] = [None]
        done = tk.BooleanVar(self, value=False)

        overlay = tk.Frame(self, bg=BG_PRIMARY)
        overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        overlay.lift()

        card = RoundedFrame(overlay, bg_color=BG_CARD, border_color=ACCENT,
                            radius=RAD_MD)
        card.place(relx=0.5, rely=0.5, anchor="center")
        body = tk.Frame(card.inner, bg=BG_CARD)
        body.pack(padx=SP_2XL, pady=SP_2XL)

        tk.Label(body, text=title, bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, FS_H2, "bold")).pack(anchor="w")
        tk.Label(body, text=prompt, bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 10), justify="left",
                 wraplength=460).pack(anchor="w", pady=(6, SP_LG))

        entry = ttk.Entry(body, width=32, font=(FONT_MONO, 13), justify="center",
                          **({"show": show} if show else {}))
        entry.pack(fill="x")

        def submit(_evt=None) -> None:
            result[0] = entry.get().strip()
            done.set(True)

        def cancel(_evt=None) -> None:
            result[0] = None
            done.set(True)

        btns = tk.Frame(body, bg=BG_CARD)
        btns.pack(fill="x", pady=(SP_LG, 0))
        PillButton(btns, text="Submit", bg_color=ACCENT, command=submit,
                   width=120, height=32).pack(side="right")
        PillButton(btns, text="Cancel", bg_color=BG_CARD_ALT, hover_color=RED,
                   command=cancel, width=100, height=32).pack(side="right",
                                                              padx=(0, SP_SM))

        entry.bind("<Return>", submit)
        entry.bind("<Escape>", cancel)
        overlay.bind("<Escape>", cancel)

        # focus after the widget is mapped, or the caret lands nowhere
        self.after(50, entry.focus_set)
        try:
            overlay.grab_set()
        except tk.TclError:
            pass
        self.wait_variable(done)
        try:
            overlay.grab_release()
        except tk.TclError:
            pass
        overlay.destroy()
        return result[0]

    # ---- Full-window alert for "go do something on your phone" -------------

    def _show_action_alert(self, title: str, body: str, *,
                           detail: str = "", icon_name: str = "warning",
                           color: str = YELLOW) -> None:
        """Full-window alert for a step only the user can complete elsewhere.

        Unlike `_ask_inline` there is nothing to type. A device approval is
        already sitting on the user's phone and the login is blocked until they
        tap it, so this takes no input, never grabs the keyboard, and stays up
        until the caller takes it down. It cannot be missed: it covers the whole
        window, raises the app, and beeps.

        Thread-safe — bootstrap runs on a worker thread.
        """
        def _show() -> None:
            existing = getattr(self, "_action_alert", None)
            if existing is not None and existing["frame"].winfo_exists():
                # Already showing: refresh the words rather than stacking a
                # second scrim on top of the first.
                existing["title"].configure(text=title)
                existing["body"].configure(text=body)
                existing["detail"].configure(text=detail)
                return

            overlay = tk.Frame(self, bg=BG_PRIMARY)
            overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            overlay.lift()

            card = RoundedFrame(overlay, bg_color=BG_CARD, border_color=color,
                                radius=RAD_LG)
            card.place(relx=0.5, rely=0.5, anchor="center")
            inner = tk.Frame(card.inner, bg=BG_CARD)
            inner.pack(padx=SP_3XL, pady=SP_3XL)

            tk.Label(inner, text=icon(icon_name), bg=BG_CARD, fg=color,
                     font=(ICON_FONT, 40)).pack(anchor="center")
            lbl_title = tk.Label(inner, text=title, bg=BG_CARD, fg=TEXT_PRIMARY,
                                 font=(FONT_FAMILY, FS_H1, "bold"),
                                 wraplength=520, justify="center")
            lbl_title.pack(anchor="center", pady=(SP_LG, SP_SM))
            lbl_body = tk.Label(inner, text=body, bg=BG_CARD, fg=TEXT_SECONDARY,
                                font=(FONT_FAMILY, 11), wraplength=520,
                                justify="center")
            lbl_body.pack(anchor="center")
            lbl_detail = tk.Label(inner, text=detail, bg=BG_CARD, fg=TEXT_MUTED,
                                  font=(FONT_FAMILY, 10), wraplength=520,
                                  justify="center")
            lbl_detail.pack(anchor="center", pady=(SP_LG, 0))

            waiting = tk.Label(inner, text="● waiting for approval", bg=BG_CARD,
                               fg=color, font=(FONT_MONO, 11))
            waiting.pack(anchor="center", pady=(SP_XL, 0))

            state = {"frame": overlay, "title": lbl_title, "body": lbl_body,
                     "detail": lbl_detail, "pulse": None, "on": True}

            def pulse() -> None:
                if not waiting.winfo_exists():
                    return
                state["on"] = not state["on"]
                waiting.configure(fg=color if state["on"] else TEXT_MUTED)
                state["pulse"] = self.after(650, pulse)

            pulse()

            # Dismissing hides the alert only. The login is still waiting on the
            # phone — saying otherwise would be a lie, and cancelling it here
            # would strand robin_stocks in its no-timeout poll.
            PillButton(inner, text="Hide this", bg_color=BG_CARD_ALT,
                       command=self._hide_action_alert,
                       width=140, height=34).pack(anchor="center", pady=(SP_XL, 0))

            self._action_alert = state

            try:
                self.deiconify()
                self.lift()
                self.attributes("-topmost", True)
                self.after(800, lambda: self.attributes("-topmost", False))
            except Exception:
                pass
            try:
                self.bell()
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass

        self.after(0, _show)

    def _hide_action_alert(self) -> None:
        def _hide() -> None:
            state = getattr(self, "_action_alert", None)
            self._action_alert = None
            if state is None:
                return
            if state.get("pulse") is not None:
                try:
                    self.after_cancel(state["pulse"])
                except Exception:
                    pass
            try:
                if state["frame"].winfo_exists():
                    state["frame"].destroy()
            except Exception:
                pass

        self.after(0, _hide)

    def _arm_device_approval_alert(self, mod) -> Any:
        """Put a broker's device-approval push on screen while it blocks.

        Robinhood is the one that needs this: its re-login sends a push and then
        polls with no timeout, so a notification nobody sees is a bootstrap that
        hangs until the app is killed. Any broker module exposing
        `set_device_approval_hook` gets the same treatment; the rest are
        untouched. Returns the setter so the caller can unregister.
        """
        setter = getattr(mod, "set_device_approval_hook", None)
        if not callable(setter):
            return None
        broker_name = str(getattr(mod, "BROKER", "Broker")).capitalize()

        def _on_push(message: str) -> None:
            # Called from the login thread, mid-print. Everything here has to be
            # scheduled onto the UI loop.
            self.after(0, lambda: self._log(f"ALERT: {broker_name} — {message}"))
            self._show_action_alert(
                "Approve the login on your phone",
                message,
                detail=(
                    "Approve within about a minute — the login shares one "
                    "120-second budget between waiting for you and confirming "
                    "afterwards. Don't start another bootstrap while this is up: "
                    "repeated attempts trip Robinhood's rate limit, which then "
                    "fails with a misleading \"check credentials\" error."
                ),
                icon_name="lock",
            )

        try:
            setter(_on_push)
        except Exception:
            return None
        return setter

    def _disarm_device_approval_alert(self, setter) -> None:
        """Unregister the hook and take the alert down, however login ended."""
        if callable(setter):
            try:
                setter(None)
            except Exception:
                pass
        self._hide_action_alert()

    def _install_input_hook(self) -> None:
        """Monkey-patch builtins.input so broker 2FA prompts show a GUI dialog."""
        original_input = builtins.input
        app = self

        def gui_input(prompt=""):
            # if called from main thread, use original (shouldn't happen)
            if threading.current_thread() is threading.main_thread():
                return original_input(prompt)

            # show notification + dialog from main thread
            result = [None]
            event = threading.Event()

            def ask():
                app._show_notification(
                    f"Action required: {prompt.strip()}",
                    color=YELLOW,
                )
                app._log(f"ALERT: {prompt.strip()}")
                answer = app._ask_inline("Broker Input Required", prompt.strip())
                result[0] = answer if answer is not None else ""
                app._hide_notification()
                event.set()

            app.after(0, ask)
            event.wait()
            return result[0]

        builtins.input = gui_input

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=BG_PRIMARY, foreground=TEXT_PRIMARY,
                        fieldbackground=BG_INPUT, borderwidth=0)
        style.configure("TFrame", background=BG_PRIMARY)
        style.configure("TLabel", background=BG_PRIMARY, foreground=TEXT_PRIMARY)
        style.configure("Muted.TLabel", background=BG_PRIMARY, foreground=TEXT_SECONDARY)

        # Entry — flat field with a hairline that lights up on focus
        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=TEXT_PRIMARY,
                        insertcolor=ACCENT, padding=9, borderwidth=1,
                        relief="flat", bordercolor=BORDER)
        style.map("TEntry",
                  fieldbackground=[("focus", BG_CARD_ALT)],
                  bordercolor=[("focus", ACCENT)],
                  lightcolor=[("focus", ACCENT)],
                  darkcolor=[("focus", ACCENT)])

        style.configure("TCombobox", fieldbackground=BG_INPUT, foreground=TEXT_PRIMARY,
                        padding=8, arrowcolor=TEXT_SECONDARY, borderwidth=1,
                        bordercolor=BORDER, relief="flat")
        style.map("TCombobox",
                  fieldbackground=[("readonly", BG_INPUT)],
                  bordercolor=[("focus", ACCENT)],
                  arrowcolor=[("active", TEXT_PRIMARY)])

        # Treeview — airier rows, quiet uppercase headers, pop-tinted selection
        style.configure("Treeview", background=BG_CARD, foreground=TEXT_PRIMARY,
                        fieldbackground=BG_CARD, rowheight=38,
                        font=(FONT_MONO, 11), borderwidth=0)
        style.configure("Treeview.Heading", background=BG_SECONDARY,
                        foreground=TEXT_MUTED,
                        font=(FONT_FAMILY, 9, "bold"), borderwidth=0,
                        relief="flat", padding=(10, 12))
        style.map("Treeview.Heading",
                  background=[("active", BG_CARD_ALT)],
                  foreground=[("active", TEXT_SECONDARY)])
        style.map("Treeview",
                  background=[("selected", ACCENT_SEL)],
                  foreground=[("selected", TEXT_PRIMARY)])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

        # Slim, chromeless scrollbar
        style.configure("Vertical.TScrollbar", background=BORDER,
                        troughcolor=BG_CARD, arrowcolor=BG_CARD,
                        borderwidth=0, relief="flat", width=8,
                        arrowsize=0)
        style.map("Vertical.TScrollbar",
                  background=[("active", BORDER_LIGHT), ("pressed", ACCENT)])
        style.layout("Vertical.TScrollbar", [
            ("Vertical.Scrollbar.trough", {
                "children": [("Vertical.Scrollbar.thumb",
                              {"expand": "1", "sticky": "nswe"})],
                "sticky": "ns"})])

    # ---- Sidebar ----------------------------------------------------------

    # Ordered by the life of a play, not by category. A play arrives on the
    # Watchlist, gets opened on the Trade Desk, sits in Positions, and closes
    # on Exits — so the sidebar reads top to bottom in the order you actually
    # work. The old grouping split that in half: Watchlist and Positions lived
    # under OVERVIEW while Trade Desk and Exits lived under TRADING, which put
    # step 3 above step 2 and buried the connection between them.
    #
    # A section title of "" renders with no header — Command Center is the home
    # screen, not a member of a group.
    _NAV_SECTIONS = [
        ("", [
            ("dashboard", "Command Center", "dashboard"),
        ]),
        ("THE PLAY", [
            ("watchlist", "Watchlist", "watchlist"),      # what to open
            ("trade", "Trade Desk", "trade"),             # open it by hand
            ("mirror", "Mirror", "lightning"),            # or have it opened for you
            ("holdings", "Positions", "positions"),       # what you hold
            ("exits", "Exits", "export"),                 # close it
        ]),
        ("PERFORMANCE", [
            ("stats", "Analytics", "analytics"),
        ]),
        ("SETUP", [
            ("settings", "Automation", "automation"),
            ("accounts", "Brokers", "brokers"),
            ("logs", "Activity", "activity"),
        ]),
    ]

    def _build_sidebar(self, parent) -> None:
        self._sidebar = tk.Frame(parent, bg=SIDEBAR_BG, width=244)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)

        self._nav_items: Dict[str, Dict[str, Any]] = {}
        tk.Frame(self._sidebar, bg=SIDEBAR_BG, height=12).pack(fill="x")

        for sect_title, items in self._NAV_SECTIONS:
            if sect_title:
                tk.Label(self._sidebar, text=sect_title, bg=SIDEBAR_BG, fg=TEXT_MUTED,
                         font=(FONT_FAMILY, 7, "bold")).pack(anchor="w", padx=26,
                                                             pady=(16, 6))
            else:
                tk.Frame(self._sidebar, bg=SIDEBAR_BG, height=6).pack(fill="x")
            for name, label, ic in items:
                self._make_nav_item(name, label, ic)

        tk.Frame(self._sidebar, bg=SIDEBAR_BG).pack(fill="both", expand=True)

        # footer: live connection status
        tk.Frame(self._sidebar, bg=BORDER, height=1).pack(fill="x", padx=18,
                                                          pady=(0, 12))
        foot = tk.Frame(self._sidebar, bg=SIDEBAR_BG)
        foot.pack(fill="x", padx=18, pady=(0, 16))
        self._sidebar_conn_dot = StatusDot(foot, color=GREEN, size=7)
        self._sidebar_conn_dot.pack(side="left", padx=(0, 7))
        n_conn = sum(1 for b in BROKER_MODULES if _broker_has_creds(b))
        self._sidebar_conn_lbl = tk.Label(
            foot, text=f"{n_conn} broker{'s' if n_conn != 1 else ''} linked",
            bg=SIDEBAR_BG, fg=TEXT_SECONDARY, font=(FONT_FAMILY, 8))
        self._sidebar_conn_lbl.pack(side="left")
        tk.Label(foot, text="v2.2", bg=SIDEBAR_BG, fg=TEXT_MUTED,
                 font=(FONT_MONO, 8)).pack(side="right")

    def _make_nav_item(self, name: str, label: str, ic: str) -> None:
        """Rounded pill nav item — CTk frame gives real anti-aliased corners."""
        item = ctk.CTkFrame(self._sidebar, corner_radius=10,
                            fg_color="transparent", bg_color=SIDEBAR_BG,
                            height=40)
        item.pack(fill="x", padx=14, pady=2)
        item.pack_propagate(False)
        icon_lbl = tk.Label(item, text=icon(ic), bg=SIDEBAR_BG, fg=TEXT_SECONDARY,
                            font=(ICON_FONT, 14), width=2, cursor="hand2")
        icon_lbl.pack(side="left", padx=(10, 0))
        text_lbl = tk.Label(item, text=f"  {label}", bg=SIDEBAR_BG,
                            fg=TEXT_SECONDARY, font=(FONT_FAMILY, 10, "bold"),
                            cursor="hand2")
        text_lbl.pack(side="left")
        dot = tk.Label(item, text="●", bg=SIDEBAR_BG, fg=SIDEBAR_BG,
                       font=(FONT_FAMILY, 6), cursor="hand2")
        dot.pack(side="right", padx=(0, 12))
        self._nav_items[name] = {
            "item": item, "icon": icon_lbl, "text": text_lbl, "dot": dot,
        }
        for widget in (item, icon_lbl, text_lbl, dot):
            widget.bind("<Enter>", lambda e, n=name: self._nav_hover(n, True))
            widget.bind("<Leave>", lambda e, n=name: self._nav_hover(n, False))
            widget.bind("<Button-1>", lambda e, n=name: self._show_frame(n))

    def _style_nav(self, name: str, state: str) -> None:
        """Apply 'idle' / 'hover' / 'active' visual state to a nav item."""
        refs = self._nav_items[name]
        if state == "active":
            fill, fg, icon_fg, dot = SIDEBAR_ACTIVE, TEXT_PRIMARY, ACCENT, ACCENT
        elif state == "hover":
            fill, fg, icon_fg, dot = SIDEBAR_HOVER, TEXT_PRIMARY, TEXT_PRIMARY, SIDEBAR_HOVER
        else:
            fill, fg, icon_fg, dot = None, TEXT_SECONDARY, TEXT_SECONDARY, SIDEBAR_BG
        refs["item"].configure(fg_color=fill if fill else "transparent")
        bg = fill if fill else SIDEBAR_BG
        refs["icon"].configure(bg=bg, fg=icon_fg)
        refs["text"].configure(bg=bg, fg=fg)
        refs["dot"].configure(bg=bg, fg=dot)

    def _nav_hover(self, name: str, entering: bool) -> None:
        if self._active_nav == name:
            return
        self._style_nav(name, "hover" if entering else "idle")

    def _set_active_nav(self, name: str) -> None:
        for n in self._nav_items:
            self._style_nav(n, "active" if n == name else "idle")
        self._active_nav = name

    # ---- Content Area -----------------------------------------------------

    def _build_content_area(self, parent) -> None:
        wrapper = tk.Frame(parent, bg=BG_PRIMARY)
        wrapper.pack(side="left", fill="both", expand=True)

        # page header — icon + title + subtitle, with a right actions slot
        header = tk.Frame(wrapper, bg=BG_PRIMARY, height=70)
        header.pack(fill="x", padx=30, pady=(18, 0))
        header.pack_propagate(False)

        title_row = tk.Frame(header, bg=BG_PRIMARY)
        title_row.pack(side="left", anchor="w", fill="y")
        self._page_icon = tk.Label(title_row, text=icon("dashboard"), bg=BG_PRIMARY,
                                   fg=ACCENT, font=(ICON_FONT, 20))
        self._page_icon.pack(side="left", anchor="n", pady=(3, 0))
        titles = tk.Frame(title_row, bg=BG_PRIMARY)
        titles.pack(side="left", padx=(13, 0))
        self._page_title = tk.Label(titles, text="Command Center", bg=BG_PRIMARY,
                                    fg=TEXT_PRIMARY, font=(FONT_FAMILY, FS_H1, "bold"))
        self._page_title.pack(anchor="w")
        self._page_subtitle = tk.Label(titles, text="", bg=BG_PRIMARY,
                                       fg=TEXT_SECONDARY, font=(FONT_FAMILY, 10))
        self._page_subtitle.pack(anchor="w", pady=(1, 0))

        self._header_right = tk.Frame(header, bg=BG_PRIMARY)
        self._header_right.pack(side="right", anchor="e", fill="y")

        tk.Frame(wrapper, bg=BORDER, height=1).pack(fill="x", padx=30, pady=(14, 0))
        self._content = tk.Frame(wrapper, bg=BG_PRIMARY)
        self._content.pack(fill="both", expand=True, padx=30, pady=16)

    def _build_frames(self) -> None:
        self._frames: Dict[str, tk.Frame] = {}
        self._build_dashboard()
        self._build_watchlist()
        self._build_holdings()
        self._build_trade()
        self._build_exits()
        self._build_stats()
        self._build_settings()
        # After settings: the Mirror page reads the mirror state vars that
        # _build_settings creates (_mirror_enabled and friends).
        self._build_mirror()
        self._build_accounts()
        self._build_logs()

    _PAGE_META = {
        "dashboard": ("dashboard", "Command Center", "Live portfolio across every connected broker"),
        "watchlist": ("watchlist", "Watchlist", "Reverse-split round-up plays you're buying — live"),
        "holdings":  ("positions", "Positions", "Allocation of confirmed-bought open positions"),
        "trade":     ("trade", "Trade Desk", "Synchronized multi-broker order execution"),
        "mirror":    ("lightning", "Mirror", "Every order automation placed for you, run by run"),
        "exits":     ("export", "Exits", "Plays that resolved — what to sell, and where"),
        "settings":  ("automation", "Automation", "Mirror trading and rules engine"),
        "stats":     ("analytics", "Analytics", "Performance, risk and realized P/L"),
        "accounts":  ("brokers", "Brokers", "Connections, credentials and bootstrap"),
        "logs":      ("activity", "Activity", "Live session event log"),
    }

    # Contextual page-header actions (rendered into the right header slot)
    _PAGE_ACTIONS = {
        "dashboard": [("Refresh All", "_dashboard_refresh")],
        "watchlist": [("Refresh Quotes", "_start_quote_loop")],
        "holdings":  [("Recompute", "_recompute_allocation")],
        "exits":     [("Refresh Board", "_track_pull_now")],
        "mirror":    [("Check Now", "_mirror_check_clicked"), ("Export CSV", "_export_mirror_csv")],
        "stats":     [("Export CSV", "_export_trades_csv")],
        "accounts":  [("Bootstrap All", "_bootstrap_all")],
    }

    def _render_header_actions(self, name: str) -> None:
        for w in self._header_right.winfo_children():
            w.destroy()
        for label, method in reversed(self._PAGE_ACTIONS.get(name, [])):
            fn = getattr(self, method, None)
            if fn is None:
                continue
            PillButton(self._header_right, text=label, command=fn,
                       bg_color=BG_CARD_ALT, hover_color=BG_ELEVATED,
                       width=max(112, len(label) * 8 + 34), height=34,
                       font_size=9).pack(side="right", padx=(8, 0), pady=16)

    def _show_frame(self, name: str) -> None:
        for f in self._frames.values():
            f.pack_forget()
        self._frames[name].pack(in_=self._content, fill="both", expand=True)
        ic, title, subtitle = self._PAGE_META.get(name, ("dashboard", name.title(), ""))
        self._page_icon.configure(text=icon(ic))
        self._page_title.configure(text=title)
        self._page_subtitle.configure(text=subtitle)
        self._render_header_actions(name)
        self._set_active_nav(name)

        if name == "exits":
            # Opening the page before the hourly tick has fired should not show
            # an empty board — pull it now instead of making you wait an hour.
            if not self._track_rows and not self._track_busy and self._track_available():
                self.after(60, self._track_pull_now)

        renderer = {
            "stats": self._refresh_stats,
            "watchlist": self._render_watchlist,
            "holdings": self._render_allocation,
            "exits": self._render_exits,
            "mirror": self._render_mirror,
        }.get(name)
        if renderer is None:
            return

        # Rebuilding a page costs real time — Positions redraws a donut and its
        # legend, Exits builds a widget per broker per play, Analytics redraws
        # six charts. Doing that on every visit is what made moving around feel
        # slow, and it is pure waste when nothing underneath has changed.
        sig = self._page_signature(name)
        if sig is not None and self._page_sig.get(name) == sig:
            return
        self._page_sig[name] = sig
        self.after(50 if name != "stats" else 100, renderer)

    def _journal_version(self) -> tuple:
        """Cheap fingerprint of the trade journal — no parse.

        Deliberately derived from the data rather than set by hand. A manual
        "dirty" flag only works if every writer remembers to set it, and the one
        that forgets shows you a stale portfolio.
        """
        return trade_journal.version()

    def _page_signature(self, name: str):
        """Everything `name` renders from, cheaply. None = always re-render."""
        if name == "exits":
            return ("exits", self._track_pulled_at, len(self._track_rows),
                    self._track_error, self._journal_version())
        if name == "mirror":
            # The toggle and broker set live on the Automation page, so they are
            # part of what this page renders even though the journal didn't move.
            return ("mirror", mirror_journal.version(),
                    bool(getattr(self, "_mirror_enabled", None)
                         and self._mirror_enabled.get()),
                    tuple(sorted(getattr(self, "_mirror_selected_brokers", ()))),
                    len(getattr(self, "_mirror_failed", ())))
        if name in ("holdings", "stats"):
            return (name, self._journal_version())
        if name == "watchlist":
            return ("watchlist", tuple(self._watchlist),
                    len(self._quick_picks), self._quotes_rev,
                    self._journal_version())
        return None

    def _invalidate_page(self, *names: str) -> None:
        """Force the next visit to re-render. For the few changes a signature
        cannot see, such as a manual Refresh."""
        for n in names or tuple(self._page_sig):
            self._page_sig.pop(n, None)

    # ---- Top command bar --------------------------------------------------

    def _build_topbar(self) -> None:
        bar = tk.Frame(self, bg=BG_SECONDARY, height=66)
        bar.pack(side="top", fill="x")
        bar.pack_propagate(False)

        # brand
        left = tk.Frame(bar, bg=BG_SECONDARY)
        left.pack(side="left", fill="y", padx=(22, 0))
        # The canvas draws the whole mark — tile included — so logo.py stays the
        # single source of what it looks like. A CTkFrame tile behind it would
        # just be a second rounded square with a different radius.
        mark = tk.Canvas(left, width=40, height=40, bg=BG_SECONDARY,
                         highlightthickness=0, bd=0)
        mark.pack(side="left", pady=13)
        logo.draw_mark(mark, 40, bg=BG_SECONDARY)
        brand = tk.Frame(left, bg=BG_SECONDARY)
        brand.pack(side="left", padx=(13, 0))
        tk.Label(brand, text="RSAMAXXED", bg=BG_SECONDARY, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 17, "bold")).pack(anchor="w")
        tk.Label(brand, text="EXECUTION TERMINAL", bg=BG_SECONDARY, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 7, "bold")).pack(anchor="w")

        # global search (opens command palette)
        center = tk.Frame(bar, bg=BG_SECONDARY)
        center.pack(side="left", fill="both", expand=True, padx=26)
        sb = ctk.CTkFrame(center, corner_radius=9, fg_color=BG_INPUT,
                          bg_color=BG_SECONDARY, border_width=1, border_color=BORDER,
                          cursor="hand2")
        sb.pack(fill="x", pady=13)
        si = tk.Label(sb, text=icon("search"), bg=BG_INPUT, fg=TEXT_MUTED,
                      font=(ICON_FONT, 12), cursor="hand2")
        si.pack(side="left", padx=(12, 8), pady=8)
        ph = tk.Label(sb, text="Search ticker, broker or action…", bg=BG_INPUT,
                      fg=TEXT_MUTED, font=(FONT_FAMILY, 10), cursor="hand2")
        ph.pack(side="left", pady=8)
        kbd = tk.Label(sb, text="Ctrl K", bg=BG_CARD_ALT, fg=TEXT_SECONDARY,
                       font=(FONT_MONO, 8), padx=7, pady=2)
        kbd.pack(side="right", padx=10)
        for w in (sb, si, ph):
            w.bind("<Button-1>", lambda e: self._open_command_palette())

        # right cluster
        right = tk.Frame(bar, bg=BG_SECONDARY)
        right.pack(side="right", fill="y", padx=(0, 16))

        self._mkt_pill = ctk.CTkFrame(right, corner_radius=16, fg_color=BG_CARD,
                                      bg_color=BG_SECONDARY, border_width=1,
                                      border_color=BORDER)
        self._mkt_pill.pack(side="left", pady=15, padx=(0, 14))
        self._mkt_dot = StatusDot(self._mkt_pill, color=GREEN, size=7)
        self._mkt_dot.pack(side="left", padx=(12, 7), pady=5)
        self._mkt_lbl = tk.Label(self._mkt_pill, text="Markets", bg=BG_CARD,
                                 fg=TEXT_SECONDARY, font=(FONT_FAMILY, 9, "bold"))
        self._mkt_lbl.pack(side="left", pady=5)
        self._mkt_clock = tk.Label(self._mkt_pill, text="--:--:--", bg=BG_CARD,
                                   fg=TEXT_MUTED, font=(FONT_MONO, 9))
        self._mkt_clock.pack(side="left", padx=(9, 13), pady=5)

        self._make_topbar_iconbtn(right, "refresh", self._global_refresh)
        self._bell_btn = self._make_topbar_iconbtn(right, "bell",
                                                   self._toggle_notifications)
        self._notif_badge = tk.Label(self._bell_btn, text="", bg=RED, fg="#0a0a12",
                                     font=(FONT_FAMILY, 7, "bold"))
        self._make_topbar_iconbtn(right, "profile", self._open_command_palette)

    def _make_topbar_iconbtn(self, parent, ic: str, command) -> tk.Frame:
        btn = tk.Frame(parent, bg=BG_SECONDARY, cursor="hand2", width=36, height=36)
        btn.pack(side="left", padx=3, pady=12)
        btn.pack_propagate(False)
        lbl = tk.Label(btn, text=icon(ic), bg=BG_SECONDARY, fg=TEXT_SECONDARY,
                       font=(ICON_FONT, 15))
        lbl.place(relx=0.5, rely=0.5, anchor="center")
        for w in (btn, lbl):
            w.bind("<Enter>", lambda e: lbl.configure(fg=TEXT_PRIMARY))
            w.bind("<Leave>", lambda e: lbl.configure(fg=TEXT_SECONDARY))
            w.bind("<Button-1>", lambda e: command())
        return btn

    # ---- Ticker tape ------------------------------------------------------

    def _build_ticker_tape(self) -> None:
        self._tape = tk.Frame(self, bg=BG_PRIMARY, height=34)
        self._tape.pack(side="top", fill="x")
        self._tape.pack_propagate(False)
        lead = tk.Frame(self._tape, bg=BG_PRIMARY)
        lead.pack(side="left", padx=(20, 0))
        StatusDot(lead, color=GREEN, size=6).pack(side="left", padx=(0, 6))
        tk.Label(lead, text="LIVE", bg=BG_PRIMARY, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 7, "bold")).pack(side="left")
        tk.Frame(self._tape, bg=BORDER, width=1, height=16).pack(side="left",
                                                                 padx=14, pady=9)
        self._tape_body = tk.Frame(self._tape, bg=BG_PRIMARY)
        self._tape_body.pack(side="left", fill="both", expand=True)
        self._render_ticker_tape()

    def _render_ticker_tape(self) -> None:
        if not hasattr(self, "_tape_body"):
            return
        for w in self._tape_body.winfo_children():
            w.destroy()
        shown = 0
        for sym in self._watchlist:
            q = self._quotes.get(sym)
            # bordered chip cell — reads as instrumentation, not loose text
            cell = tk.Frame(self._tape_body, bg=BG_SECONDARY,
                            highlightbackground=BORDER, highlightthickness=1)
            cell.pack(side="left", padx=(0, 8), pady=4)
            pad = tk.Frame(cell, bg=BG_SECONDARY)
            pad.pack(padx=9, pady=2)
            tk.Label(pad, text=sym, bg=BG_SECONDARY, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 9, "bold")).pack(side="left")
            if q:
                tk.Label(pad, text=f"  {q['price']:,.2f}", bg=BG_SECONDARY,
                         fg=TEXT_SECONDARY, font=(FONT_MONO, 9)).pack(side="left")
                up = q["pct"] >= 0
                col = GREEN if up else RED
                tk.Label(pad, text=f"  {icon('up') if up else icon('down')}",
                         bg=BG_SECONDARY, fg=col, font=(ICON_FONT, 7)).pack(side="left")
                tk.Label(pad, text=f"{abs(q['pct']):.2f}%", bg=BG_SECONDARY, fg=col,
                         font=(FONT_MONO, 9, "bold")).pack(side="left")
            else:
                # RSA/OTC names often have no public quote — show the pick note tag
                info = self._pick_info(sym)
                note = (info or {}).get("note", "") if info else ""
                tag = self._NOTE_DISPLAY.get(note.lower(), note) if note else "RSA"
                is_reg = note.lower() in ("reg alert", "alert", "early access")
                tk.Label(pad, text=f"  {tag or 'RSA'}", bg=BG_SECONDARY,
                         fg=ACCENT if is_reg else TEXT_MUTED,
                         font=(FONT_FAMILY, 8, "bold")).pack(side="left")
            shown += 1
            if shown >= 12:
                break

    # ---- Live clock + quote loop ------------------------------------------

    def _tick_clock(self) -> None:
        state, label, now = _market_status()
        color = {"open": GREEN, "pre": YELLOW, "closed": RED}.get(state, TEXT_MUTED)
        try:
            self._mkt_dot.set_color(color)
            self._mkt_lbl.configure(text=label)
            self._mkt_clock.configure(text=now.strftime("%H:%M:%S") + " ET")
        except Exception:
            pass
        # Rides the clock rather than owning a timer: the age it shows has to
        # keep counting up on its own, or a feed that died an hour ago would
        # still read "just now" until the next successful pull.
        self._update_feed_status()
        self.after(1000, self._tick_clock)

    def _start_quote_loop(self) -> None:
        self._run_in_thread(self._quote_worker)

    @staticmethod
    def _fetch_quotes_parallel(syms: List[str], max_workers: int = 8) -> Dict[str, Dict[str, Any]]:
        """Fetch many quotes concurrently (bounded). Keeps a cycle to ~tens of
        seconds even when dozens of RSA/OTC names time out on Yahoo."""
        from queue import Queue, Empty
        results: Dict[str, Dict[str, Any]] = {}
        lock = threading.Lock()
        q: "Queue[str]" = Queue()
        for s in syms:
            q.put(s)

        def worker() -> None:
            while True:
                try:
                    sym = q.get_nowait()
                except Empty:
                    return
                quote = _fetch_quote(sym)
                if quote:
                    with lock:
                        results[sym] = quote
        ts = [threading.Thread(target=worker, daemon=True)
              for _ in range(min(max_workers, max(1, len(syms))))]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        return results

    def _quote_worker(self) -> None:
        results = self._fetch_quotes_parallel(list(self._watchlist))
        self.after(0, lambda: self._apply_quotes(results))

    def _apply_quotes(self, results: Dict[str, Dict[str, Any]]) -> None:
        self._merge_quotes(results)
        if hasattr(self, "_status_quotes"):
            self._status_quotes.configure(
                text=f"QUOTES · SYNCED {datetime.now():%H:%M:%S}")
        self._quote_loop_id = self.after(45000, self._start_quote_loop)

    def _merge_quotes(self, results: Dict[str, Dict[str, Any]]) -> None:
        if not results:
            return
        self._quotes.update(results)
        self._quotes_rev += 1
        self._check_roundup_radar(results)
        self._render_ticker_tape()
        self._render_dash_movers()
        if self._active_nav == "watchlist":
            self._render_watchlist()

    def _check_roundup_radar(self, results: Dict[str, Dict[str, Any]]) -> None:
        """Reverse-split detector: an open position quoting far above our
        recorded cost usually means the split executed and the round-up landed.
        Notifies once per symbol — never auto-sells."""
        try:
            open_syms = {p["symbol"]
                         for p in self._portfolio_summary()["open_positions"]}
            if not open_syms:
                return
            trades = trade_journal.get_trades()
        except Exception:
            return
        cost: Dict[str, Dict[str, float]] = {}
        for t in trades:
            if t.get("side") != "buy" or not t.get("fill_price"):
                continue
            d = cost.setdefault((t.get("symbol") or "").upper(),
                                {"qty": 0.0, "cost": 0.0})
            d["qty"] += float(t.get("qty") or 0)
            d["cost"] += float(t["fill_price"]) * float(t.get("qty") or 0)
        changed = False
        for sym, q in results.items():
            if sym not in open_syms or sym in self._roundup_flagged:
                continue
            d = cost.get(sym)
            if not d or d["qty"] <= 0:
                continue
            avg = d["cost"] / d["qty"]
            if avg > 0 and q["price"] >= avg * 2.5:
                self._roundup_flagged.add(sym)
                changed = True
                mult = q["price"] / avg
                self._push_notification(
                    f"⚡ {sym} is quoting {mult:.1f}× your avg cost — reverse "
                    f"split likely executed. Review and sell.", "warning")
                self._log(f"Round-up radar: {sym} at {mult:.1f}× cost — "
                          f"check & sell", "warn")
        if changed:
            self._render_pipeline()
            if self._active_nav == "holdings":
                self._render_allocation()

    def _sync_watchlist_from_picks(self) -> None:
        """Rebuild the watchlist/ticker from the RSA Quick Picks (the tickers we
        actually buy), newest first, plus any user-pinned extras. Fetches quotes
        for any newly-seen symbols."""
        seen, syms = set(), []
        for p in sorted(self._quick_picks, key=lambda p: p.get("date", ""),
                        reverse=True):
            s = (p.get("symbol") or "").upper().strip()
            if s and s not in seen:
                seen.add(s)
                syms.append(s)
        self._pick_symbols = syms
        extras = [s for s in self._user_watchlist if s not in seen]
        new_list = syms + extras
        added = [s for s in new_list if s not in self._watchlist]
        self._watchlist = new_list
        self._render_ticker_tape()
        self._render_dash_movers()
        if self._active_nav == "watchlist":
            self._render_watchlist()
        if added:
            self._run_in_thread(self._quote_many_worker, added)

    def _quote_many_worker(self, syms: List[str]) -> None:
        results = self._fetch_quotes_parallel(syms)
        if results:
            self.after(0, lambda: self._merge_quotes(results))

    def _pick_info(self, symbol: str) -> Optional[Dict[str, str]]:
        """Most-recent Quick Pick entry for a symbol (note/date), or None."""
        sym = symbol.upper()
        best = None
        for p in self._quick_picks:
            if (p.get("symbol") or "").upper() == sym:
                if best is None or p.get("date", "") >= best.get("date", ""):
                    best = p
        return best

    def _global_refresh(self) -> None:
        self._start_quote_loop()
        if self._active_nav == "dashboard":
            self._dashboard_refresh()
        elif self._active_nav == "holdings":
            self._holdings_refresh()
        elif self._active_nav == "stats":
            self._refresh_stats()
        self._push_notification("Refreshing live market data", "info")

    # ---- Notifications center ---------------------------------------------

    def _push_notification(self, message: str, kind: str = "info") -> None:
        self._notifications.insert(0, {
            "msg": message, "kind": kind,
            "time": datetime.now().strftime("%H:%M"),
        })
        del self._notifications[50:]
        self._notif_unread += 1
        self._update_notif_badge()
        self._show_toast(message, kind)
        if self._notif_popup is not None and self._notif_popup.winfo_exists():
            self._render_notifications()

    def _update_notif_badge(self) -> None:
        if not hasattr(self, "_notif_badge"):
            return
        if self._notif_unread > 0:
            txt = str(self._notif_unread) if self._notif_unread < 10 else "9+"
            self._notif_badge.configure(text=f" {txt} ")
            self._notif_badge.place(relx=1.0, rely=0.0, anchor="ne", x=-1, y=3)
        else:
            self._notif_badge.place_forget()

    # ---- Toasts (transient slide-in confirmations) --------------------------

    _TOAST_COLORS = {"success": GREEN, "error": RED, "warning": YELLOW, "info": ACCENT}
    _TOAST_ICONS = {"success": "check", "error": "error", "warning": "warning",
                    "info": "info"}

    def _show_toast(self, message: str, kind: str = "info") -> None:
        """Transient toast card, bottom-right of the window. Auto-dismisses;
        complements (not replaces) the notification center."""
        try:
            self._toasts = [t for t in self._toasts if t.winfo_exists()]
            if len(self._toasts) >= 3:
                self._toasts.pop(0).destroy()
                self._toasts = [t for t in self._toasts if t.winfo_exists()]
            c = self._TOAST_COLORS.get(kind, ACCENT)
            t = tk.Toplevel(self)
            # Stay unmapped until geometry + alpha are set, otherwise the window
            # is drawn at the default position and full opacity before the fade.
            t.withdraw()
            t.overrideredirect(True)
            t.attributes("-topmost", True)
            t.configure(bg=BORDER_LIGHT)
            body = tk.Frame(t, bg=BG_ELEVATED)
            body.pack(fill="both", expand=True, padx=1, pady=1)
            tk.Frame(body, bg=c, width=3).pack(side="left", fill="y")
            tk.Label(body, text=icon(self._TOAST_ICONS.get(kind, "info")),
                     bg=BG_ELEVATED, fg=c, font=(ICON_FONT, 12)).pack(
                         side="left", padx=(12, 9), pady=11)
            tk.Label(body, text=message[:120], bg=BG_ELEVATED, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 9, "bold"), wraplength=300,
                     justify="left").pack(side="left", padx=(0, 16), pady=11)
            t.update_idletasks()
            # withdrawn windows report winfo_width()==1, so use the requested size
            w, h = t.winfo_reqwidth(), t.winfo_reqheight()
            stack = sum(tt.winfo_reqheight() + 10 for tt in self._toasts
                        if tt.winfo_exists())
            x = self.winfo_rootx() + self.winfo_width() - w - 26
            y = self.winfo_rooty() + self.winfo_height() - h - 26 - stack
            t.geometry(f"{w}x{h}+{x}+{y}")
            try:
                t.attributes("-alpha", 0.0)
            except Exception:
                pass
            t.deiconify()

            def _fade(step: int = 0) -> None:
                try:
                    if t.winfo_exists() and step < 8:
                        t.attributes("-alpha", (step + 1) / 8)
                        t.after(18, _fade, step + 1)
                except Exception:
                    pass
            _fade()
            self._toasts.append(t)
            t.bind("<Button-1>", lambda e: t.destroy())

            def _dismiss() -> None:
                try:
                    if t.winfo_exists():
                        t.destroy()
                    self._toasts = [x for x in self._toasts if x.winfo_exists()]
                except Exception:
                    pass
            t.after(3800, _dismiss)
        except Exception:
            pass

    def _toggle_notifications(self) -> None:
        if self._notif_popup is not None and self._notif_popup.winfo_exists():
            self._notif_popup.destroy()
            self._notif_popup = None
            return
        self._notif_unread = 0
        self._update_notif_badge()
        pop = tk.Toplevel(self)
        self._notif_popup = pop
        pop.overrideredirect(True)
        pop.configure(bg=BORDER)
        pop.attributes("-topmost", True)
        w = 350
        bx = self._bell_btn.winfo_rootx()
        by = self._bell_btn.winfo_rooty()
        pop.geometry(f"{w}x440+{bx - w + 46}+{by + 42}")
        inner = tk.Frame(pop, bg=BG_ELEVATED)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        hdr = tk.Frame(inner, bg=BG_ELEVATED)
        hdr.pack(fill="x", padx=14, pady=(12, 8))
        tk.Label(hdr, text="Notifications", bg=BG_ELEVATED, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 11, "bold")).pack(side="left")
        clr = tk.Label(hdr, text="Clear all", bg=BG_ELEVATED, fg=ACCENT,
                       font=(FONT_FAMILY, 8, "bold"), cursor="hand2")
        clr.pack(side="right")
        clr.bind("<Button-1>", lambda e: self._clear_notifications())
        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x")
        self._notif_list = tk.Frame(inner, bg=BG_ELEVATED)
        self._notif_list.pack(fill="both", expand=True, padx=6, pady=6)
        self._render_notifications()

    def _clear_notifications(self) -> None:
        self._notifications.clear()
        self._render_notifications()

    def _render_notifications(self) -> None:
        if self._notif_popup is None or not self._notif_popup.winfo_exists():
            return
        for w in self._notif_list.winfo_children():
            w.destroy()
        if not self._notifications:
            tk.Label(self._notif_list, text="You're all caught up.",
                     bg=BG_ELEVATED, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, 9)).pack(pady=26)
            return
        colors = {"success": GREEN, "error": RED, "warning": YELLOW, "info": ACCENT}
        icons = {"success": "check", "error": "error", "warning": "warning", "info": "info"}
        for n in self._notifications[:30]:
            c = colors.get(n["kind"], ACCENT)
            row = tk.Frame(self._notif_list, bg=BG_CARD)
            row.pack(fill="x", pady=2, padx=4)
            box = tk.Frame(row, bg=BG_CARD)
            box.pack(fill="x", padx=11, pady=8)
            tk.Label(box, text=icon(icons.get(n["kind"], "info")), bg=BG_CARD,
                     fg=c, font=(ICON_FONT, 11)).pack(side="left", padx=(0, 9))
            txt = tk.Frame(box, bg=BG_CARD)
            txt.pack(side="left", fill="x", expand=True)
            tk.Label(txt, text=n["msg"], bg=BG_CARD, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 9), wraplength=250, justify="left",
                     anchor="w").pack(anchor="w")
            tk.Label(txt, text=n["time"], bg=BG_CARD, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, 7)).pack(anchor="w")

    # ---- Command palette (Ctrl+K) -----------------------------------------

    def _open_command_palette(self) -> None:
        if self._palette is not None and self._palette.winfo_exists():
            self._palette.lift()
            self._palette_entry.focus_set()
            return
        pal = tk.Toplevel(self)
        self._palette = pal
        pal.overrideredirect(True)
        pal.configure(bg=BORDER)
        pal.attributes("-topmost", True)
        w, h = 640, 470
        x = self.winfo_rootx() + (self.winfo_width() - w) // 2
        y = self.winfo_rooty() + 130
        pal.geometry(f"{w}x{h}+{x}+{y}")
        wrap = tk.Frame(pal, bg=BG_ELEVATED)
        wrap.pack(fill="both", expand=True, padx=1, pady=1)
        top = tk.Frame(wrap, bg=BG_ELEVATED)
        top.pack(fill="x", padx=16, pady=14)
        tk.Label(top, text=icon("search"), bg=BG_ELEVATED, fg=TEXT_SECONDARY,
                 font=(ICON_FONT, 15)).pack(side="left", padx=(2, 11))
        self._palette_entry = tk.Entry(top, bg=BG_ELEVATED, fg=TEXT_PRIMARY,
                                       insertbackground=ACCENT, font=(FONT_FAMILY, 14),
                                       relief="flat", bd=0)
        self._palette_entry.pack(side="left", fill="x", expand=True)
        tk.Frame(wrap, bg=BORDER, height=1).pack(fill="x")
        hint = tk.Frame(wrap, bg=BG_ELEVATED)
        hint.pack(fill="x", side="bottom")
        tk.Label(hint, text="↑ ↓ navigate      ↵ run      esc close",
                 bg=BG_ELEVATED, fg=TEXT_MUTED, font=(FONT_MONO, 8)).pack(
                     side="left", padx=16, pady=8)
        tk.Label(hint, text="RSAMAXXED COMMAND", bg=BG_ELEVATED, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 7, "bold")).pack(side="right", padx=16)
        tk.Frame(wrap, bg=BORDER, height=1).pack(fill="x", side="bottom")
        self._palette_results = tk.Frame(wrap, bg=BG_ELEVATED)
        self._palette_results.pack(fill="both", expand=True, padx=8, pady=8)
        self._palette_sel = 0
        self._palette_cmds: List[Dict[str, Any]] = []
        self._palette_entry.bind("<KeyRelease>", self._palette_on_key)
        self._palette_entry.bind("<Down>", lambda e: self._palette_move(1))
        self._palette_entry.bind("<Up>", lambda e: self._palette_move(-1))
        self._palette_entry.bind("<Return>", lambda e: self._palette_run())
        for w_ in (pal, self._palette_entry):
            w_.bind("<Escape>", lambda e: self._close_palette())
        pal.bind("<FocusOut>", lambda e: self._close_palette())
        self._palette_entry.focus_set()
        self._palette_filter()

    def _close_palette(self) -> None:
        if self._palette is not None:
            try:
                self._palette.destroy()
            except Exception:
                pass
            self._palette = None

    def _palette_on_key(self, event) -> None:
        if event.keysym in ("Up", "Down", "Return", "Escape"):
            return
        self._palette_filter()

    def _palette_commands(self, query: str) -> List[Dict[str, Any]]:
        cmds: List[Dict[str, Any]] = []
        tok = query.strip().upper()
        if re.fullmatch(r"[A-Z]{1,6}", tok):
            cmds.append({"icon": "eye", "label": f"Look up {tok}", "hint": "Quote",
                         "action": lambda t=tok: self._palette_lookup(t)})
            cmds.append({"icon": "trade", "label": f"Trade {tok}", "hint": "Order",
                         "action": lambda t=tok: self._palette_trade(t)})
            cmds.append({"icon": "watchlist", "label": f"Add {tok} to watchlist",
                         "hint": "Watchlist",
                         "action": lambda t=tok: (self._add_watchlist_symbol(t),
                                                  self._show_frame("watchlist"))})
        for sect, items in self._NAV_SECTIONS:
            for name, label, ic in items:
                cmds.append({"icon": ic, "label": f"Go to {label}",
                             "hint": sect.title(),
                             "action": lambda n=name: self._show_frame(n)})
        cmds.append({"icon": "refresh", "label": "Refresh live data",
                     "hint": "Action", "action": self._global_refresh})
        cmds.append({"icon": "export", "label": "Export trade history (CSV)",
                     "hint": "Action", "action": self._export_trades_csv})
        q = query.strip().lower()
        if q:
            filt = [c for c in cmds if q in c["label"].lower() or q in c["hint"].lower()]
            cmds = filt or cmds
        return cmds[:8]

    def _palette_filter(self) -> None:
        query = self._palette_entry.get()
        self._palette_cmds = self._palette_commands(query)
        self._palette_sel = 0
        self._palette_render()

    def _palette_render(self) -> None:
        for w in self._palette_results.winfo_children():
            w.destroy()
        if not self._palette_cmds:
            tk.Label(self._palette_results, text="No matching commands",
                     bg=BG_ELEVATED, fg=TEXT_MUTED, font=(FONT_FAMILY, 10)).pack(pady=24)
            return
        for i, c in enumerate(self._palette_cmds):
            sel = (i == self._palette_sel)
            bg = BG_CARD_ALT if sel else BG_ELEVATED
            row = tk.Frame(self._palette_results, bg=bg, cursor="hand2")
            row.pack(fill="x", pady=1)
            inner = tk.Frame(row, bg=bg)
            inner.pack(fill="x", padx=12, pady=9)
            tk.Label(inner, text=icon(c["icon"]), bg=bg,
                     fg=ACCENT if sel else TEXT_SECONDARY,
                     font=(ICON_FONT, 13)).pack(side="left", padx=(0, 12))
            tk.Label(inner, text=c["label"], bg=bg,
                     fg=TEXT_PRIMARY if sel else TEXT_SECONDARY,
                     font=(FONT_FAMILY, 11, "bold" if sel else "normal")).pack(side="left")
            tk.Label(inner, text=c["hint"], bg=bg, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, 8)).pack(side="right")
            for w in (row, inner):
                w.bind("<Button-1>", lambda e, idx=i: self._palette_run(idx))

    def _palette_move(self, delta: int) -> None:
        if not self._palette_cmds:
            return
        self._palette_sel = (self._palette_sel + delta) % len(self._palette_cmds)
        self._palette_render()

    def _palette_run(self, idx: Optional[int] = None) -> None:
        if idx is None:
            idx = self._palette_sel
        if 0 <= idx < len(self._palette_cmds):
            action = self._palette_cmds[idx]["action"]
            self._close_palette()
            try:
                action()
            except Exception as ex:
                self._log(f"Command failed: {ex}", "error")

    def _palette_lookup(self, ticker: str) -> None:
        self._show_frame("stats")
        try:
            self._stats_search.delete(0, "end")
            self._stats_search.insert(0, ticker)
            self._stats_ticker_lookup()
        except Exception:
            pass

    def _palette_trade(self, ticker: str) -> None:
        self._show_frame("trade")
        try:
            self._set_trade_side("buy")
            self._trade_symbol.delete(0, "end")
            self._trade_symbol.insert(0, ticker)
            self._trade_qty.delete(0, "end")
            self._trade_qty.insert(0, "1")
        except Exception:
            pass

    # ---- Keyboard shortcuts -----------------------------------------------

    def _install_shortcuts(self) -> None:
        self.bind("<Control-k>", lambda e: self._open_command_palette())
        self.bind("<Control-K>", lambda e: self._open_command_palette())
        self.bind("<Control-r>", lambda e: self._global_refresh())
        # Same order as _NAV_SECTIONS, so Ctrl+N counts down the sidebar. Only
        # the first nine: there is no <Control-Key-10> keysym, and binding one
        # raises at startup rather than failing quietly.
        order = [name for _sect, items in self._NAV_SECTIONS for name, _l, _i in items]
        for i, name in enumerate(order[:9], start=1):
            self.bind(f"<Control-Key-{i}>", lambda e, n=name: self._show_frame(n))

    # ---- Lightweight mousewheel scroller (no CTkScrollableFrame overhead) ---

    def _make_vscroll(self, parent):
        """Return (outer, inner): a tk.Canvas-backed scroll region whose inner
        frame you pack content into. Mousewheel scrolls while hovering anywhere
        inside — no scrollbar dragging needed. Far lighter than CTkScrollableFrame."""
        outer = tk.Frame(parent, bg=BG_PRIMARY)
        canvas = tk.Canvas(outer, bg=BG_PRIMARY, highlightthickness=0, bd=0)
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG_PRIMARY)
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        def _wheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        outer.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", _wheel))
        outer.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))
        return outer, inner

    # ---- Shared micro-components -------------------------------------------

    def _empty_state(self, parent, ic: str, title: str, sub: str = "",
                     bg: str = BG_PRIMARY, pad: int = 26) -> tk.Frame:
        """Consistent friendly empty-state block (icon, title, hint)."""
        box = tk.Frame(parent, bg=bg)
        tk.Label(box, text=icon(ic), bg=bg, fg=TEXT_MUTED,
                 font=(ICON_FONT, 24)).pack(pady=(pad, 8))
        tk.Label(box, text=title, bg=bg, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 11, "bold")).pack()
        tk.Label(box, text=sub, bg=bg, fg=TEXT_MUTED, font=(FONT_FAMILY, 9),
                 wraplength=480, justify="center").pack(pady=(3, pad))
        return box

    def _bind_row_click(self, row: tk.Frame, handler) -> None:
        """Make a whole row clickable, including its labels.

        Skips any widget that already has its own <Button-1> — the action chips
        ("Top up", "Mark done") must keep their handler, and binding with add
        would fire both, so a click meant to expand a row would also buy.
        """
        def _walk(w) -> None:
            if w.__class__.__module__.startswith("customtkinter"):
                return
            try:
                if not w.bind("<Button-1>"):
                    w.bind("<Button-1>", handler)
                    w.configure(cursor="hand2")
            except Exception:
                pass
            for ch in w.winfo_children():
                _walk(ch)
        _walk(row)

    def _bind_row_hover(self, row: tk.Frame, base: str, hover: str) -> None:
        """Repaint a flat row's matching-bg widgets on pointer enter/leave.
        Only widgets whose bg equals the row surface are touched, so badges,
        stripes and CTk children keep their own colors."""
        def _paint(col: str) -> None:
            def walk(w) -> None:
                if w.__class__.__module__.startswith("customtkinter"):
                    return
                try:
                    if str(w.cget("bg")) in (base, hover):
                        w.configure(bg=col)
                except Exception:
                    pass
                for ch in w.winfo_children():
                    walk(ch)
            walk(row)

        def _on_leave(_e) -> None:
            try:
                x, y = row.winfo_pointerxy()
                rx, ry = row.winfo_rootx(), row.winfo_rooty()
                inside = (rx <= x < rx + row.winfo_width()
                          and ry <= y < ry + row.winfo_height())
            except Exception:
                inside = False
            if not inside:
                _paint(base)

        def _bind_all(w) -> None:
            if w.__class__.__module__.startswith("customtkinter"):
                return
            w.bind("<Enter>", lambda e: _paint(hover), add="+")
            w.bind("<Leave>", _on_leave, add="+")
            for ch in w.winfo_children():
                _bind_all(ch)
        _bind_all(row)

    # ---- Watchlist --------------------------------------------------------

    def _build_watchlist(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["watchlist"] = frame

        top = tk.Frame(frame, bg=BG_PRIMARY)
        top.pack(fill="x", pady=(0, 14))
        add_box = ctk.CTkFrame(top, corner_radius=9, fg_color=BG_INPUT,
                               bg_color=BG_PRIMARY, border_width=1, border_color=BORDER)
        add_box.pack(side="left")
        tk.Label(add_box, text=icon("add"), bg=BG_INPUT, fg=TEXT_MUTED,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(12, 6), pady=8)
        self._wl_entry = tk.Entry(add_box, bg=BG_INPUT, fg=TEXT_PRIMARY,
                                  insertbackground=ACCENT, font=(FONT_MONO, 11),
                                  relief="flat", bd=0, width=12)
        self._wl_entry.pack(side="left", padx=(0, 12), pady=9)
        self._wl_entry.bind("<Return>",
                            lambda e: self._add_watchlist_symbol(self._wl_entry.get()))
        PillButton(top, text="Add Symbol",
                   command=lambda: self._add_watchlist_symbol(self._wl_entry.get()),
                   width=112, height=40, font_size=10).pack(side="left", padx=(10, 0))

        outer, self._wl_list = self._make_vscroll(frame)
        outer.pack(fill="both", expand=True)
        self._render_watchlist()

    def _render_watchlist(self) -> None:
        if not hasattr(self, "_wl_list"):
            return
        for w in self._wl_list.winfo_children():
            w.destroy()
        if not self._watchlist:
            self._empty_state(
                self._wl_list, "watchlist", "No picks on the radar yet",
                "Your RSA picks appear here automatically once they sync — "
                "or pin an extra ticker above.").pack(fill="x")
            return
        purchased = {s for (s, d) in self._get_purchased_pick_set(self._quick_picks)}
        reg_notes = ("reg alert", "alert", "early access")
        # Flat rows (tk.Frame, no per-row CTk canvas) keep a 39-row list snappy.
        for sym in self._watchlist:
            q = self._quotes.get(sym)
            info = self._pick_info(sym)
            is_pick = sym in self._pick_symbols
            is_bought = sym in purchased
            is_reg = bool(info) and info.get("note", "").lower() in reg_notes

            row = tk.Frame(self._wl_list, bg=BG_CARD)
            row.pack(fill="x", pady=(0, 6))
            tk.Frame(row, bg=ACCENT if is_reg else BORDER, width=3).pack(
                side="left", fill="y")
            body = tk.Frame(row, bg=BG_CARD)
            body.pack(side="left", fill="x", expand=True, padx=16, pady=12)

            # left: symbol + RSA note / date / purchased badge
            left = tk.Frame(body, bg=BG_CARD)
            left.pack(side="left")
            sym_row = tk.Frame(left, bg=BG_CARD)
            sym_row.pack(anchor="w")
            tk.Label(sym_row, text=sym, bg=BG_CARD, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 16, "bold")).pack(side="left")
            if is_bought:
                badge = tk.Frame(sym_row, bg=GREEN_SOFT)
                badge.pack(side="left", padx=(8, 0))
                tk.Label(badge, text=f" {icon('check')} Bought ", bg=GREEN_SOFT,
                         fg=GREEN, font=(FONT_FAMILY, 8, "bold")).pack()
            meta = tk.Frame(left, bg=BG_CARD)
            meta.pack(anchor="w", pady=(2, 0))
            if info:
                note = info.get("note", "")
                disp = self._NOTE_DISPLAY.get(note.lower(), note) if note else "RSA pick"
                ncol = ACCENT if is_reg else TEXT_SECONDARY
                tk.Label(meta, text=disp or "RSA pick", bg=BG_CARD, fg=ncol,
                         font=(FONT_FAMILY, 8, "bold")).pack(side="left")
                d = info.get("date", "")
                if d:
                    tk.Label(meta, text=f"   ·   {d}", bg=BG_CARD, fg=TEXT_MUTED,
                             font=(FONT_FAMILY, 8)).pack(side="left")
            else:
                tk.Label(meta, text="Tracked", bg=BG_CARD, fg=TEXT_MUTED,
                         font=(FONT_FAMILY, 8)).pack(side="left")

            # right: actions
            act = tk.Frame(body, bg=BG_CARD)
            act.pack(side="right")
            if not is_pick:  # only manually-pinned extras can be removed
                rm = tk.Label(act, text=icon("delete"), bg=BG_CARD, fg=TEXT_MUTED,
                              font=(ICON_FONT, 12), cursor="hand2")
                rm.pack(side="right", padx=(16, 0))
                rm.bind("<Button-1>", lambda e, s=sym: self._remove_watchlist_symbol(s))
            PillButton(act, text="Buy 1", command=lambda s=sym: self._palette_trade(s),
                       width=72, height=30, font_size=9).pack(side="right")

            # quote + change (many RSA/OTC names have no public quote)
            if q:
                pcol = GREEN if q["pct"] >= 0 else RED
                pr = tk.Frame(body, bg=BG_CARD)
                pr.pack(side="right", padx=(0, 30))
                tk.Label(pr, text=f"${q['price']:,.2f}", bg=BG_CARD, fg=TEXT_PRIMARY,
                         font=(FONT_MONO, 16, "bold")).pack(anchor="e")
                chg = tk.Frame(pr, bg=BG_CARD)
                chg.pack(anchor="e")
                tk.Label(chg, text=icon("up") if q["pct"] >= 0 else icon("down"),
                         bg=BG_CARD, fg=pcol, font=(ICON_FONT, 8)).pack(side="left")
                tk.Label(chg, text=f" {q['change']:+.2f} ({q['pct']:+.2f}%)",
                         bg=BG_CARD, fg=pcol, font=(FONT_MONO, 9, "bold")).pack(side="left")
            else:
                tk.Label(body, text="no public quote", bg=BG_CARD, fg=TEXT_MUTED,
                         font=(FONT_FAMILY, 9)).pack(side="right", padx=(0, 30))

            # intraday sparkline (only names Yahoo actually quotes)
            if q and len(q.get("spark") or []) >= 2:
                sc = tk.Canvas(body, bg=BG_CARD, width=96, height=30,
                               highlightthickness=0, bd=0)
                sc.pack(side="right", padx=(0, 26), pady=3)
                self._draw_sparkline(sc, list(q["spark"]),
                                     GREEN if q["pct"] >= 0 else RED)
            self._bind_row_hover(row, BG_CARD, BG_CARD_ALT)

    def _add_watchlist_symbol(self, raw: str) -> None:
        sym = (raw or "").strip().upper()
        if not sym or not re.fullmatch(r"[A-Z]{1,6}", sym):
            return
        if sym not in self._user_watchlist:
            self._user_watchlist.append(sym)
            _save_watchlist(self._user_watchlist)
        if sym not in self._watchlist:
            self._watchlist.append(sym)
            self._render_watchlist()
            self._render_ticker_tape()
            self._log(f"Watchlist: tracking {sym}")
            self._run_in_thread(self._quote_one_worker, sym)
        try:
            self._wl_entry.delete(0, "end")
        except Exception:
            pass

    def _quote_one_worker(self, sym: str) -> None:
        q = _fetch_quote(sym)
        if q:
            self.after(0, lambda: self._merge_quotes({sym: q}))

    def _remove_watchlist_symbol(self, sym: str) -> None:
        if sym in self._user_watchlist:
            self._user_watchlist.remove(sym)
            _save_watchlist(self._user_watchlist)
        if sym in self._watchlist and sym not in self._pick_symbols:
            self._watchlist.remove(sym)
        self._render_watchlist()
        self._render_ticker_tape()
        self._log(f"Watchlist: removed {sym}")

    def _draw_sparkline(self, canvas: tk.Canvas, data: list, color: str) -> None:
        try:
            canvas.delete("all")
            w = int(canvas.cget("width")) or canvas.winfo_width()
            h = int(canvas.cget("height")) or canvas.winfo_height()
            pad = 4
            lo, hi = min(data), max(data)
            rng = (hi - lo) or 1.0
            n = len(data)
            pts = []
            for i, v in enumerate(data):
                x = pad + (w - 2 * pad) * i / (n - 1)
                y = (h - pad) - (h - 2 * pad) * (v - lo) / rng
                pts.append((x, y))
            fill = _blend(color, BG_CARD, 0.82)
            poly = [pad, h - pad] + [c for p in pts for c in p] + [w - pad, h - pad]
            canvas.create_polygon(poly, fill=fill, outline="")
            flat = [c for p in pts for c in p]
            canvas.create_line(flat, fill=color, width=2)
        except Exception:
            pass

    # ---- CSV export -------------------------------------------------------

    def _export_trades_csv(self) -> None:
        import csv
        from tkinter import filedialog
        try:
            trades = trade_journal.get_trades()
        except Exception:
            trades = []
        if not trades:
            self._push_notification("No trades to export yet", "warning")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="rsamaxxed_trades.csv", parent=self)
        if not path:
            return
        cols = ["timestamp", "broker", "account_id", "side", "symbol", "qty", "fill_price"]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                wr = csv.writer(f)
                wr.writerow(cols)
                for t in trades:
                    wr.writerow([t.get(c, "") for c in cols])
            self._push_notification(f"Exported {len(trades)} trades", "success")
            self._log(f"Exported {len(trades)} trades to {path}")
        except Exception as ex:
            self._push_notification(f"Export failed: {ex}", "error")

    # ---- Logging ----------------------------------------------------------

    # Top-level feed lines get a colored category badge; detail lines (broker
    # sub-steps, ✔/⚠/✘ rows, indented progress) nest under them without one.
    _LOG_BADGES = {
        "trade error": ("TRADE", "trade"), "trade": ("TRADE", "trade"),
        "mirror": ("MIRROR", "mirror"),
        "round-up radar": ("RADAR", "radar"), "radar": ("RADAR", "radar"),
        "reverse-split": ("RADAR", "radar"),
        "alert": ("ALERT", "alert"),
        "quick pick": ("PICK", "pick"),
        "watchlist": ("WATCH", "watch"),
        "dashboard": ("DASH", "dash"),
        "stats": ("STATS", "stats"),
        "bootstrap": ("BOOT", "boot"),
        "command": ("CMD", "cmd"),
        "exported": ("EXPORT", "export"), "export": ("EXPORT", "export"),
    }

    def _log_category(self, msg: str):
        m = msg.lower()
        for kw, spec in self._LOG_BADGES.items():
            if m.startswith(kw):
                return spec
        return ("SYS", "sys")

    def _log(self, msg: str, tag: Optional[str] = None) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_lines.append((f"{ts}  {msg}", tag))
        if not hasattr(self, "_log_text"):
            return
        t = self._log_text
        t.configure(state="normal")
        t.insert("end", f"{ts}  ", "ts")
        stripped = msg.lstrip() if msg else ""
        is_detail = bool(msg) and (msg[:1] in (" ", "\t")
                                   or stripped[:1] in ("✔", "⚠", "✘", "•", "→"))
        if msg and not is_detail:
            label, key = self._log_category(msg)
            t.insert("end", f" {label} ", f"badge_{key}")
            t.insert("end", "  ")
        elif is_detail:
            t.insert("end", "     ")   # indent so detail nests under its parent
        if tag:
            t.insert("end", msg, tag)
        else:
            t.insert("end", msg)
        t.insert("end", "\n")
        t.see("end")
        t.configure(state="disabled")

    def _run_in_thread(self, target, *args) -> None:
        threading.Thread(target=target, args=args, daemon=True).start()

    # ---- Dashboard --------------------------------------------------------

    def _update_total_accounts(self, broker: str = None, count: int = None) -> None:
        """Update a broker's account count and refresh the total accounts card."""
        if broker and count is not None:
            self._broker_account_counts[broker] = count
        total = sum(self._broker_account_counts.values())
        self._dash_accounts.configure(text=str(total))

    def _render_dash_movers(self) -> None:
        """Top movers panel on the dashboard, driven by live watchlist quotes."""
        if not hasattr(self, "_dash_movers"):
            return
        for w in self._dash_movers.winfo_children():
            w.destroy()
        quotes = [self._quotes[s] for s in self._watchlist if s in self._quotes]
        quotes.sort(key=lambda q: abs(q.get("pct", 0.0)), reverse=True)
        if not quotes:
            tk.Label(self._dash_movers, text="Live quotes loading…", bg=BG_CARD,
                     fg=TEXT_MUTED, font=(FONT_FAMILY, 9)).pack(anchor="w", pady=8)
            return
        for q in quotes[:5]:
            up = q["pct"] >= 0
            col = GREEN if up else RED
            row = tk.Frame(self._dash_movers, bg=BG_CARD)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=q["symbol"], bg=BG_CARD, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 10, "bold"), width=7, anchor="w").pack(side="left")
            tk.Label(row, text=f"${q['price']:,.2f}", bg=BG_CARD, fg=TEXT_SECONDARY,
                     font=(FONT_MONO, 10)).pack(side="left")
            chg = tk.Frame(row, bg=BG_CARD)
            chg.pack(side="right")
            tk.Label(chg, text=icon("up") if up else icon("down"), bg=BG_CARD,
                     fg=col, font=(ICON_FONT, 8)).pack(side="left")
            tk.Label(chg, text=f" {q['pct']:+.2f}%", bg=BG_CARD, fg=col,
                     font=(FONT_MONO, 10, "bold")).pack(side="left")

    def _build_dashboard(self) -> None:
        outer = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["dashboard"] = outer

        canvas = tk.Canvas(outer, bg=BG_PRIMARY, highlightthickness=0, bd=0)
        canvas.pack(fill="both", expand=True)

        frame = tk.Frame(canvas, bg=BG_PRIMARY)
        win_id = canvas.create_window((0, 0), window=frame, anchor="nw")

        def _on_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        frame.bind("<Configure>", _on_configure)

        def _on_canvas_configure(e):
            canvas.itemconfig(win_id, width=e.width)
        canvas.bind("<Configure>", _on_canvas_configure)

        def _dash_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

        def _dash_enter(e):
            canvas.bind_all("<MouseWheel>", _dash_mousewheel)

        def _dash_leave(e):
            canvas.unbind_all("<MouseWheel>")

        outer.bind("<Enter>", _dash_enter)
        outer.bind("<Leave>", _dash_leave)

        # ===== Hero: portfolio value + live top movers =====
        hero_row = tk.Frame(frame, bg=BG_PRIMARY)
        hero_row.pack(fill="x", pady=(0, 14))
        hero_row.columnconfigure(0, weight=3, uniform="hero")
        hero_row.columnconfigure(1, weight=2, uniform="hero")

        hero = RoundedFrame(hero_row, bg_color=BG_HERO,
                            border_color=_blend(ACCENT, BORDER, 0.55),
                            radius=RAD_LG)
        hero.grid(row=0, column=0, sticky="nsew", padx=(0, SP_MD))
        # accent glow fading into the panel — reads as a lit top edge
        for t in (0.45, 0.62, 0.75, 0.85, 0.93, 0.98):
            tk.Frame(hero.inner, bg=_blend(ACCENT, BG_HERO, t), height=2).pack(
                fill="x")
        hb = tk.Frame(hero.inner, bg=BG_HERO)
        hb.pack(fill="both", expand=True, padx=28, pady=(20, 24))
        lab_row = tk.Frame(hb, bg=BG_HERO)
        lab_row.pack(fill="x")
        tk.Label(lab_row, text=icon("lightning"), bg=BG_HERO, fg=ACCENT,
                 font=(ICON_FONT, 10)).pack(side="left", padx=(0, 7))
        tk.Label(lab_row, text="NET REALIZED PROFIT", bg=BG_HERO,
                 fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, FS_LABEL, "bold")).pack(side="left")
        tk.Label(lab_row, text="JOURNAL-VERIFIED", bg=BG_HERO, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 7, "bold")).pack(side="right")
        self._dash_value = tk.Label(hb, text="$0.00", bg=BG_HERO, fg=TEXT_PRIMARY,
                                    font=(FONT_MONO, FS_DISPLAY, "bold"))
        self._dash_value.pack(anchor="w", pady=(6, 2))
        self._dash_value_sub = tk.Label(
            hb, text="Realized P/L shows after a confirmed buy → sell at a higher price",
            bg=BG_HERO, fg=TEXT_MUTED, font=(FONT_FAMILY, 9))
        self._dash_value_sub.pack(anchor="w")

        tk.Frame(hb, bg=_blend(ACCENT, BORDER, 0.75), height=1).pack(
            fill="x", pady=(20, 18))
        substats = tk.Frame(hb, bg=BG_HERO)
        substats.pack(fill="x")

        def _substat(label):
            cell = tk.Frame(substats, bg=BG_HERO)
            cell.pack(side="left", expand=True, fill="x")
            tk.Label(cell, text=label, bg=BG_HERO, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, FS_MICRO, "bold")).pack(anchor="w")
            val = tk.Label(cell, text="$0.00", bg=BG_HERO, fg=TEXT_PRIMARY,
                           font=(FONT_MONO, 17, "bold"))
            val.pack(anchor="w", pady=(3, 0))
            return val

        self._dash_invested = _substat("DEPLOYED (OPEN COST)")
        self._dash_pl = _substat("OPEN POSITIONS")
        startup_total = sum(
            _KNOWN_ACCOUNT_COUNTS.get(b, 1) if _broker_has_creds(b) else 0
            for b in BROKER_MODULES
        )
        self._dash_accounts = _substat("ACCOUNTS")
        self._dash_accounts.configure(text=str(startup_total))
        self._broker_account_counts: Dict[str, int] = {
            b: _KNOWN_ACCOUNT_COUNTS.get(b, 1) if _broker_has_creds(b) else 0
            for b in BROKER_MODULES
        }

        movers_card = RoundedFrame(hero_row, bg_color=BG_CARD, border_color=BORDER,
                                   radius=RAD_LG)
        movers_card.grid(row=0, column=1, sticky="nsew")
        mh = tk.Frame(movers_card.inner, bg=BG_CARD)
        mh.pack(fill="x", padx=20, pady=(18, 8))
        tk.Label(mh, text=icon("up"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(0, 8))
        tk.Label(mh, text="Top Movers", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 13, "bold")).pack(side="left")
        tk.Label(mh, text="RSA PICKS", bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 7, "bold")).pack(side="right")
        self._dash_movers = tk.Frame(movers_card.inner, bg=BG_CARD)
        self._dash_movers.pack(fill="both", expand=True, padx=20, pady=(2, 14))
        self._render_dash_movers()

        # ===== RSA pipeline — the strategy's lifecycle at a glance =====
        pipe_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER,
                                 radius=RAD_LG)
        pipe_card.pack(fill="x", pady=(0, 12))
        pipe_head = tk.Frame(pipe_card.inner, bg=BG_CARD)
        pipe_head.pack(fill="x", padx=20, pady=(16, 2))
        tk.Label(pipe_head, text=icon("lightning"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(0, 8))
        tk.Label(pipe_head, text="RSA Pipeline", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 13, "bold")).pack(side="left")
        tk.Label(pipe_head, text="PICK  →  BUY  →  SPLIT  →  SELL", bg=BG_CARD,
                 fg=TEXT_MUTED, font=(FONT_FAMILY, 7, "bold")).pack(side="right")
        strip = tk.Frame(pipe_card.inner, bg=BG_CARD)
        strip.pack(fill="x", padx=20, pady=(8, 18))
        self._pipe_stages: Dict[str, tk.Label] = {}
        for i, (key, label, hint) in enumerate([
            ("new", "NEW PICKS", "awaiting entry"),
            ("open", "IN PLAY", "open round-up bets"),
            ("watch", "ROUND-UP WATCH", "quote ≫ cost — check & sell"),
            ("closed", "CLOSED", "realized round-trips"),
        ]):
            if i:
                tk.Label(strip, text=icon("chevright"), bg=BG_CARD, fg=TEXT_MUTED,
                         font=(ICON_FONT, 11)).pack(side="left", padx=12)
            cell = tk.Frame(strip, bg=BG_CARD)
            cell.pack(side="left", expand=True, fill="x")
            val = tk.Label(cell, text="0", bg=BG_CARD, fg=TEXT_PRIMARY,
                           font=(FONT_MONO, 20, "bold"))
            val.pack(anchor="w")
            tk.Label(cell, text=label, bg=BG_CARD, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 8, "bold")).pack(anchor="w")
            tk.Label(cell, text=hint, bg=BG_CARD, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, 8)).pack(anchor="w")
            self._pipe_stages[key] = val

        # broker status card
        status_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        status_card.pack(fill="x", pady=(0, 12))

        header = tk.Frame(status_card.inner, bg=BG_CARD)
        header.pack(fill="x", padx=20, pady=(16, 12))
        tk.Label(header, text=icon("brokers"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(0, 8))
        tk.Label(header, text="Broker Status", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 13, "bold")).pack(side="left")
        PillButton(header, text="Refresh All", command=self._dashboard_refresh,
                   width=110, height=28).pack(side="right")

        self._broker_status_labels: Dict[str, Dict[str, Any]] = {}
        self._public_status_labels: Dict[int, Dict[str, Any]] = {}

        list_frame = tk.Frame(status_card.inner, bg=BG_CARD)
        list_frame.pack(fill="x", padx=20, pady=(0, 16))

        def _status_row(name: str, status_text: str) -> Dict[str, Any]:
            row = tk.Frame(list_frame, bg=BG_CARD)
            row.pack(fill="x", pady=2)
            dot = StatusDot(row, color=GREEN, size=8)
            dot.pack(side="left", padx=(0, 10))
            tk.Label(row, text=name, bg=BG_CARD, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 10), width=12, anchor="w").pack(side="left")
            status_lbl = tk.Label(row, text=status_text, bg=BG_CARD, fg=GREEN,
                                   font=(FONT_FAMILY, 9))
            status_lbl.pack(side="left", padx=(8, 0))
            return {"dot": dot, "status": status_lbl}

        for broker in sorted(BROKER_MODULES):
            if not _broker_has_creds(broker):
                continue
            # Public runs one independent login per API secret token — render each
            # configured token as its own P1/P2/P3 row so you can see which connects.
            if broker == "public":
                for idx in _public_token_indices():
                    self._public_status_labels[idx] = _status_row(f"Public P{idx}", "credentials set")
                continue

            n = _KNOWN_ACCOUNT_COUNTS.get(broker)
            status_text = f"{n} account(s)" if n else "credentials set"
            self._broker_status_labels[broker] = _status_row(broker.capitalize(), status_text)

        # ---- Custom Accounts card ----
        custom_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        custom_card.pack(fill="x", pady=(0, 12))

        custom_header = tk.Frame(custom_card.inner, bg=BG_CARD)
        custom_header.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(custom_header, text=icon("profile"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(0, 8))
        tk.Label(custom_header, text="Custom Accounts", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 13, "bold")).pack(side="left")
        PillButton(custom_header, text="+ Add", command=self._add_custom_account,
                   width=70, height=28).pack(side="right")

        self._custom_list_frame = tk.Frame(custom_card.inner, bg=BG_CARD)
        self._custom_list_frame.pack(fill="x", padx=20, pady=(0, 16))
        self._custom_account_widgets: List[Dict[str, Any]] = []
        self._rebuild_custom_accounts_list()

        # ---- Quick Picks card ----
        picks_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        picks_card.pack(fill="x", pady=(12, 0))

        picks_header = tk.Frame(picks_card.inner, bg=BG_CARD)
        picks_header.pack(fill="x", padx=20, pady=(16, 8))

        # Tab-style labels: Quick Picks | Partial | Purchased
        self._picks_tab_active = "picks"  # "picks", "partial" or "purchased"
        # (SYMBOL, date) rows showing their missing-account breakdown.
        self._pick_expanded: set = set()

        tk.Label(picks_header, text=icon("starfill"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(0, 8))
        self._picks_tab_lbl = tk.Label(picks_header, text="Quick Picks", bg=BG_CARD,
                 fg=TEXT_PRIMARY, font=(FONT_FAMILY, 13, "bold"), cursor="hand2")
        self._picks_tab_lbl.pack(side="left")
        self._picks_tab_lbl.bind("<Button-1>", lambda e: self._switch_picks_tab("picks"))

        tk.Label(picks_header, text="   |   ", bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 12)).pack(side="left")

        self._partial_tab_lbl = tk.Label(picks_header, text="Partial", bg=BG_CARD,
                 fg=TEXT_MUTED, font=(FONT_FAMILY, 13, "bold"), cursor="hand2")
        self._partial_tab_lbl.pack(side="left")
        self._partial_tab_lbl.bind("<Button-1>", lambda e: self._switch_picks_tab("partial"))

        tk.Label(picks_header, text="   |   ", bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 12)).pack(side="left")

        self._purchased_tab_lbl = tk.Label(picks_header, text="Purchased", bg=BG_CARD,
                 fg=TEXT_MUTED, font=(FONT_FAMILY, 13, "bold"), cursor="hand2")
        self._purchased_tab_lbl.pack(side="left")
        self._purchased_tab_lbl.bind("<Button-1>", lambda e: self._switch_picks_tab("purchased"))

        PillButton(picks_header, text="Reload", command=self._reload_quick_picks,
                   width=80, height=28).pack(side="right", padx=(4, 0))
        if os.environ.get("RSAMAXXED_ADMIN") == "1":
            PillButton(picks_header, text="Manage Picks", command=self._manage_picks,
                       width=110, height=28).pack(side="right")

        # Render picks inline — the dashboard's single outer scroll handles it
        # (no nested canvas, which was the source of the scroll lag).
        picks_body = tk.Frame(picks_card.inner, bg=BG_CARD)
        picks_body.pack(fill="x", padx=20, pady=(0, 16))
        self._picks_grid = tk.Frame(picks_body, bg=BG_CARD)
        self._picks_grid.pack(fill="x")
        # hidden until their tab is selected
        self._partial_grid = tk.Frame(picks_body, bg=BG_CARD)
        self._purchased_grid = tk.Frame(picks_body, bg=BG_CARD)

        # ---- Sell Alerts card ----
        # The SELL channel names the brokerage for every exit; that was parsed
        # and dropped on the floor. Exits are never auto-traded (an alerter
        # selling says nothing about what you hold), so this is a worklist.
        sell_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER,
                                 radius=14)
        sell_card.pack(fill="x", pady=(12, 0))

        sell_header = tk.Frame(sell_card.inner, bg=BG_CARD)
        sell_header.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(sell_header, text=icon("down"), bg=BG_CARD, fg=RED,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(0, 8))
        tk.Label(sell_header, text="Sell Alerts", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 13, "bold")).pack(side="left")
        self._sell_count_lbl = tk.Label(sell_header, text="", bg=BG_CARD,
                                        fg=TEXT_MUTED,
                                        font=(FONT_FAMILY, 9))
        self._sell_count_lbl.pack(side="left", padx=(10, 0))
        tk.Label(sell_header, text="FROM DISCORD · NEVER AUTO-TRADED", bg=BG_CARD,
                 fg=TEXT_MUTED, font=(FONT_FAMILY, 7, "bold")).pack(side="right")

        self._sell_grid = tk.Frame(sell_card.inner, bg=BG_CARD)
        self._sell_grid.pack(fill="x", padx=20, pady=(0, 16))
        self._render_sell_alerts()

        # Fetch picks in background on startup
        self.after(300, self._reload_quick_picks)

    def _render_sell_alerts(self) -> None:
        """Recent exits, newest first. Fed by the cloud, or by Discord when
        this machine is the one running the feed."""
        grid = getattr(self, "_sell_grid", None)
        if grid is None:
            return
        for w in grid.winfo_children():
            w.destroy()

        sells = _load_sells()
        self._sell_count_lbl.configure(
            text=f"{len(sells)} in the last {SELL_MAX_AGE_DAYS} days" if sells else "")

        if not sells:
            self._empty_state(
                grid, "info", "No sell alerts yet",
                "Exits arrive with your subscription once this device is "
                "linked — no Discord needed — and name the brokerage each one "
                "was taken at.",
                bg=BG_CARD, pad=16).pack(fill="x")
            return

        held = {s for (_b, s) in trade_journal.get_portfolio()}
        for sell in sells[:12]:
            sym = str(sell.get("symbol") or "???").upper()
            row_bg = BG_INPUT
            row = tk.Frame(grid, bg=row_bg)
            row.pack(fill="x", pady=(0, 5))
            tk.Frame(row, bg=RED if sym in held else BORDER, width=3).pack(
                side="left", fill="y")
            inner = tk.Frame(row, bg=row_bg)
            inner.pack(side="left", fill="x", expand=True, padx=(12, 14), pady=9)

            top = tk.Frame(inner, bg=row_bg)
            top.pack(fill="x")
            tk.Label(top, text=sym, bg=row_bg, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 13, "bold")).pack(side="left")
            px = sell.get("exit_price")
            if px is not None:
                tk.Label(top, text=f"  @ ${float(px):,.4f}".rstrip("0").rstrip("."),
                         bg=row_bg, fg=TEXT_SECONDARY,
                         font=(FONT_MONO, 9)).pack(side="left")
            # Only offer the action for something we actually hold — an alerter
            # exiting says nothing about our own position.
            if sym in held:
                act = tk.Label(top, text="Sell 1 ea →",
                               bg=_blend(RED, row_bg, 0.82), fg=RED,
                               font=(FONT_FAMILY, 9, "bold"), padx=10, pady=3,
                               cursor="hand2")
                act.pack(side="right")
                act.bind("<Button-1>",
                         lambda e, s=sym: self._prefill_trade(s, "sell", "1"))
            else:
                tk.Label(top, text="not held", bg=row_bg, fg=TEXT_MUTED,
                         font=(FONT_FAMILY, 8)).pack(side="right")
            if sell.get("sell_date"):
                tk.Label(top, text=str(sell["sell_date"]), bg=row_bg,
                         fg=TEXT_MUTED, font=(FONT_MONO, 8)).pack(
                             side="right", padx=(0, 14))

            legs = _sell_legs_text(sell)
            if legs:
                tk.Label(inner, text=legs, bg=row_bg, fg=TEXT_SECONDARY,
                         font=(FONT_MONO, 8), justify="left",
                         wraplength=760).pack(anchor="w", pady=(4, 0))
            meta = []
            proceeds = sell.get("proceeds_low")
            if proceeds is not None:
                hi = sell.get("proceeds_high")
                meta.append(f"+${float(proceeds):,.2f}"
                            + (f"–${float(hi):,.2f}" if hi and hi > proceeds else ""))
            if sell.get("note"):
                meta.append(str(sell["note"])[:110])
            if meta:
                tk.Label(inner, text="  ·  ".join(meta), bg=row_bg, fg=TEXT_MUTED,
                         font=(FONT_FAMILY, 8), justify="left",
                         wraplength=760).pack(anchor="w", pady=(2, 0))
            self._bind_row_hover(row, row_bg, BG_CARD_ALT)

    def _switch_picks_tab(self, tab: str) -> None:
        """Switch between Quick Picks and Purchased tabs."""
        self._picks_tab_active = tab
        grids = {"picks": self._picks_grid,
                 "partial": self._partial_grid,
                 "purchased": self._purchased_grid}
        for g in grids.values():
            g.pack_forget()
        grids.get(tab, self._picks_grid).pack(fill="x")
        self._picks_tab_lbl.configure(
            fg=TEXT_PRIMARY if tab == "picks" else TEXT_MUTED)
        self._partial_tab_lbl.configure(
            fg=YELLOW if tab == "partial" else TEXT_MUTED)
        self._purchased_tab_lbl.configure(
            fg=GREEN if tab == "purchased" else TEXT_MUTED)

    def _reload_quick_picks(self) -> None:
        """Fetch quick picks from remote gist in a background thread."""
        def _worker():
            picks = _fetch_quick_picks()
            self.after(0, lambda: self._render_quick_picks(picks))
        threading.Thread(target=_worker, daemon=True).start()

    # Note label mappings — normalize display text
    _NOTE_DISPLAY = {
        "reg alert": "Reg Alert",
        "alert": "Reg Alert",
        "early access": "Reg Alert",
    }

    def _get_purchased_pick_set(self, picks: List[Dict[str, str]]) -> set:
        """Return set of (symbol, date) tuples for picks that have been bought."""
        return _purchased_pick_keys(picks)

    def _mark_pick_done(self, symbol: str, date_str: str) -> None:
        """Move a part-filled pick to Purchased by hand.

        Full coverage isn't always reachable — a broker can be down or a name
        restricted — so this is the escape hatch that keeps Partial a real
        worklist instead of a graveyard.
        """
        key = (str(symbol).upper(), str(date_str))
        if not key[1]:
            return
        done = _load_done_picks()
        done.add(key)
        _save_done_picks(done)
        self._log(f"Picks: marked {key[0]} ({key[1]}) done")
        self._render_quick_picks(self._quick_picks)
        self._switch_picks_tab("partial")

    def _unmark_pick_done(self, symbol: str, date_str: str) -> None:
        """Undo _mark_pick_done — send the pick back to Partial."""
        key = (str(symbol).upper(), str(date_str))
        done = _load_done_picks()
        if key not in done:
            return
        done.discard(key)
        _save_done_picks(done)
        self._log(f"Picks: reopened {key[0]} ({key[1]})")
        self._render_quick_picks(self._quick_picks)
        self._switch_picks_tab("purchased")

    def _render_quick_picks(self, picks: List[Dict[str, str]]) -> None:
        """Render picks into the three tabs (available / partial / purchased)."""
        for grid in (self._picks_grid, self._partial_grid, self._purchased_grid):
            for w in grid.winfo_children():
                w.destroy()
        self._quick_picks = picks
        if picks:
            self._repair_mirror_executed()
        # Watchlist + ticker tape track the RSA picks we buy.
        self._sync_watchlist_from_picks()
        self._render_pipeline()

        if not picks:
            # Empty has two very different causes and the user can act on only
            # one of them, so never show the same message for both: "nothing is
            # open today" is normal, "we can't reach the feed" is a problem.
            # There is deliberately nothing to sign up for here — the plays
            # arrive on their own.
            if _PICKS_AUTH_ERROR:
                # The one empty state the user MUST act on. Waiting will not
                # fix it, so this says the opposite of the message below — and
                # carries the button that fixes it, rather than describing a
                # file they would have to go and find.
                box = self._empty_state(
                    self._picks_grid, "warning", "Add your plays password",
                    "This copy has no plays password yet, so the feed won't "
                    "send anything. Paste the one you were given — the same "
                    "one that opens rsamaxxed.com/plays. Waiting will not fix "
                    "this on its own.",
                    bg=BG_CARD, pad=18)
                PillButton(box, text="Enter password",
                           command=self._prompt_plays_key,
                           width=150, height=32).pack(pady=(0, 18))
                box.pack(fill="x")
            elif getattr(self, "_feed_fail_streak", 0) or self._feed_last_ok is None:
                self._empty_state(
                    self._picks_grid, "warning", "Waiting for the play feed",
                    "Couldn't reach the feed just now. It retries by itself "
                    "every few minutes — nothing for you to do, and nothing to "
                    "sign up for. Your saved plays stay put in the meantime.",
                    bg=BG_CARD, pad=18).pack(fill="x")
            else:
                self._empty_state(
                    self._picks_grid, "starfill", "No open plays right now",
                    f"Nothing is live today. New alerts land here on their own — "
                    f"the feed is checked every hour "
                    f"(last at {self._feed_last_ok:%H:%M}).",
                    bg=BG_CARD, pad=18).pack(fill="x")
            return

        purchased_pick_set = self._get_purchased_pick_set(picks)
        partial_pick_set = _partial_pick_keys(picks)

        def _key(p: Dict[str, str]) -> tuple:
            return (p.get("symbol", "").upper(), p.get("date", ""))

        purchased_picks = [p for p in picks if _key(p) in purchased_pick_set]
        partial_picks = [p for p in picks if _key(p) in partial_pick_set]
        available_picks = [p for p in picks
                           if _key(p) not in purchased_pick_set
                           and _key(p) not in partial_pick_set]

        self._partial_tab_lbl.configure(
            text=f"Partial ({len(partial_picks)})" if partial_picks else "Partial")
        self._purchased_tab_lbl.configure(
            text=f"Purchased ({len(purchased_picks)})" if purchased_picks
            else "Purchased")

        # ---- Not started (main tab) ----
        if available_picks:
            self._render_picks_list(self._picks_grid, available_picks, "available")
        else:
            self._empty_state(
                self._picks_grid, "check", "Nothing left to open",
                "Every live pick has at least one confirmed buy — "
                "check Partial for the ones still owed accounts.",
                bg=BG_CARD, pad=14).pack(fill="x")

        # ---- Partially filled ----
        if partial_picks:
            self._render_picks_list(self._partial_grid, partial_picks, "partial")
        else:
            self._empty_state(
                self._partial_grid, "check", "Nothing part-filled",
                "Picks bought on some accounts but not all show up here.",
                bg=BG_CARD, pad=14).pack(fill="x")

        # ---- Fully covered / marked done ----
        if purchased_picks:
            self._render_picks_list(self._purchased_grid, purchased_picks, "purchased")
        else:
            self._empty_state(
                self._purchased_grid, "check", "Nothing bought yet",
                "Picks move here once a buy is confirmed in the journal.",
                bg=BG_CARD, pad=14).pack(fill="x")

    # Pick note -> (badge text, badge color). Coverage + badges are the core of
    # the RSA pick rows: profit scales linearly with accounts filled.
    _NOTE_STYLE = {
        "reg alert": ("REG ALERT", ACCENT),
        "otc": ("OTC", YELLOW),
        "conditional": ("CONDITIONAL", BLUE),
    }

    @staticmethod
    def _pick_age_label(date_str: str) -> str:
        try:
            d = datetime.strptime(str(date_str), "%Y-%m-%d").date()
        except (ValueError, TypeError):
            return ""
        days = (datetime.now().date() - d).days
        if days <= 0:
            return "today"
        left = PICK_MAX_AGE_DAYS - days
        return f"{days}d old" + (f" · expires in {left}d" if 0 <= left <= 1 else "")

    def _note_style(self, note: str) -> tuple:
        n = (note or "").lower()
        if n in ("alert", "early access"):
            return self._NOTE_STYLE["reg alert"]
        for key, style in self._NOTE_STYLE.items():
            if n.startswith(key) or key in n:
                return style
        return ((note or "RSA").upper()[:18], TEXT_SECONDARY)

    def _account_universe(self) -> int:
        """Total account count across linked brokers — coverage denominator.

        Must agree with _account_universe_static(), which decides when a pick
        counts as fully bought: if the bar's denominator and the Purchased gate
        disagree, a row reads "43/27 accounts" and never leaves Quick Picks.
        """
        counts = getattr(self, "_broker_account_counts", None)
        live = sum(counts.values()) if counts else 0
        return max(live, _account_universe_static())

    @staticmethod
    def _draw_coverage_bar(cv: tk.Canvas, frac: float, color: str) -> None:
        try:
            w, h = int(cv.cget("width")), int(cv.cget("height"))
        except Exception:
            return
        cv.delete("all")
        frac = max(0.0, min(1.0, frac))
        cv.create_rectangle(0, 0, w, h, fill=BG_ELEVATED, outline="")
        if frac > 0:
            cv.create_rectangle(0, 0, max(2, w * frac), h, fill=color, outline="")

    def _render_pipeline(self) -> None:
        """Refresh the Command Center pipeline strip (pick→buy→split→sell)."""
        if not hasattr(self, "_pipe_stages"):
            return
        try:
            s = self._portfolio_summary()
        except Exception:
            return
        purchased = self._get_purchased_pick_set(self._quick_picks)
        avail = sum(1 for p in self._quick_picks
                    if (p.get("symbol", "").upper(), p.get("date", ""))
                    not in purchased)
        self._pipe_stages["new"].configure(
            text=str(avail), fg=ACCENT if avail else TEXT_PRIMARY)
        self._pipe_stages["open"].configure(text=str(s["open_count"]))
        n_watch = len(self._roundup_flagged)
        self._pipe_stages["watch"].configure(
            text=str(n_watch), fg=YELLOW if n_watch else TEXT_PRIMARY)
        self._pipe_stages["closed"].configure(
            text=str(s["closed"]),
            fg=GREEN if s["realized"] > 0 else TEXT_PRIMARY)
        if hasattr(self, "_status_journal"):
            try:
                n_tr = len(trade_journal.get_trades())
            except Exception:
                n_tr = 0
            self._status_journal.configure(
                text=f"JOURNAL · {n_tr} TRADES · REALIZED ${s['realized']:+,.2f}")

    def _render_picks_list(self, parent: tk.Frame, picks: List[Dict[str, str]],
                           mode: str = "available") -> None:
        """Pick rows grouped by alert date: type badge, age, account-coverage
        bar (bought on n of M accounts) and a buy / top-up action.

        mode is 'available' (nothing bought yet), 'partial' (some accounts) or
        'purchased' (every account, or manually marked done).
        """
        purchased = mode == "purchased"
        done_keys = _load_done_picks()
        from collections import OrderedDict
        try:
            all_trades = trade_journal.get_trades()
        except Exception:
            all_trades = []
        buys_by_sym: Dict[str, List[tuple]] = {}
        for t in all_trades:
            if t.get("side") == "buy":
                buys_by_sym.setdefault((t.get("symbol") or "").upper(), []).append(
                    ((t.get("timestamp") or "")[:10], t.get("broker"),
                     t.get("account_id")))
        universe = self._account_universe()

        grouped: OrderedDict = OrderedDict()
        for pick in picks:
            grouped.setdefault(pick.get("date", "Unknown"), []).append(pick)

        for date_str in sorted(grouped.keys(), reverse=True):
            try:
                display_date = datetime.strptime(
                    date_str, "%Y-%m-%d").strftime("%B %d, %Y")
            except (ValueError, TypeError):
                display_date = str(date_str)

            hdr = tk.Frame(parent, bg=BG_CARD)
            hdr.pack(fill="x", pady=(12, 5))
            tk.Label(hdr, text=display_date.upper(), bg=BG_CARD, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, 8, "bold")).pack(side="left")
            age = self._pick_age_label(date_str)
            if age:
                tk.Label(hdr, text=f"   ·   {age}", bg=BG_CARD, fg=TEXT_MUTED,
                         font=(FONT_FAMILY, 8)).pack(side="left")
            tk.Frame(parent, bg=GREEN if purchased else (
                YELLOW if mode == "partial" else BORDER), height=1).pack(
                    fill="x", pady=(0, 6))

            pdate = date_str if re.fullmatch(r"\d{4}-\d{2}-\d{2}",
                                             str(date_str)) else ""
            for pick in grouped[date_str]:
                sym = pick.get("symbol", "???").upper()
                btxt, bcol = self._note_style(pick.get("note", ""))
                n_acct = len({(b, a) for (d, b, a) in buys_by_sym.get(sym, [])
                              if not pdate or (d and d >= pdate)})

                row_bg = BG_INPUT
                # Every row does something on click now: available -> buy,
                # partial/purchased -> open the missing-account breakdown.
                row = tk.Frame(parent, bg=row_bg, cursor="hand2")
                row.pack(fill="x", pady=(0, 5))
                stripe = GREEN if purchased else (
                    YELLOW if mode == "partial" else bcol)
                tk.Frame(row, bg=stripe, width=3).pack(side="left", fill="y")
                inner = tk.Frame(row, bg=row_bg)
                inner.pack(side="left", fill="x", expand=True,
                           padx=(12, 14), pady=9)

                tk.Label(inner, text=sym, bg=row_bg, fg=TEXT_PRIMARY,
                         font=(FONT_FAMILY, 13, "bold")).pack(side="left")
                tk.Label(inner, text=f" {btxt} ", bg=_blend(bcol, row_bg, 0.82),
                         fg=bcol, font=(FONT_FAMILY, 7, "bold"), pady=1).pack(
                             side="left", padx=(10, 0))

                if purchased:
                    if universe and n_acct >= universe:
                        tk.Label(inner, text=f"{icon('check')} Filled", bg=row_bg,
                                 fg=GREEN, font=(FONT_FAMILY, 9, "bold")).pack(
                                     side="right")
                    elif (sym, pdate) in done_keys:
                        # Called finished by hand rather than fully covered —
                        # say so, and let it be undone.
                        undo = tk.Label(inner, text="Marked done · reopen",
                                        bg=row_bg, fg=TEXT_MUTED,
                                        font=(FONT_FAMILY, 8), cursor="hand2")
                        undo.pack(side="right")
                        undo.bind("<Button-1>",
                                  lambda e, s=sym, d=pdate: self._unmark_pick_done(s, d))
                    else:
                        top = tk.Label(inner, text="Top up →",
                                       bg=_blend(ACCENT, row_bg, 0.82),
                                       fg=ACCENT_HOVER,
                                       font=(FONT_FAMILY, 9, "bold"),
                                       padx=10, pady=3, cursor="hand2")
                        top.pack(side="right")
                        top.bind("<Button-1>",
                                 lambda e, s=sym: self._prefill_trade(s, "buy", "1"))
                elif mode == "partial":
                    done = tk.Label(inner, text=f"{icon('check')} Mark done",
                                    bg=_blend(GREEN, row_bg, 0.82), fg=GREEN,
                                    font=(FONT_FAMILY, 9, "bold"),
                                    padx=10, pady=3, cursor="hand2")
                    done.pack(side="right")
                    done.bind("<Button-1>",
                              lambda e, s=sym, d=pdate: self._mark_pick_done(s, d))
                    top = tk.Label(inner, text="Top up →",
                                   bg=_blend(ACCENT, row_bg, 0.82),
                                   fg=ACCENT_HOVER,
                                   font=(FONT_FAMILY, 9, "bold"),
                                   padx=10, pady=3, cursor="hand2")
                    top.pack(side="right", padx=(0, 8))
                    top.bind("<Button-1>",
                             lambda e, s=sym: self._prefill_trade(s, "buy", "1"))
                else:
                    tk.Label(inner, text="Buy →", bg=_blend(GREEN, row_bg, 0.82),
                             fg=GREEN, font=(FONT_FAMILY, 9, "bold"),
                             padx=10, pady=3, cursor="hand2").pack(side="right")

                # account-coverage bar — the operational number that matters
                if n_acct or purchased:
                    covw = tk.Frame(inner, bg=row_bg)
                    covw.pack(side="right", padx=(0, 18))
                    cv = tk.Canvas(covw, width=110, height=5, bg=row_bg,
                                   highlightthickness=0, bd=0)
                    cv.pack(anchor="e", pady=(3, 2))
                    frac = (n_acct / universe) if universe else 0.0
                    self._draw_coverage_bar(cv, frac, stripe if mode == "partial"
                                            else (GREEN if purchased else ACCENT))
                    cap = tk.Frame(covw, bg=row_bg)
                    cap.pack(anchor="e")
                    tk.Label(cap, text=f"{n_acct}/{universe} accounts",
                             bg=row_bg, fg=TEXT_SECONDARY,
                             font=(FONT_MONO, 7)).pack(side="left")
                    n_missing = max(0, universe - n_acct)
                    if n_missing and pdate:
                        expanded = (sym, pdate) in self._pick_expanded
                        miss_lbl = tk.Label(
                            cap,
                            text=f"  ·  {n_missing} missing "
                                 f"{icon('chevdown') if expanded else icon('chevright')}",
                            bg=row_bg, fg=YELLOW, font=(FONT_MONO, 7),
                            cursor="hand2")
                        miss_lbl.pack(side="left")
                        miss_lbl.bind(
                            "<Button-1>",
                            lambda e, s=sym, d=pdate: self._toggle_pick_detail(s, d))

                if mode == "available":
                    self._bind_row_click(
                        row, lambda e, s=sym: self._quick_pick_buy(s))
                elif pdate:
                    # Once a pick has any fills, the useful thing to see is
                    # which brokers still owe it and why — buying is the
                    # explicit "Top up" button, not a whole-row click that
                    # could fire by accident.
                    self._bind_row_click(
                        row, lambda e, s=sym, d=pdate: self._toggle_pick_detail(s, d))
                self._bind_row_hover(row, row_bg, BG_CARD_ALT)

                if pdate and (sym, pdate) in self._pick_expanded:
                    self._render_pick_detail(parent, sym, pdate)

    def _toggle_pick_detail(self, symbol: str, date_str: str) -> None:
        key = (str(symbol).upper(), str(date_str))
        if key in self._pick_expanded:
            self._pick_expanded.discard(key)
        else:
            self._pick_expanded.add(key)
        tab = self._picks_tab_active
        self._render_quick_picks(self._quick_picks)
        self._switch_picks_tab(tab)

    def _render_pick_detail(self, parent: tk.Frame, symbol: str,
                            date_str: str) -> None:
        """Which accounts are missing this pick, grouped by broker and reason.

        Grouped rather than one row per account: 38 identical "not attempted"
        lines is noise, "wellsfargo · 10 accounts · symbol not eligible for
        online trading" is the answer.
        """
        missing = _pick_missing_accounts(symbol, date_str)
        panel = tk.Frame(parent, bg=BG_CARD_ALT)
        panel.pack(fill="x", pady=(0, 6), padx=(3, 0))
        body = tk.Frame(panel, bg=BG_CARD_ALT)
        body.pack(fill="x", padx=16, pady=(10, 12))

        if not missing:
            tk.Label(body, text=f"{icon('check')}  Every account holds {symbol}",
                     bg=BG_CARD_ALT, fg=GREEN,
                     font=(FONT_FAMILY, 9, "bold")).pack(anchor="w")
            return

        n_failed = sum(1 for m in missing if m["status"] == "failed")
        head = f"{len(missing)} ACCOUNT{'S' if len(missing) != 1 else ''} MISSING"
        if n_failed:
            head += f"  ·  {n_failed} REJECTED BY THE BROKER"
        tk.Label(body, text=head, bg=BG_CARD_ALT, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).pack(anchor="w", pady=(0, 7))

        # (broker, tidied reason) -> accounts sharing it
        groups: Dict[tuple, List[str]] = {}
        for m in missing:
            reason = _tidy_reason(m["reason"]) if m["status"] == "failed" else ""
            groups.setdefault((m["broker"], reason), []).append(m["account"])

        # Broker rejections first — they are the ones needing a decision.
        for (broker, reason), accts in sorted(
                groups.items(), key=lambda kv: (not kv[0][1], kv[0][0])):
            line = tk.Frame(body, bg=BG_CARD_ALT)
            line.pack(fill="x", pady=(0, 5))
            tk.Frame(line, bg=RED if reason else TEXT_MUTED, width=2).pack(
                side="left", fill="y", padx=(0, 9))
            txt = tk.Frame(line, bg=BG_CARD_ALT)
            txt.pack(side="left", fill="x", expand=True)

            top = tk.Frame(txt, bg=BG_CARD_ALT)
            top.pack(fill="x")
            tk.Label(top, text=broker.capitalize(), bg=BG_CARD_ALT,
                     fg=TEXT_PRIMARY, font=(FONT_FAMILY, 9, "bold")).pack(side="left")
            tk.Label(top, text=f"  {len(accts)} account"
                              f"{'s' if len(accts) != 1 else ''}",
                     bg=BG_CARD_ALT, fg=TEXT_MUTED,
                     font=(FONT_MONO, 8)).pack(side="left")
            tk.Label(top, text="  REJECTED" if reason else "  NOT ATTEMPTED",
                     bg=BG_CARD_ALT, fg=RED if reason else TEXT_MUTED,
                     font=(FONT_FAMILY, 7, "bold")).pack(side="left")

            tk.Label(txt, text=reason or "No order was ever sent for this pick.",
                     bg=BG_CARD_ALT, fg=TEXT_SECONDARY if reason else TEXT_MUTED,
                     font=(FONT_FAMILY, 8), justify="left",
                     wraplength=620).pack(anchor="w", pady=(1, 0))

    def _prefill_trade(self, ticker: str, side: str = "buy", qty: str = "1") -> None:
        """Jump to the Trade Desk with side / symbol / qty pre-filled."""
        self._show_frame("trade")
        try:
            self._set_trade_side(side)
            self._trade_symbol.delete(0, "end")
            self._trade_symbol.insert(0, ticker.upper())
            self._trade_qty.delete(0, "end")
            self._trade_qty.insert(0, qty)
            self._update_trade_estimate()
        except Exception:
            pass

    def _quick_pick_buy(self, symbol: str) -> None:
        """Jump to Trade tab with symbol and qty pre-filled."""
        self._prefill_trade(symbol, "buy", "1")
        self._log(f"Quick Pick: {symbol} loaded — select brokers and execute")

    @staticmethod
    def _parse_discord_picks(raw: str) -> List[Dict[str, str]]:
        """Parse raw Discord-style messages into pick entries.

        Strips emojis, usernames, @Premium, timestamps, etc.
        Extracts tickers from (TICKER) pattern and classifies note type.
        """
        import re as _re
        picks = []
        # Match tickers in parentheses like (ZNB)
        # Also detect note type from keywords before the ticker
        lines = raw.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Find all (TICKER) patterns
            ticker_matches = _re.findall(r"\(([A-Za-z]{1,5})\)", line)
            if not ticker_matches:
                continue
            # Determine note type from keywords in the line
            line_lower = line.lower()
            # Strip emojis and special chars for analysis
            clean = _re.sub(r"[^\w\s\-()@,.$]", "", line_lower)
            if "conditional" in clean:
                # Extract everything after CONDITIONAL as the note, remove ticker and noise
                cond_match = _re.search(r"conditional\s*[-–—]?\s*(.*)", line_lower)
                note_text = cond_match.group(1).strip() if cond_match else ""
                note_text = _re.sub(r"\([a-z]{1,5}\)", "", note_text)  # remove (TICKER)
                note_text = _re.sub(r"@\w+", "", note_text).strip()
                note_text = note_text.strip(" -–—")
                note = f"conditional - {note_text}" if note_text else "conditional"
            elif "otc" in clean:
                otc_match = _re.search(r"otc\s*[-–—]?\s*(.*)", line_lower)
                note_text = otc_match.group(1).strip() if otc_match else ""
                note_text = _re.sub(r"\([a-z]{1,5}\)", "", note_text)  # remove (TICKER)
                note_text = _re.sub(r"@\w+", "", note_text).strip()
                note_text = note_text.strip(" -–—")
                note = f"OTC - {note_text}" if note_text else "OTC"
            elif "early access" in clean:
                note = "Reg Alert"
            elif "alert" in clean:
                note = "Reg Alert"
            else:
                note = "Reg Alert"

            for ticker in ticker_matches:
                # Skip noise words that look like tickers
                if ticker.upper() in ("IDLE", "ALERT", "OTC", "EARLY", "PREMIUM"):
                    continue
                picks.append({"symbol": ticker.upper(), "note": note})
        return picks

    def _manage_picks(self) -> None:
        """Dialog to add/remove quick picks — date picker + raw paste, appends to existing."""
        dlg = tk.Toplevel(self)
        dlg.title("Manage Quick Picks")
        dlg.configure(bg=BG_CARD)
        dlg.geometry("500x500")
        dlg.resizable(False, False)

        # Date picker row
        date_frame = tk.Frame(dlg, bg=BG_CARD)
        date_frame.pack(fill="x", padx=16, pady=(16, 8))

        tk.Label(date_frame, text="DATE:", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(side="left", padx=(0, 8))

        today = datetime.now().strftime("%Y-%m-%d")
        # Month
        months = [f"{i:02d}" for i in range(1, 13)]
        month_var = tk.StringVar(value=datetime.now().strftime("%m"))
        month_menu = ttk.Combobox(date_frame, textvariable=month_var, values=months,
                                  width=4, font=(FONT_MONO, 10), state="readonly")
        month_menu.pack(side="left", padx=(0, 4))
        tk.Label(date_frame, text="/", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 10)).pack(side="left")
        # Day
        days = [f"{i:02d}" for i in range(1, 32)]
        day_var = tk.StringVar(value=datetime.now().strftime("%d"))
        day_menu = ttk.Combobox(date_frame, textvariable=day_var, values=days,
                                width=4, font=(FONT_MONO, 10), state="readonly")
        day_menu.pack(side="left", padx=(4, 4))
        tk.Label(date_frame, text="/", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 10)).pack(side="left")
        # Year
        cur_year = datetime.now().year
        years = [str(y) for y in range(cur_year - 1, cur_year + 2)]
        year_var = tk.StringVar(value=str(cur_year))
        year_menu = ttk.Combobox(date_frame, textvariable=year_var, values=years,
                                 width=6, font=(FONT_MONO, 10), state="readonly")
        year_menu.pack(side="left", padx=(4, 0))

        # Instructions
        tk.Label(dlg, text="Paste raw messages below (auto-extracts tickers, strips noise):",
                 bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 9)).pack(
                     anchor="w", padx=16, pady=(4, 4))

        txt = tk.Text(dlg, bg=BG_INPUT, fg=TEXT_PRIMARY, font=(FONT_MONO, 10),
                      height=10, bd=0, insertbackground=TEXT_PRIMARY,
                      highlightthickness=1, highlightcolor=ACCENT, padx=8, pady=8)
        txt.pack(fill="x", padx=16, pady=(0, 4))

        # Preview area
        preview_lbl = tk.Label(dlg, text="", bg=BG_CARD, fg=TEXT_MUTED,
                               font=(FONT_FAMILY, 9), justify="left", anchor="w")
        preview_lbl.pack(fill="x", padx=16)

        def _preview(event=None):
            raw = txt.get("1.0", "end").strip()
            if not raw:
                preview_lbl.configure(text="")
                return
            parsed = self._parse_discord_picks(raw)
            if parsed:
                lines = [f"  {p['symbol']}  —  {p['note']}" for p in parsed]
                preview_lbl.configure(
                    text=f"Found {len(parsed)} ticker(s):\n" + "\n".join(lines),
                    fg=TEXT_PRIMARY)
            else:
                preview_lbl.configure(text="No tickers found — use (TICKER) format", fg=RED)

        txt.bind("<KeyRelease>", _preview)

        status_lbl = tk.Label(dlg, text="", bg=BG_CARD, fg=TEXT_MUTED,
                              font=(FONT_FAMILY, 9))
        status_lbl.pack(anchor="w", padx=16, pady=(4, 0))

        def _save():
            raw = txt.get("1.0", "end").strip()
            if not raw:
                status_lbl.configure(text="Paste some messages first.", fg=RED)
                return

            date_str = f"{year_var.get()}-{month_var.get()}-{day_var.get()}"
            parsed = self._parse_discord_picks(raw)
            if not parsed:
                status_lbl.configure(text="No tickers found.", fg=RED)
                return

            # Add date to each pick
            for p in parsed:
                p["date"] = date_str

            # Merge with existing picks (append new ones)
            existing = list(self._quick_picks) if self._quick_picks else []
            # Avoid duplicates for same date+symbol
            existing_keys = {(p.get("date"), p.get("symbol")) for p in existing}
            for p in parsed:
                if (p["date"], p["symbol"]) not in existing_keys:
                    existing.append(p)

            all_picks = existing
            status_lbl.configure(text="Saving...", fg=TEXT_MUTED)
            dlg.update()

            def _push():
                import json as _json
                # Save locally first (primary storage)
                try:
                    PICKS_FILE.write_text(_json.dumps(all_picks, indent=2), encoding="utf-8")
                except Exception as ex:
                    self.after(0, lambda: status_lbl.configure(
                        text=f"Local save failed: {ex}", fg=RED))
                    return

                # Publishing to the shared feed is best-effort, and only happens
                # at all on the operator's machine — see _push_picks_remote.
                _push_picks_remote(all_picks)

                self.after(0, lambda: self._render_quick_picks(all_picks))
                self.after(0, lambda: status_lbl.configure(
                    text=f"Added {len(parsed)} pick(s) for {date_str}!", fg=GREEN))
                self.after(0, lambda: self._log(
                    f"Quick Picks: added {len(parsed)} tickers for {date_str}"))

            threading.Thread(target=_push, daemon=True).start()

        def _clear_all():
            # Local only. The cloud feed is insert-only and keyed on source_id,
            # so nothing here can unpublish a play — and that is deliberate: the
            # old build cleared the shared list for every user from this button.
            # Anything still open will come back on the next feed refresh.
            if messagebox.askyesno(
                    "Clear All Picks",
                    "Clear the pick list on this machine?\n\n"
                    "Plays that are still open will reappear on the next sync.",
                    parent=dlg):
                def _push_empty():
                    try:
                        PICKS_FILE.write_text("[]", encoding="utf-8")
                    except Exception as ex:
                        self.after(0, lambda: status_lbl.configure(
                            text=f"Failed: {ex}", fg=RED))
                        return
                    self.after(0, lambda: self._render_quick_picks([]))
                    self.after(0, lambda: status_lbl.configure(
                        text="Picks cleared on this machine.", fg=TEXT_MUTED))
                threading.Thread(target=_push_empty, daemon=True).start()

        btn_row = tk.Frame(dlg, bg=BG_CARD)
        btn_row.pack(fill="x", padx=16, pady=(8, 16))
        PillButton(btn_row, text="Add Picks", command=_save,
                   width=120, height=36).pack(side="left", padx=(0, 8))
        PillButton(btn_row, text="Clear All", command=_clear_all,
                   width=100, height=36).pack(side="left")
        PillButton(btn_row, text="Cancel", command=dlg.destroy,
                   width=80, height=36).pack(side="right")

    def _make_metric_card(self, parent, title: str, value: str, col: int,
                          accent: str = ACCENT, caption: str = "") -> tk.Label:
        card = RoundedFrame(parent, bg_color=BG_CARD, border_color=BORDER,
                            radius=RAD_MD, height=112)
        card.grid(row=0, column=col, sticky="nsew",
                  padx=(0, SP_MD) if col < 3 else (0, 0))

        # accent micro-bar (category color cue)
        tk.Frame(card.inner, bg=accent, height=3).pack(fill="x")

        body = tk.Frame(card.inner, bg=BG_CARD)
        body.pack(fill="both", expand=True, padx=SP_XL, pady=(SP_LG, SP_LG))

        tk.Label(body, text=title.upper(), bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, FS_LABEL, "bold")).pack(anchor="w")

        val_lbl = tk.Label(body, text=value, bg=BG_CARD, fg=TEXT_PRIMARY,
                           font=(FONT_MONO, FS_VALUE, "bold"))
        val_lbl.pack(anchor="w", pady=(SP_XS, 0))

        if caption:
            tk.Label(body, text=caption, bg=BG_CARD, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, FS_MICRO)).pack(anchor="w")
        return val_lbl

    # ---- Custom Accounts ---------------------------------------------------

    def _rebuild_custom_accounts_list(self) -> None:
        for w in self._custom_list_frame.winfo_children():
            w.destroy()
        self._custom_account_widgets.clear()

        accounts = _load_custom_accounts()
        if not accounts:
            tk.Label(self._custom_list_frame, text="No custom accounts yet",
                     bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 9)).pack(anchor="w")
            return

        # Header row
        hdr = tk.Frame(self._custom_list_frame, bg=BG_CARD)
        hdr.pack(fill="x", pady=(0, 4))
        for txt, w in [("Name", 16), ("Invested", 12), ("Value", 12), ("P/L", 12)]:
            tk.Label(hdr, text=txt, bg=BG_CARD, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 8, "bold"), width=w, anchor="w").pack(side="left")

        for i, acct in enumerate(accounts):
            row = tk.Frame(self._custom_list_frame, bg=BG_CARD)
            row.pack(fill="x", pady=1)

            invested = acct.get("invested", 0.0)
            value = acct.get("value", 0.0)
            pl = value - invested

            tk.Label(row, text=acct.get("name", ""), bg=BG_CARD, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 9), width=16, anchor="w").pack(side="left")
            tk.Label(row, text=f"${invested:,.2f}", bg=BG_CARD, fg=TEXT_PRIMARY,
                     font=(FONT_MONO, 9), width=12, anchor="w").pack(side="left")
            tk.Label(row, text=f"${value:,.2f}", bg=BG_CARD, fg=TEXT_PRIMARY,
                     font=(FONT_MONO, 9), width=12, anchor="w").pack(side="left")
            pl_color = GREEN if pl >= 0 else RED
            tk.Label(row, text=f"${pl:+,.2f}", bg=BG_CARD, fg=pl_color,
                     font=(FONT_MONO, 9), width=12, anchor="w").pack(side="left")

            edit_btn = tk.Label(row, text="edit", bg=BG_CARD, fg=ACCENT,
                                font=(FONT_FAMILY, 8), cursor="hand2")
            edit_btn.pack(side="left", padx=(4, 0))
            edit_btn.bind("<Button-1>", lambda e, idx=i: self._edit_custom_account(idx))

            del_btn = tk.Label(row, text="x", bg=BG_CARD, fg=RED,
                               font=(FONT_FAMILY, 8, "bold"), cursor="hand2")
            del_btn.pack(side="left", padx=(8, 0))
            del_btn.bind("<Button-1>", lambda e, idx=i: self._delete_custom_account(idx))

    def _add_custom_account(self) -> None:
        self._custom_account_dialog()

    def _edit_custom_account(self, idx: int) -> None:
        accounts = _load_custom_accounts()
        if idx < len(accounts):
            self._custom_account_dialog(edit_idx=idx, defaults=accounts[idx])

    def _delete_custom_account(self, idx: int) -> None:
        accounts = _load_custom_accounts()
        if idx < len(accounts):
            accounts.pop(idx)
            _save_custom_accounts(accounts)
            self._rebuild_custom_accounts_list()
            self._update_custom_totals()
            self._log("Dashboard: custom account removed")

    def _custom_account_dialog(self, edit_idx: Optional[int] = None,
                                defaults: Optional[Dict] = None) -> None:
        dlg = tk.Toplevel(self)
        dlg.title("Edit Account" if edit_idx is not None else "Add Custom Account")
        dlg.configure(bg=BG_CARD)
        dlg.geometry("340x220")
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        d = defaults or {}
        fields: Dict[str, tk.Entry] = {}
        for label_text, key, default in [
            ("Account Name", "name", d.get("name", "")),
            ("Amount Invested ($)", "invested", str(d.get("invested", ""))),
            ("Current Value ($)", "value", str(d.get("value", ""))),
        ]:
            tk.Label(dlg, text=label_text, bg=BG_CARD, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 9)).pack(anchor="w", padx=20, pady=(8, 2))
            entry = tk.Entry(dlg, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                             font=(FONT_FAMILY, 10), relief="flat", bd=0,
                             highlightthickness=1, highlightbackground=BORDER,
                             highlightcolor=ACCENT)
            entry.pack(fill="x", padx=20)
            entry.insert(0, str(default))
            fields[key] = entry

        def save():
            name = fields["name"].get().strip()
            if not name:
                return
            try:
                invested = float(fields["invested"].get().replace(",", "").replace("$", ""))
            except ValueError:
                invested = 0.0
            try:
                value = float(fields["value"].get().replace(",", "").replace("$", ""))
            except ValueError:
                value = 0.0

            accounts = _load_custom_accounts()
            entry = {"name": name, "invested": invested, "value": value}
            if edit_idx is not None and edit_idx < len(accounts):
                accounts[edit_idx] = entry
            else:
                accounts.append(entry)
            _save_custom_accounts(accounts)
            dlg.destroy()
            self._rebuild_custom_accounts_list()
            self._update_custom_totals()
            self._log(f"Dashboard: custom account {'updated' if edit_idx is not None else 'added'} — {name}")

        btn_frame = tk.Frame(dlg, bg=BG_CARD)
        btn_frame.pack(fill="x", padx=20, pady=(12, 8))
        PillButton(btn_frame, text="Save", command=save, width=90, height=30).pack(side="right")

    def _needs_plays_key(self) -> bool:
        """True when this copy can't read the feed and could be told how to.

        A paired device authenticates with its token and needs no password, so
        asking would be noise.
        """
        if not CLOUD_AVAILABLE:
            return False
        try:
            client = cloud_sync.CloudSync()
            return not client.device_token and not client.plays_key
        except Exception:
            return False

    def _maybe_prompt_plays_key(self) -> None:
        """Ask for the password on first launch, once.

        The whole subscription is one string, and until this existed the only
        way to enter it was to find .env in a file manager and edit it — which
        is why a new customer's Watchlist sat empty and looked broken. Asked
        once: a customer who dismisses it gets the picks-screen button instead
        of a dialog every hour.
        """
        if getattr(self, "_asked_plays_key", False) or not self._needs_plays_key():
            return
        self._asked_plays_key = True
        self._prompt_plays_key(first_run=True)

    def _prompt_plays_key(self, first_run: bool = False) -> None:
        """Modal: paste the plays password, verify it, save it, load the feed.

        Verified before it is saved, because a wrong password fails exactly
        like no password — an empty screen — and a customer who believes they
        have already entered it has no way left to tell the difference.
        """
        dlg = tk.Toplevel(self)
        dlg.title("Connect your plays feed")
        dlg.configure(bg=BG_CARD)
        dlg.geometry("460x290")
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        tk.Label(dlg, text=icon("starfill"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 22)).pack(pady=(20, 6))
        tk.Label(dlg,
                 text="Welcome to RSAMAXXED" if first_run else "Connect your plays feed",
                 bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 13, "bold")).pack()
        tk.Label(dlg,
                 text="Paste your plays password to start receiving alerts.\n"
                      "It's the same one that opens rsamaxxed.com/plays.",
                 bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 9),
                 justify="center").pack(pady=(4, 12))

        entry = tk.Entry(dlg, bg=BG_INPUT, fg=TEXT_PRIMARY, show="•",
                         insertbackground=TEXT_PRIMARY, font=(FONT_FAMILY, 11),
                         relief="flat", bd=0, highlightthickness=1,
                         highlightbackground=BORDER, highlightcolor=ACCENT,
                         justify="center")
        entry.pack(fill="x", padx=40, ipady=6)
        entry.focus_set()

        status = tk.Label(dlg, text="", bg=BG_CARD, fg=TEXT_MUTED,
                          font=(FONT_FAMILY, 9), wraplength=380, justify="center")
        status.pack(pady=(8, 0))

        btns = tk.Frame(dlg, bg=BG_CARD)
        btns.pack(fill="x", padx=40, pady=(14, 8))

        def _finish(key: str) -> None:
            cloud_sync.CloudSync().set_plays_key(key)
            global _PICKS_AUTH_ERROR
            _PICKS_AUTH_ERROR = None
            self._notified_no_plays_key = False
            dlg.destroy()
            self._push_notification("Plays feed connected — loading alerts.", "success")
            self._log("Feed: plays password accepted")
            self._run_in_thread(self._feed_pull_worker)

        def _verdict(good: bool, err: str, key: str) -> None:
            if good:
                _finish(key)
                return
            connect.configure(state="normal")
            connect.configure_text("Connect")
            status.configure(
                text=err or "That password was refused. Check it opens "
                            "rsamaxxed.com/plays in a browser — same spelling.",
                fg=RED)

        def _check() -> None:
            key = entry.get().strip()
            if not key:
                status.configure(text="Paste the password first.", fg=TEXT_MUTED)
                return
            connect.configure(state="disabled")
            connect.configure_text("Checking…")
            status.configure(text="Checking with the server…", fg=TEXT_MUTED)

            def work() -> None:
                try:
                    good, err = cloud_sync.CloudSync().check_plays_key(key), ""
                except Exception as exc:                       # noqa: BLE001
                    good, err = False, str(exc)
                self.after(0, lambda: _verdict(good, err, key))

            self._run_in_thread(work)

        def _later() -> None:
            dlg.destroy()
            if first_run:
                self._push_notification(
                    "No plays password yet — the Quick Picks tab has a button "
                    "to add it whenever you're ready.", "info")

        connect = PillButton(btns, text="Connect", command=_check, width=120, height=32)
        connect.pack(side="right")
        PillButton(btns, text="I'll do it later", command=_later, width=120,
                   height=32, bg_color=BG_INPUT, fg_color=TEXT_SECONDARY).pack(side="left")

        tk.Label(dlg, text="No account or sign-up needed.", bg=BG_CARD,
                 fg=TEXT_MUTED, font=(FONT_FAMILY, 8)).pack(pady=(0, 10))

        entry.bind("<Return>", lambda _e: _check())
        dlg.bind("<Escape>", lambda _e: _later())

    def _update_custom_totals(self) -> None:
        """Custom accounts are a separate manual tracker (shown in their own
        card); the hero is realized-P/L only. Nothing to fold into the hero."""
        return

    def _startup_refresh(self) -> None:
        """Auto-refresh all brokers on startup, reusing saved sessions."""
        self._log("Dashboard: restoring broker sessions...")
        self._apply_dashboard_summary()
        self._run_in_thread(self._startup_refresh_worker)

    def _startup_refresh_worker(self) -> None:
        load_dotenv(ENV_FILE, override=True)
        results: Dict[str, BrokerOutput] = {}
        lock = threading.Lock()

        # --- Non-browser brokers: run in parallel (fast) ---
        threads: List[threading.Thread] = []

        def fetch_api(broker: str) -> None:
            try:
                mod = _load_broker(broker)
                out = mod.get_holdings()
                with lock:
                    results[broker] = out
            except Exception as e:
                self.after(0, lambda b=broker, err=str(e): self._log(f"Startup refresh {b} failed: {err}"))

        for broker in BROKER_MODULES:
            if broker not in _BROWSER_BROKERS and _broker_has_creds(broker):
                t = threading.Thread(target=fetch_api, args=(broker,), daemon=True)
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        # Update UI with API broker results immediately
        def update_api() -> None:
            for broker, out in results.items():
                if broker == "public":
                    self._apply_public_status(out)
                    continue
                n = len(out.accounts)
                labels = self._broker_status_labels.get(broker)
                if labels and out.state == "success":
                    labels["dot"].set_color(GREEN)
                    labels["status"].configure(text=f"{n} account(s) connected", fg=GREEN)
            self._log("Dashboard: API brokers restored")
        self.after(0, update_api)

        # Browser brokers skip auto-refresh (require manual bootstrap/Refresh All)
        self.after(0, lambda: self._log("Dashboard: browser brokers skipped (use Bootstrap or Refresh All)"))

        # Account counts only — the hero value is valued separately from the
        # trade journal + Yahoo (see _valuate_portfolio_worker) so it shows even
        # when broker holdings haven't been fetched.
        def update_final() -> None:
            for broker, out in results.items():
                if out.state == "success":
                    self._update_total_accounts(broker, len(out.accounts))
            self._log("Dashboard: startup refresh complete")

        self.after(0, update_final)

    def _apply_public_status(self, out: Optional[Any]) -> None:
        """Update the per-login Public rows (P1/P2/P3) on the Command Center.

        Public runs one independent login per API secret token. get_holdings()
        (and bootstrap) return AccountOutputs whose account_id is prefixed
        ``Public N ...``, so we bucket each returned account back to the token
        slot (N) that produced it. A configured token that returns no accounts
        failed to connect — public.py silently drops tokens that don't auth."""
        by_idx: Dict[int, List[Any]] = {}
        for acc in (getattr(out, "accounts", None) or []):
            m = re.match(r"\s*Public\s+(\d+)", str(getattr(acc, "account_id", "")))
            if not m:
                continue
            by_idx.setdefault(int(m.group(1)), []).append(acc)

        for idx, labels in self._public_status_labels.items():
            accs = by_idx.get(idx)
            connected = [a for a in (accs or []) if getattr(a, "ok", False)]
            if connected:
                labels["dot"].set_color(GREEN)
                labels["status"].configure(text=f"{len(connected)} account(s) connected", fg=GREEN)
            elif accs:
                labels["dot"].set_color(RED)
                labels["status"].configure(text=(accs[0].message or "failed"), fg=RED)
            else:
                labels["dot"].set_color(RED)
                labels["status"].configure(text="not connected", fg=RED)

    def _portfolio_summary(self) -> Dict[str, Any]:
        """Trade-journal truth for reverse-split arbitrage. The ONLY real profit
        is a recorded buy matched with a confirmed sell at a higher price
        (realized P/L) — live prices can't tell you whether a name rounded up.
        Also returns the OPEN positions (bought, not yet sold) for allocation.
        Realized P/L matches the Analytics tab (all-time avg-buy basis).

        Reads the journal through split_adjusted(): a reverse split changes the
        share count with no trade to record, and without that lens a fractional
        sell is priced against a tenth of what was paid for it (see the rule in
        trade_journal). It also leaves the position permanently open, so the
        allocation donut below would keep drawing shares the split destroyed."""
        trades = trade_journal.split_adjusted()
        buys: Dict[str, Dict[str, float]] = {}   # symbol -> {qty, cost}
        sells: Dict[str, Dict[str, float]] = {}  # symbol -> {qty, rev}
        open_qty: Dict[tuple, float] = {}        # (broker, symbol) -> net held
        for t in trades:
            sym = t["symbol"]
            qty = float(t.get("qty", 0) or 0)
            price = t.get("fill_price")
            key = (t["broker"], sym)
            if t["side"] == "buy":
                b = buys.setdefault(sym, {"qty": 0.0, "cost": 0.0})
                b["qty"] += qty
                b["cost"] += (price or 0) * qty
                open_qty[key] = open_qty.get(key, 0.0) + qty
            elif t["side"] == "sell":
                s = sells.setdefault(sym, {"qty": 0.0, "rev": 0.0})
                s["qty"] += qty
                s["rev"] += (price or 0) * qty
                open_qty[key] = open_qty.get(key, 0.0) - qty
            elif t["side"] == trade_journal.SIDE_CLOSE:
                # Closes the position -- which is what stops DEPLOYED counting
                # shares a corporate action dissolved -- and touches neither
                # side of the profit arithmetic.
                open_qty[key] = open_qty.get(key, 0.0) - qty

        realized = 0.0
        wins = losses = 0
        for sym, s in sells.items():
            b = buys.get(sym)
            if not b or not b["qty"] or not s["qty"]:
                continue
            avg_b = b["cost"] / b["qty"]
            avg_s = s["rev"] / s["qty"]
            profit = (avg_s - avg_b) * s["qty"]
            realized += profit
            if profit > 0:
                wins += 1
            elif profit < 0:
                losses += 1
        closed = wins + losses

        sym_open: Dict[str, float] = {}
        for (_b, sym), q in open_qty.items():
            if q > 1e-9:
                sym_open[sym] = sym_open.get(sym, 0.0) + q
        open_positions = [{"symbol": s, "qty": q} for s, q in sym_open.items()]
        deployed = 0.0
        for sym, q in sym_open.items():
            b = buys.get(sym)
            if b and b["qty"]:
                deployed += (b["cost"] / b["qty"]) * q
        return {"realized": realized, "wins": wins, "losses": losses,
                "closed": closed, "open_positions": open_positions,
                "open_count": len(open_positions), "deployed": deployed}

    def _apply_dashboard_summary(self) -> None:
        """Update the Command Center hero from realized P/L + open positions
        (no live prices — accurate for RSA round-ups)."""
        try:
            s = self._portfolio_summary()
        except Exception as e:
            self._log(f"Dashboard summary failed: {e}")
            return
        realized = s["realized"]
        self._dash_value.configure(text=f"${realized:+,.2f}",
                                   fg=GREEN if realized >= 0 else RED)
        self._dash_invested.configure(text=f"${s['deployed']:,.2f}")
        self._dash_pl.configure(text=str(s["open_count"]), fg=TEXT_PRIMARY)
        if hasattr(self, "_dash_value_sub"):
            closed = s["closed"]
            if closed:
                wr = s["wins"] / closed * 100
                self._dash_value_sub.configure(
                    text=f"{closed} closed round-trip{'s' if closed != 1 else ''}"
                         f"  ·  {wr:.0f}% sold at a profit")
            else:
                self._dash_value_sub.configure(
                    text="Realized P/L shows after a confirmed buy → sell at a higher price")
        self._render_pipeline()

    def _dashboard_refresh(self) -> None:
        self._log("Dashboard: refreshing all brokers...")
        self._run_in_thread(self._dashboard_refresh_worker)

    def _dashboard_refresh_worker(self) -> None:
        load_dotenv(ENV_FILE, override=True)
        threads: List[threading.Thread] = []
        results: Dict[str, BrokerOutput] = {}
        lock = threading.Lock()

        def fetch(broker: str) -> None:
            slot = _browser_slot(broker)  # per-broker lock; different brokers run in parallel
            held_slot = None
            try:
                if slot is not None:
                    if not slot.acquire(timeout=_BROWSER_LOCK_TIMEOUT):
                        raise RuntimeError(_BROWSER_BUSY_MSG)
                    held_slot = slot
                mod = _load_broker(broker)
                out = mod.get_holdings()
                with lock:
                    results[broker] = out
            except Exception as e:
                self.after(0, lambda b=broker, err=e: self._log(f"  {b}: error - {err}"))
            finally:
                if held_slot is not None:
                    try:
                        held_slot.release()
                    except RuntimeError:
                        pass

        for broker in BROKER_MODULES:
            if _broker_has_creds(broker):
                t = threading.Thread(target=fetch, args=(broker,), daemon=True)
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        def update_ui() -> None:
            # Realized P/L hero is journal-based (accurate); refresh it too.
            self._apply_dashboard_summary()
            for broker in sorted(BROKER_MODULES):
                if broker == "public":
                    if "public" in results:
                        self._update_total_accounts("public", len(results["public"].accounts))
                    self._apply_public_status(results.get("public"))
                    continue
                labels = self._broker_status_labels.get(broker)
                if labels is None:
                    continue
                if broker in results:
                    out = results[broker]
                    n = len(out.accounts)
                    if out.state == "success":
                        self._update_total_accounts(broker, n)
                        labels["dot"].set_color(GREEN)
                        labels["status"].configure(text=f"{n} account(s) connected", fg=GREEN)
                    else:
                        labels["dot"].set_color(RED)
                        labels["status"].configure(text=out.message or "failed", fg=RED)
                elif _broker_has_creds(broker):
                    labels["dot"].set_color(GREEN)
                    labels["status"].configure(text="credentials set", fg=GREEN)
            self._log("Dashboard: refresh complete")

        self.after(0, update_ui)

    # ---- Holdings ---------------------------------------------------------

    def _build_holdings(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["holdings"] = frame

        top = tk.Frame(frame, bg=BG_PRIMARY)
        top.pack(fill="x", pady=(0, 12))
        self._holdings_status_lbl = tk.Label(top, text="", bg=BG_PRIMARY,
                                             fg=TEXT_MUTED, font=(FONT_FAMILY, 9))
        self._holdings_status_lbl.pack(side="left")

        outer, scroll = self._make_vscroll(frame)
        outer.pack(fill="both", expand=True)

        card = RoundedFrame(scroll, bg_color=BG_CARD, border_color=BORDER, radius=RAD_LG)
        card.pack(fill="x")
        head = tk.Frame(card.inner, bg=BG_CARD)
        head.pack(fill="x", padx=24, pady=(18, 2))
        tk.Label(head, text=icon("pie"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(0, 8))
        tk.Label(head, text="Open Positions — Allocation", bg=BG_CARD,
                 fg=TEXT_PRIMARY, font=(FONT_FAMILY, 13, "bold")).pack(side="left")
        tk.Label(head, text="Shares bought and not yet sold — round-up bets in play",
                 bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 8)).pack(
                     side="left", padx=(10, 0))

        body = tk.Frame(card.inner, bg=BG_CARD)
        body.pack(fill="x", padx=24, pady=(12, 24))
        self._alloc_canvas = tk.Canvas(body, bg=BG_CARD, width=300, height=300,
                                       highlightthickness=0, bd=0)
        self._alloc_canvas.pack(side="left", padx=(0, 28), anchor="n")
        self._alloc_legend = tk.Frame(body, bg=BG_CARD)
        self._alloc_legend.pack(side="left", fill="x", expand=True, anchor="n")
        self._alloc_positions: list = []
        self._alloc_canvas.bind("<Configure>", lambda e: self._draw_allocation_pie())

    def _holdings_refresh(self, *args, **kwargs) -> None:
        """Positions is an allocation view now — recomputed locally from the
        trade journal (confirmed buys, net of sells). No broker login / prices."""
        self._render_allocation()

    def _recompute_allocation(self) -> None:
        """The header button: always rebuild, even if the fingerprint matches."""
        self._invalidate_page("holdings")
        self._render_allocation()

    def _render_allocation(self) -> None:
        if not hasattr(self, "_alloc_legend"):
            return
        positions = sorted(self._portfolio_summary()["open_positions"],
                           key=lambda p: p["qty"], reverse=True)
        self._alloc_positions = positions
        self._draw_allocation_pie()
        for w in self._alloc_legend.winfo_children():
            w.destroy()
        total = sum(p["qty"] for p in positions)
        if not positions:
            self._empty_state(
                self._alloc_legend, "pie", "No open positions",
                "Confirmed buys appear here until you sell them.",
                bg=BG_CARD, pad=18).pack(fill="x")
        else:
            tk.Label(self._alloc_legend,
                     text=f"{len(positions)} open position"
                          f"{'s' if len(positions) != 1 else ''}  ·  "
                          f"{int(total)} shares in play",
                     bg=BG_CARD, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 9, "bold")).pack(anchor="w", pady=(2, 10))
            for i, p in enumerate(positions):
                col = CHART_PALETTE[i % len(CHART_PALETTE)]
                r = tk.Frame(self._alloc_legend, bg=BG_CARD)
                r.pack(fill="x", pady=2)
                tk.Frame(r, bg=col, width=11, height=11).pack(side="left",
                                                              padx=(0, 9), pady=2)
                tk.Label(r, text=p["symbol"], bg=BG_CARD, fg=TEXT_PRIMARY,
                         font=(FONT_FAMILY, 9, "bold"), width=8, anchor="w").pack(side="left")
                tk.Label(r, text=f"{p['qty']:.0f} sh", bg=BG_CARD, fg=TEXT_SECONDARY,
                         font=(FONT_MONO, 9)).pack(side="left")
                if p["symbol"] in self._roundup_flagged:
                    tk.Label(r, text=f" {icon('lightning')} SPLIT? ",
                             bg=_blend(YELLOW, BG_CARD, 0.84), fg=YELLOW,
                             font=(FONT_FAMILY, 7, "bold")).pack(side="left",
                                                                 padx=(8, 0))
                sell = tk.Label(r, text="Sell 1 ea →",
                                bg=_blend(RED, BG_CARD, 0.86), fg=RED,
                                font=(FONT_FAMILY, 8, "bold"), padx=9, pady=2,
                                cursor="hand2")
                sell.pack(side="right", padx=(0, 6))
                sell.bind("<Button-1>",
                          lambda e, s=p["symbol"]: self._prefill_trade(s, "sell", "1"))
                pct = (p["qty"] / total * 100) if total else 0
                tk.Label(r, text=f"{pct:.1f}%", bg=BG_CARD, fg=TEXT_MUTED,
                         font=(FONT_MONO, 9)).pack(side="right", padx=(0, 14))
        self._holdings_status_lbl.configure(
            text=f"Updated {datetime.now():%H:%M:%S}", fg=TEXT_MUTED)

    def _draw_allocation_pie(self) -> None:
        c = getattr(self, "_alloc_canvas", None)
        if c is None:
            return
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 320
        h = c.winfo_height() or 320
        positions = getattr(self, "_alloc_positions", [])
        total = sum(p["qty"] for p in positions)
        cx, cy = w / 2, h / 2
        r = min(w, h) / 2 - 14
        inner = r * 0.60
        if total <= 0 or r <= 10:
            c.create_text(cx, cy, text="No open positions", fill=TEXT_MUTED,
                          font=(FONT_FAMILY, 10))
            return
        if len(positions) == 1:
            c.create_oval(cx - r, cy - r, cx + r, cy + r,
                          fill=CHART_PALETTE[0], outline=BG_CARD, width=2)
        else:
            start = 90.0
            for i, p in enumerate(positions):
                ext = -(p["qty"] / total) * 360.0
                col = CHART_PALETTE[i % len(CHART_PALETTE)]
                c.create_arc(cx - r, cy - r, cx + r, cy + r, start=start, extent=ext,
                             fill=col, outline=BG_CARD, width=2, style="pieslice")
                start += ext
        c.create_oval(cx - inner, cy - inner, cx + inner, cy + inner,
                      fill=BG_CARD, outline="")
        c.create_text(cx, cy - 10, text=str(len(positions)), fill=TEXT_PRIMARY,
                      font=(FONT_MONO, 22, "bold"))
        c.create_text(cx, cy + 14, text="OPEN POSITIONS", fill=TEXT_MUTED,
                      font=(FONT_FAMILY, 7, "bold"))


    # ---- Trade ------------------------------------------------------------

    def _style_chip(self, btn, selected: bool) -> None:
        btn.configure(
            fg_color=ACCENT if selected else BG_INPUT,
            hover_color=ACCENT_HOVER if selected else BG_CARD_ALT,
            text_color=TEXT_PRIMARY if selected else TEXT_SECONDARY,
            border_color=ACCENT if selected else BORDER)

    def _make_chip(self, parent, text: str, command, selected: bool = False):
        w = max(60, len(text) * 8 + 28)
        return ctk.CTkButton(
            parent, text=text, command=command, width=w, height=29, corner_radius=15,
            fg_color=ACCENT if selected else BG_INPUT,
            hover_color=ACCENT_HOVER if selected else BG_CARD_ALT,
            text_color=TEXT_PRIMARY if selected else TEXT_SECONDARY,
            bg_color=_widget_bg(parent) or BG_CARD,
            border_width=1, border_color=ACCENT if selected else BORDER,
            font=ctk.CTkFont(family=FONT_FAMILY, size=10, weight="bold"))

    def _build_trade(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["trade"] = frame

        # form card — proper "order ticket" framing
        form_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14,
                                 height=320)
        form_card.pack(fill="x", pady=(0, 16))

        tick_head = tk.Frame(form_card.inner, bg=BG_CARD)
        tick_head.pack(fill="x", padx=24, pady=(18, 0))
        tk.Label(tick_head, text=icon("trade"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(0, 8))
        tk.Label(tick_head, text="Order Ticket", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 13, "bold")).pack(side="left")
        tk.Label(tick_head, text="EXECUTES ON EVERY SELECTED BROKER IN PARALLEL",
                 bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 7, "bold")).pack(side="right")
        tk.Frame(form_card.inner, bg=BORDER, height=1).pack(fill="x", padx=24,
                                                            pady=(12, 0))

        form = tk.Frame(form_card.inner, bg=BG_CARD)
        form.pack(fill="x", padx=24, pady=20)

        row = 0

        def add_label(text, r):
            tk.Label(form, text=text, bg=BG_CARD, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 9, "bold")).grid(row=r, column=0, sticky="nw",
                                                         pady=(0, 12), padx=(0, 16))

        # broker multi-select chips
        add_label("BROKERS", row)
        broker_frame = tk.Frame(form, bg=BG_CARD)
        broker_frame.grid(row=row, column=1, sticky="w", pady=(0, 12))

        self._trade_broker_chips: Dict[str, Dict[str, Any]] = {}
        self._trade_selected_brokers: set = set()

        # "Select All" chip
        select_all_chip = self._make_chip(broker_frame, "Select All", None)
        select_all_chip.pack(side="left", padx=(0, 10), pady=2)

        chips_wrap = tk.Frame(broker_frame, bg=BG_CARD)
        chips_wrap.pack(side="left")

        # only show brokers that have credentials
        linked_brokers = sorted([b for b in BROKER_MODULES if _broker_has_creds(b)])

        chip_row_frame = tk.Frame(chips_wrap, bg=BG_CARD)
        chip_row_frame.pack(anchor="w")
        chips_per_row = 5

        for idx, broker in enumerate(linked_brokers):
            if idx > 0 and idx % chips_per_row == 0:
                chip_row_frame = tk.Frame(chips_wrap, bg=BG_CARD)
                chip_row_frame.pack(anchor="w", pady=(6, 0))
            chip = self._make_chip(chip_row_frame, broker.capitalize(),
                                   lambda b=broker: self._toggle_broker_chip(b))
            chip.pack(side="left", padx=(0, 6), pady=2)
            self._trade_broker_chips[broker] = {"label": chip, "selected": False}

        def toggle_all():
            all_selected = len(self._trade_selected_brokers) == len(linked_brokers)
            for b in linked_brokers:
                sel = not all_selected
                self._trade_broker_chips[b]["selected"] = sel
                self._style_chip(self._trade_broker_chips[b]["label"], sel)
                if sel:
                    self._trade_selected_brokers.add(b)
                else:
                    self._trade_selected_brokers.discard(b)
            self._style_chip(select_all_chip, not all_selected)
            self._update_trade_estimate()

        select_all_chip.configure(command=toggle_all)
        self._select_all_chip = select_all_chip
        self._linked_brokers = linked_brokers

        # side — segmented BUY / SELL
        row += 1
        add_label("SIDE", row)
        side_wrap = ctk.CTkFrame(form, fg_color=BG_INPUT, bg_color=BG_CARD,
                                 corner_radius=9)
        side_wrap.grid(row=row, column=1, sticky="w", pady=(0, 12))
        self._trade_side = tk.StringVar(value="buy")

        _seg_font = ctk.CTkFont(family=FONT_FAMILY, size=10, weight="bold")
        buy_btn = ctk.CTkButton(side_wrap, text="BUY", width=82, height=30,
                                corner_radius=7, fg_color=GREEN, hover_color=GREEN,
                                text_color=BG_PRIMARY, font=_seg_font)
        buy_btn.pack(side="left", padx=3, pady=3)
        sell_btn = ctk.CTkButton(side_wrap, text="SELL", width=82, height=30,
                                 corner_radius=7, fg_color="transparent",
                                 hover_color=BG_CARD_ALT, text_color=RED, font=_seg_font)
        sell_btn.pack(side="left", padx=(0, 3), pady=3)
        self._buy_btn = buy_btn
        self._sell_btn = sell_btn

        def set_side(s):
            self._trade_side.set(s)
            if s == "buy":
                self._buy_btn.configure(fg_color=GREEN, hover_color=GREEN, text_color=BG_PRIMARY)
                self._sell_btn.configure(fg_color="transparent", hover_color=BG_CARD_ALT, text_color=RED)
            else:
                self._sell_btn.configure(fg_color=RED, hover_color=RED, text_color=BG_PRIMARY)
                self._buy_btn.configure(fg_color="transparent", hover_color=BG_CARD_ALT, text_color=GREEN)
            self._update_trade_estimate()

        self._set_trade_side = set_side
        buy_btn.configure(command=lambda: set_side("buy"))
        sell_btn.configure(command=lambda: set_side("sell"))

        # symbol
        row += 1
        add_label("SYMBOL", row)
        self._trade_symbol = ttk.Entry(form, width=14, font=(FONT_MONO, 11))
        self._trade_symbol.grid(row=row, column=1, sticky="w", pady=(0, 12))

        # qty
        row += 1
        add_label("QUANTITY", row)
        self._trade_qty = ttk.Entry(form, width=14, font=(FONT_MONO, 11))
        self._trade_qty.grid(row=row, column=1, sticky="w", pady=(0, 12))

        # live order estimate — accounts × shares × quote
        row += 1
        self._trade_estimate = tk.Label(form, text="", bg=BG_CARD, fg=TEXT_MUTED,
                                        font=(FONT_MONO, 9))
        self._trade_estimate.grid(row=row, column=1, sticky="w", pady=(0, 10))
        self._trade_symbol.bind("<KeyRelease>", self._update_trade_estimate)
        self._trade_qty.bind("<KeyRelease>", self._update_trade_estimate)

        # dry run + execute
        row += 1
        action_frame = tk.Frame(form, bg=BG_CARD)
        action_frame.grid(row=row, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self._trade_dry = tk.BooleanVar(value=False)
        dry_cb = tk.Checkbutton(action_frame, text="Dry Run", variable=self._trade_dry,
                                bg=BG_CARD, fg=TEXT_SECONDARY, selectcolor=BG_INPUT,
                                activebackground=BG_CARD, activeforeground=TEXT_PRIMARY,
                                font=(FONT_FAMILY, 9))
        dry_cb.pack(side="left", padx=(0, 16))

        self._trade_execute_btn = PillButton(
            action_frame, text="Execute Trade", command=self._trade_execute,
            width=140, height=36, font_size=10)
        self._trade_execute_btn.pack(side="left")

        # result area
        result_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        result_card.pack(fill="both", expand=True)

        out_head = tk.Frame(result_card.inner, bg=BG_CARD)
        out_head.pack(fill="x", padx=16, pady=(14, 4))
        tk.Label(out_head, text=icon("activity"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 11)).pack(side="left", padx=(0, 8))
        tk.Label(out_head, text="Execution Output", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(side="left")
        tk.Label(out_head, text="LIVE PER-ACCOUNT FILLS & FAILURES", bg=BG_CARD,
                 fg=TEXT_MUTED, font=(FONT_FAMILY, 7, "bold")).pack(side="right")

        self._trade_result = tk.Text(result_card.inner, bg=BG_CARD, fg=TEXT_PRIMARY,
                                     font=(FONT_MONO, 10), bd=0, wrap="word",
                                     state="disabled", insertbackground=TEXT_PRIMARY,
                                     highlightthickness=0)
        self._trade_result.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self._trade_result.tag_configure("success", foreground=GREEN)
        self._trade_result.tag_configure("error", foreground=RED)
        self._trade_result.tag_configure("warn", foreground=YELLOW)
        self._trade_result.tag_configure(
            "banner_ok", foreground=GREEN, font=(FONT_MONO, 13, "bold"))
        self._trade_result.tag_configure(
            "banner_err", foreground=RED, font=(FONT_MONO, 13, "bold"))

    def _toggle_broker_chip(self, broker: str) -> None:
        chip = self._trade_broker_chips[broker]
        chip["selected"] = not chip["selected"]
        self._style_chip(chip["label"], chip["selected"])
        if chip["selected"]:
            self._trade_selected_brokers.add(broker)
        else:
            self._trade_selected_brokers.discard(broker)
        self._style_chip(self._select_all_chip,
                         len(self._trade_selected_brokers) == len(self._linked_brokers))
        self._update_trade_estimate()

    def _update_trade_estimate(self, *_args) -> None:
        """Live footprint of the order being built: accounts × shares × quote."""
        if not hasattr(self, "_trade_estimate"):
            return
        try:
            sym = self._trade_symbol.get().strip().upper()
            qty = float(self._trade_qty.get().strip() or 0)
        except (ValueError, tk.TclError):
            sym, qty = "", 0
        sel = getattr(self, "_trade_selected_brokers", set())
        counts = getattr(self, "_broker_account_counts", {})
        n_accts = sum(counts.get(b, 1) for b in sel)
        if not sym or qty <= 0 or not sel:
            self._trade_estimate.configure(text="")
            return
        q = self._quotes.get(sym)
        verb = "deployed" if self._trade_side.get() == "buy" else "recovered"
        plural = "s" if n_accts != 1 else ""
        if q:
            total = q["price"] * qty * n_accts
            self._trade_estimate.configure(
                text=f"{n_accts} account{plural} × {qty:g} sh × "
                     f"${q['price']:,.2f}  ≈  ${total:,.2f} {verb}")
        else:
            self._trade_estimate.configure(
                text=f"{n_accts} account{plural} × {qty:g} sh — no public quote")

    def _trade_execute(self) -> None:
        # --- Double-submit guard -------------------------------------------
        # Every click used to fire a brand-new order batch, so an impatient
        # second click = a duplicate BUY/SELL (this is what double-sold AIFA on
        # Robinhood). Refuse a new batch while one is still running.
        if getattr(self, "_trade_in_flight", False):
            self._push_notification(
                "A trade is already running — wait for it to finish.", "warning")
            self._log("Trade: ignored — a batch is already in flight", "warn")
            return

        selected = list(self._trade_selected_brokers)
        side = self._trade_side.get()
        symbol = self._trade_symbol.get().strip().upper()
        qty_str = self._trade_qty.get().strip()
        dry_run = self._trade_dry.get()

        if not selected:
            messagebox.showwarning("No broker", "Select at least one broker.")
            return
        if not symbol:
            messagebox.showwarning("Missing field", "Enter a symbol.")
            return
        if not qty_str:
            messagebox.showwarning("Missing field", "Enter a quantity.")
            return
        try:
            qty_val = float(qty_str)
            if qty_val <= 0:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Invalid quantity", "Quantity must be a positive number.")
            return
        if qty_val > 5 and not dry_run:
            if not messagebox.askyesno(
                    "Large quantity",
                    f"{qty_str} shares per account is unusually large for a "
                    f"reverse-split round-up play (standard is 1).\n\nExecute anyway?",
                    parent=self):
                return

        brokers_str = ", ".join(sorted(selected))
        label = f"{side.upper()} {qty_str} {symbol} on [{brokers_str}]" + (" [DRY RUN]" if dry_run else "")
        self._log(f"Trade: {label}")
        self._trade_result_write(f"Executing: {label}\n")

        # Batch tracker: each broker thread reports back here when it finishes.
        # When the last one reports, we print the big DONE banner. All callbacks
        # are marshalled onto the Tk main thread, so this needs no lock.
        batch = {
            "pending": set(sorted(selected)),
            "all_brokers": sorted(selected),
            "results": [],
            "side": side,
            "symbol": symbol,
            "qty": qty_str,
            "dry_run": dry_run,
            "origin": "desk",
            "finished": False,
            "started": datetime.now(),
        }
        self._trade_batch = batch

        # Lock the button + flag so a second click can't fire a duplicate order.
        self._trade_in_flight = True
        if hasattr(self, "_trade_execute_btn"):
            self._trade_execute_btn.configure(state="disabled")
            self._trade_execute_btn.configure_text("Executing…")

        # Live "operation in progress" strip on the Activity page.
        self._live_start(batch)

        # launch one thread per broker in parallel
        for broker in sorted(selected):
            self._run_in_thread(self._trade_worker, broker, side, symbol, qty_str, dry_run, batch)

    def _trade_result_write(self, text: str, tag: Optional[str] = None) -> None:
        self._trade_result.configure(state="normal")
        start = self._trade_result.index("end-1c")
        self._trade_result.insert("end", text)
        if tag:
            self._trade_result.tag_add(tag, start, "end-1c")
        self._trade_result.see("end")
        self._trade_result.configure(state="disabled")

    @staticmethod
    def _fetch_market_price(symbol: str) -> Optional[float]:
        """Fetch current market price from Yahoo Finance as a fallback."""
        try:
            url = f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?range=1d&interval=1d"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            price = data["chart"]["result"][0]["meta"]["regularMarketPrice"]
            return round(float(price), 4)
        except Exception:
            return None

    def _fetch_quote_price(self, broker: str, symbol: str, side: str = "buy") -> Optional[float]:
        """The market price around the time of a trade. NOT a fill.

        Renamed from `_fetch_fill_price`, which is what it was called for as
        long as it has existed and is the reason nobody noticed: it reads
        `h.price` out of get_holdings() — the CURRENT market price — and falls
        back to Yahoo when the position has already gone. Neither is an
        execution, and on a thin post-split name the two can be far apart.

        Its answer is looked up once per batch and stamped onto every account,
        so it cannot represent a per-order fill even in principle. Rows written
        from it are marked PRICE_QUOTE; see trade_journal.is_estimated.
        """
        try:
            mod = _load_broker(broker)
            output = mod.get_holdings()
            for acct in output.accounts:
                for h in acct.holdings:
                    if h.symbol and h.symbol.upper() == symbol.upper() and h.price is not None:
                        return h.price
        except Exception:
            pass
        # Fallback: fetch market price (especially useful after sells when
        # the position no longer appears in holdings)
        return self._fetch_market_price(symbol)

    def _trade_worker(self, broker: str, side: str, symbol: str, qty: str,
                      dry_run: bool, batch: Optional[dict] = None,
                      only_accounts: Optional[List[str]] = None) -> None:
        slot = _browser_slot(broker)  # per-broker Chrome lock (None = API broker)
        held_slot: Optional[threading.Lock] = None
        # Per-broker outcome reported back to the batch tracker (defaults to a
        # total failure; overwritten on the happy path below).
        # `accounts` is carried for the Mirror journal: the on-screen result box
        # is thrown away on the next trade, so the per-account verdict has to
        # travel with the summary or it is gone.
        summary = {"broker": broker, "ok_accounts": 0, "fail_accounts": 0,
                   "shares": 0.0, "errors": [], "state": "error",
                   "accounts": [], "fill_price": None}
        try:
            if slot is not None:
                self.after(0, lambda b=broker, busy=slot.locked(): self._log(
                    f"  {b}: waiting for browser..." if busy else f"  {b}: starting trade..."))
                if not slot.acquire(timeout=_BROWSER_LOCK_TIMEOUT):
                    raise RuntimeError(_BROWSER_BUSY_MSG)
                held_slot = slot

            load_dotenv(ENV_FILE, override=True)
            mod = _load_broker(broker)

            # Live progress: tail the broker's nav log for real-time updates
            done = threading.Event()
            log_file = Path("sessions") / broker / f"{broker}_nav.log"
            last_size = [log_file.stat().st_size if log_file.exists() else 0]

            t_start = datetime.now()
            last_beat = [datetime.now()]

            def progress_ticker():
                while not done.is_set():
                    done.wait(3)
                    if done.is_set():
                        break
                    saw_new = False
                    try:
                        if log_file.exists():
                            cur_size = log_file.stat().st_size
                            if cur_size > last_size[0]:
                                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                                    f.seek(last_size[0])
                                    new_lines = f.read().strip().splitlines()
                                last_size[0] = cur_size
                                for line in new_lines:
                                    # Strip timestamp prefix, show the action
                                    parts = line.split("] ", 1)
                                    msg = parts[1] if len(parts) > 1 else line
                                    self.after(0, lambda b=broker, m=msg: self._log(f"  {b}: {m}", "meta"))
                                saw_new = True
                                last_beat[0] = datetime.now()
                    except Exception:
                        pass
                    # Heartbeat: even brokers with no nav log (API brokers) must
                    # never go silent for minutes — emit "still working" every 12s.
                    if not saw_new and (datetime.now() - last_beat[0]).total_seconds() >= 12:
                        secs = int((datetime.now() - t_start).total_seconds())
                        act = "still selling" if side == "sell" else "still purchasing"
                        self.after(0, lambda b=broker, s=secs, a=act: self._log(
                            f"  {b}: {a}… ({s}s elapsed)", "meta"))
                        last_beat[0] = datetime.now()

            ticker = threading.Thread(target=progress_ticker, daemon=True)
            ticker.start()

            # For sells, pre-fetch price while position still exists in holdings
            # (after selling, position may be gone and Yahoo may fail for OTC stocks)
            pre_trade_price = None
            if side == "sell" and not dry_run:
                pre_trade_price = self._fetch_quote_price(broker, symbol, "buy")

            try:
                kw = {"side": side, "qty": qty, "symbol": symbol, "dry_run": dry_run}
                if only_accounts:
                    # Not every broker module can narrow to a subset of its
                    # accounts. Ask, and if the module doesn't take the kwarg,
                    # say so instead of quietly re-buying the whole broker.
                    try:
                        output: BrokerOutput = mod.execute_trade(
                            **kw, only_accounts=list(only_accounts))
                    except TypeError as te:
                        if "only_accounts" not in str(te):
                            raise
                        raise RuntimeError(
                            f"{broker} cannot trade specific accounts — "
                            f"retry it from the Trade Desk instead") from None
                else:
                    output = mod.execute_trade(**kw)
            finally:
                done.set()
                ticker.join(timeout=2)

            log_event(broker=broker, action="trade", output=output)

            lines = [f"[{broker.capitalize()}] State: {output.state}"]
            if output.message:
                lines.append(f"  Message: {output.message}")

            # fetch fill price after successful trade
            fill_price = None
            has_success = any(a.ok for a in output.accounts)
            if has_success and not dry_run:
                self.after(0, lambda b=broker: self._log(f"  {b}: fetching fill price..."))
                fill_price = self._fetch_quote_price(broker, symbol, side)
                if fill_price is None and pre_trade_price is not None:
                    fill_price = pre_trade_price

            ok_accounts = 0
            fail_accounts = 0
            for acct in output.accounts:
                status = "OK" if acct.ok else "FAIL"
                lines.append(f"  [{status}] {acct.account_id}: {acct.message}")
                summary["accounts"].append({
                    "account_id": acct.account_id,
                    "ok": bool(acct.ok),
                    "message": acct.message or "",
                })
                if acct.ok:
                    ok_accounts += 1
                else:
                    fail_accounts += 1
                    summary["errors"].append(f"{acct.account_id}: {acct.message}")
                if acct.ok and not dry_run:
                    # order_id is the broker's own handle on this order, and it
                    # is the only thing that makes the real fill recoverable
                    # later. It was being returned by the API, carried this far,
                    # and then thrown away.
                    #
                    # price_source says what fill_price IS. It is one quote,
                    # looked up once for the whole batch and stamped onto every
                    # account -- not an execution. Recording that honestly is
                    # what stops nine orders spread over seven minutes reading
                    # as nine fills at an identical price.
                    trade_journal.record_trade(
                        broker=broker, account_id=acct.account_id,
                        side=side, symbol=symbol, qty=float(qty),
                        fill_price=fill_price,
                        order_id=getattr(acct, "order_id", None),
                        price_source=trade_journal.PRICE_QUOTE,
                    )

            if fill_price is not None:
                lines.append(f"  Quoted price: ${fill_price:.2f}")

            # Persist the full per-account result (fills AND failures with their
            # reason) so "which accounts didn't buy, and why" is always
            # recoverable later — the on-screen result box isn't saved.
            try:
                stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                header = (f"[{stamp}] {side.upper()} {qty} {symbol} on {broker} "
                          f"-> {output.state} ({ok_accounts} ok, {fail_accounts} fail)"
                          + (" [DRY RUN]" if dry_run else ""))
                LOG_DIR.mkdir(parents=True, exist_ok=True)
                with open(LOG_DIR / "trade_results.log", "a", encoding="utf-8") as _fh:
                    _fh.write(header + "\n")
                    for acct in output.accounts:
                        _fh.write(f"  [{'OK' if acct.ok else 'FAIL'}] "
                                  f"{acct.account_id}: {acct.message}\n")
                    _fh.write("\n")
            except Exception:
                pass

            # Record this broker's outcome for the batch DONE banner.
            summary["ok_accounts"] = ok_accounts
            summary["fail_accounts"] = fail_accounts
            summary["shares"] = float(qty) * ok_accounts if ok_accounts else 0.0
            summary["state"] = output.state
            summary["fill_price"] = fill_price

            # Color the per-broker output block: red if anything failed, else green.
            block_tag = "error" if fail_accounts else ("success" if ok_accounts else None)
            result_text = "\n".join(lines) + "\n\n"
            self.after(0, lambda t=result_text, tg=block_tag: self._trade_result_write(t, tg))
            # Log state + reason so failures are visible in the log panel
            fail_reasons = [a.message for a in output.accounts if not a.ok]
            if output.state != "success" and fail_reasons:
                short_reason = fail_reasons[0][:80]
                self.after(0, lambda b=broker, s=output.state, r=short_reason: self._log(f"Trade: {b} -> {s}: {r}", "error"))
            else:
                self.after(0, lambda b=broker, s=output.state, n=ok_accounts: self._log(f"Trade: {b} -> {s} ({n} account{'s' if n != 1 else ''})", "success"))

            # Refresh Quick Picks to move purchased picks to the Purchased section
            if any(acct.ok for acct in output.accounts) and not dry_run:
                self.after(0, lambda: self._render_quick_picks(self._quick_picks))
        except Exception as e:
            summary["errors"].append(str(e))
            if summary["fail_accounts"] == 0:
                summary["fail_accounts"] = 1
            self.after(0, lambda b=broker, err=e: self._trade_result_write(f"[{b.capitalize()}] Error: {err}\n\n", "error"))
            self.after(0, lambda b=broker, err=e: self._log(f"Trade error ({b}): {err}", "error"))
        finally:
            if held_slot is not None:
                try:
                    held_slot.release()
                except RuntimeError:
                    pass
            # Report this broker back to the batch; last one in prints the banner.
            if batch is not None:
                self.after(0, self._trade_broker_complete, batch, summary)

    def _trade_broker_complete(self, batch: dict, summary: dict) -> None:
        """Runs on the Tk main thread as each broker finishes. When the last
        broker reports in, renders the completion receipt with totals."""
        if batch.get("finished"):
            return
        batch["results"].append(summary)
        batch["pending"].discard(summary["broker"])
        # Persist the leg as it lands, not at the end: a crash or a force-quit
        # mid-fan-out then still leaves the brokers that did report on disk.
        if batch.get("mirror_run"):
            try:
                mirror_journal.record_leg(batch["mirror_run"], summary)
            except Exception:
                pass
        # Live feed: announce each broker as it lands so there's no dead air.
        r = summary
        if r["ok_accounts"] > 0 and not r["fail_accounts"]:
            self._log(f"✔  {r['broker'].capitalize()} filled "
                      f"{r['ok_accounts']} account{'s' if r['ok_accounts'] != 1 else ''}", "ok")
        elif r["ok_accounts"] > 0:
            self._log(f"⚠  {r['broker'].capitalize()}: "
                      f"{r['ok_accounts']} ok, {r['fail_accounts']} failed", "warn")
        else:
            detail = r["errors"][0][:70] if r["errors"] else "failed"
            self._log(f"✘  {r['broker'].capitalize()}: {detail}", "fail")
        if not batch["pending"]:
            batch["finished"] = True
            self._trade_batch_finish(batch)

    def _trade_batch_finish(self, batch: dict) -> None:
        """Finalize a batch: hide the live strip, show the completion receipt
        card, drop a concise summary into the feed, and release the guard."""
        results = batch["results"]
        side = batch["side"]
        symbol = batch["symbol"]
        dry = batch["dry_run"]
        verb = "Bought" if side == "buy" else "Sold"

        total_ok = sum(r["ok_accounts"] for r in results)
        total_fail = sum(r["fail_accounts"] for r in results)
        total_shares = sum(r["shares"] for r in results)

        if batch.get("origin") == "mirror" and batch.get("mirror_key") and not dry:
            self._mirror_record_outcome(batch["mirror_key"], symbol,
                                        total_ok, total_fail)
        ok_brokers = [r["broker"] for r in results if r["ok_accounts"] > 0]
        failed = [r for r in results if r["fail_accounts"] > 0 or r["errors"]]

        shares_str = (f"{total_shares:g}")
        dry_tag = " · DRY RUN" if dry else ""
        elapsed = 0.0
        try:
            elapsed = (datetime.now() - batch["started"]).total_seconds()
        except Exception:
            pass

        if batch.get("mirror_run"):
            try:
                mirror_journal.finish_run(
                    batch["mirror_run"], ok_accounts=total_ok,
                    fail_accounts=total_fail, shares=total_shares,
                    elapsed=elapsed)
            except Exception:
                pass
            self._invalidate_page("mirror")
            if self._active_nav == "mirror":
                self.after(80, self._render_mirror)

        if total_ok > 0 and not failed:
            kind = "ok"
        elif total_ok > 0:
            kind = "warn"
        else:
            kind = "fail"

        # --- Notification center summary ---
        if kind == "ok":
            self._push_notification(
                f"{verb} {shares_str} {symbol} across {total_ok} "
                f"account{'s' if total_ok != 1 else ''}{dry_tag}", "success")
        elif kind == "warn":
            self._push_notification(
                f"{verb} {symbol}: {total_ok} ok, {total_fail} failed", "warning")
        else:
            self._push_notification(
                f"{verb} {symbol} failed on {total_fail} "
                f"account{'s' if total_fail != 1 else ''}", "error")

        # --- Live strip: this batch is done ---
        self._live_batches = [b for b in getattr(self, "_live_batches", []) if b is not batch]

        # --- Rich completion receipt card (the "ending screen") ---
        self._render_done_receipt(
            kind=kind, verb=verb, shares=shares_str, symbol=symbol,
            total_ok=total_ok, total_fail=total_fail, ok_brokers=ok_brokers,
            results=results, dry=dry, elapsed=elapsed, batch=batch)

        # --- Concise, styled feed summary (no ASCII bars) ---
        if kind == "ok":
            head = (f"✔  {verb} {shares_str} {symbol} — "
                    f"{total_ok} account{'s' if total_ok != 1 else ''} across "
                    f"{len(ok_brokers)} broker{'s' if len(ok_brokers) != 1 else ''}"
                    f" · {elapsed:.1f}s{dry_tag}")
            head_tag = "done_ok"
        elif kind == "warn":
            head = (f"⚠  {verb} {symbol} with errors — "
                    f"{total_ok} ok, {total_fail} failed · {elapsed:.1f}s{dry_tag}")
            head_tag = "done_warn"
        else:
            head = (f"✘  Nothing {verb.lower()} — "
                    f"{total_fail} account{'s' if total_fail != 1 else ''} failed"
                    f" · {elapsed:.1f}s{dry_tag}")
            head_tag = "done_err"
        self._log(head, head_tag)

        # Mirror the newly journaled fills to the web dashboard. Fire-and-forget:
        # a cloud outage can never affect an order that already executed.
        if total_ok > 0 and not dry:
            self._cloud_push_async()

        if not self._live_batches:
            self._live_hide()

        # --- Trade Desk output panel (kept; cleaner separator, no === bars) ---
        rule = "─" * 46
        banner_tag = "banner_ok" if kind == "ok" else "banner_err"
        self._trade_result_write(f"{rule}\n{head.strip()}\n", banner_tag)
        for r in sorted(results, key=lambda x: x["broker"]):
            if r["ok_accounts"] > 0 and not r["fail_accounts"]:
                self._trade_result_write(
                    f"  ✔ {r['broker'].capitalize()}: {r['ok_accounts']} account(s)\n", "success")
            elif r["ok_accounts"] > 0:
                self._trade_result_write(
                    f"  ⚠ {r['broker'].capitalize()}: {r['ok_accounts']} ok, {r['fail_accounts']} failed\n", "warn")
            else:
                detail = r["errors"][0][:80] if r["errors"] else "failed"
                self._trade_result_write(
                    f"  ✘ {r['broker'].capitalize()}: {detail}\n", "error")
        self._trade_result_write("\n")

        # --- Release the double-submit guard ---
        # Every origin that SET the flag must clear it. An exit batch takes the
        # same guard as a desk order, so missing it here would leave the app
        # unable to trade at all until restart.
        if batch.get("origin") in ("desk", "exit"):
            self._trade_in_flight = False
            if hasattr(self, "_trade_execute_btn"):
                self._trade_execute_btn.configure(state="normal")
                self._trade_execute_btn.configure_text("Execute Trade")

    # ---- Stats ------------------------------------------------------------

    def _build_stats(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["stats"] = frame

        # Scrollable container (mousewheel only, no visible scrollbar)
        canvas = tk.Canvas(frame, bg=BG_PRIMARY, bd=0, highlightthickness=0)
        scroll_frame = tk.Frame(canvas, bg=BG_PRIMARY)
        scroll_frame.bind("<Configure>",
                          lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        cw = canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(cw, width=e.width))
        canvas.pack(fill="both", expand=True)

        def _stats_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

        def _stats_enter(e):
            canvas.bind_all("<MouseWheel>", _stats_mousewheel)

        def _stats_leave(e):
            canvas.unbind_all("<MouseWheel>")

        frame.bind("<Enter>", _stats_enter)
        frame.bind("<Leave>", _stats_leave)

        self._stats_scroll_frame = scroll_frame

        # Filter bar + search + refresh
        top_bar = tk.Frame(scroll_frame, bg=BG_PRIMARY)
        top_bar.pack(fill="x", pady=(0, 12), padx=(0, 4))
        PillButton(top_bar, text="Refresh Stats", command=self._refresh_stats,
                   width=130, height=36).pack(side="right")

        # Ticker search + price lookup
        search_frame = tk.Frame(top_bar, bg=BG_PRIMARY)
        search_frame.pack(side="right", padx=(0, 12))
        tk.Label(search_frame, text="Ticker:", bg=BG_PRIMARY, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9)).pack(side="left", padx=(0, 4))
        self._stats_search = ttk.Entry(search_frame, width=10, font=(FONT_MONO, 10))
        self._stats_search.pack(side="left", padx=(0, 6))
        self._stats_search.bind("<KeyRelease>", lambda e: self._refresh_stats())
        PillButton(search_frame, text="Lookup", command=self._stats_ticker_lookup,
                   width=72, height=28, font_size=8, bg_color=BG_CARD_ALT,
                   hover_color=ACCENT).pack(side="left", padx=(0, 6))
        self._stats_price_lbl = tk.Label(search_frame, text="", bg=BG_PRIMARY,
                                          fg=TEXT_PRIMARY, font=(FONT_MONO, 10, "bold"))
        self._stats_price_lbl.pack(side="left")

        # Period filter chips
        tk.Label(top_bar, text="PERIOD", bg=BG_PRIMARY, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(side="left", padx=(0, 8))
        self._stats_period = tk.StringVar(value="all")
        self._stats_period_chips: Dict[str, tk.Label] = {}
        for period_val, period_label in [
            ("week", "This Week"), ("month", "This Month"),
            ("last_month", "Last Month"), ("year", "This Year"),
            ("all", "All Time"),
        ]:
            chip = self._make_chip(top_bar, period_label,
                                   lambda pv=period_val: self._set_stats_period(pv),
                                   selected=(period_val == "all"))
            chip.pack(side="left", padx=(0, 6))
            self._stats_period_chips[period_val] = chip

        # ================================================================
        # HERO P/L CARD — big prominent realized profit number
        # ================================================================
        hero_card = RoundedFrame(scroll_frame, bg_color=BG_HERO,
                                 border_color=_blend(ACCENT, BORDER, 0.55),
                                 radius=16)
        hero_card.pack(fill="x", pady=(0, 14))
        for t in (0.45, 0.62, 0.75, 0.85, 0.93, 0.98):
            tk.Frame(hero_card.inner, bg=_blend(ACCENT, BG_HERO, t),
                     height=2).pack(fill="x")
        hero_inner = tk.Frame(hero_card.inner, bg=BG_HERO)
        hero_inner.pack(fill="x", padx=26, pady=(16, 20))

        hero_left = tk.Frame(hero_inner, bg=BG_HERO)
        hero_left.pack(side="left", fill="y")
        tk.Label(hero_left, text="NET REALIZED PROFIT", bg=BG_HERO, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(anchor="w")
        self._hero_pl = tk.Label(hero_left, text="$0.00", bg=BG_HERO, fg=GREEN,
                                 font=(FONT_MONO, 40, "bold"))
        self._hero_pl.pack(anchor="w", pady=(2, 0))
        self._hero_pl_sub = tk.Label(hero_left, text="", bg=BG_HERO, fg=TEXT_SECONDARY,
                                     font=(FONT_FAMILY, 10))
        self._hero_pl_sub.pack(anchor="w")

        hero_right = tk.Frame(hero_inner, bg=BG_HERO)
        hero_right.pack(side="right", fill="y")
        hero_right_grid = tk.Frame(hero_right, bg=BG_HERO)
        hero_right_grid.pack(anchor="e")
        for i in range(3):
            hero_right_grid.columnconfigure(i, weight=1, minsize=120)

        self._hero_win_rate = self._make_hero_mini(hero_right_grid, "WIN RATE", "—", 0, 0)
        self._hero_best = self._make_hero_mini(hero_right_grid, "BEST TRADE", "—", 0, 1)
        self._hero_worst = self._make_hero_mini(hero_right_grid, "WORST TRADE", "—", 0, 2)
        self._hero_trades = self._make_hero_mini(hero_right_grid, "TOTAL TRADES", "0", 1, 0)
        self._hero_volume = self._make_hero_mini(hero_right_grid, "VOLUME", "$0", 1, 1)
        self._hero_avg_return = self._make_hero_mini(hero_right_grid, "AVG RETURN", "—", 1, 2)

        # ================================================================
        # COVERAGE — what the figure above does NOT include
        # ================================================================
        # Packed only when there is something to say, so it is never furniture.
        #
        # A total that quietly drops rows overstates its own coverage, and this
        # one drops them in both directions at once: a symbol sold with no
        # recorded buy vanishes from realized entirely (TOPT, $339), while one
        # whose buys have no price counts as 100% profit because its cost
        # divides out to zero (MASK, $6.48). A third kind is subtler and has no
        # visible symptom at all — LHSW has 26 buys of which 13 carry no price,
        # so its cost is summed over 13 and divided by 26, and the profit is
        # simply too big.
        self._cov_card = RoundedFrame(scroll_frame, bg_color=BG_CARD,
                                      border_color=YELLOW, radius=RAD_MD)
        cov_body = tk.Frame(self._cov_card.inner, bg=BG_CARD)
        cov_body.pack(fill="x", padx=SP_XL, pady=SP_MD)
        cov_head = tk.Frame(cov_body, bg=BG_CARD)
        cov_head.pack(fill="x")
        tk.Label(cov_head, text=f"{icon('warning')}  WHAT THIS FIGURE LEAVES OUT",
                 bg=BG_CARD, fg=YELLOW, font=(ICON_FONT, 10, "bold")).pack(side="left")
        PillButton(cov_head, text="Mark as read", bg_color=BG_CARD_ALT,
                   hover_color=ACCENT, command=self._mark_coverage_read,
                   width=110, height=26, font_size=9).pack(side="right")
        self._cov_lines = tk.Frame(cov_body, bg=BG_CARD)
        self._cov_lines.pack(fill="x", pady=(8, 0))

        # ================================================================
        # RISK & PERFORMANCE METRICS — quant KPI tiles
        # ================================================================
        adv_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=RAD_MD)
        adv_card.pack(fill="x", pady=(0, SP_LG))
        # The coverage strip slots in above this one when it has something to
        # report. Held as a reference so it lands under the hero rather than at
        # the foot of the page.
        self._cov_before = adv_card

        adv_head = tk.Frame(adv_card.inner, bg=BG_CARD)
        adv_head.pack(fill="x", padx=SP_XL, pady=(SP_LG, SP_SM))
        tk.Label(adv_head, text="Risk & Performance Metrics", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, FS_H2, "bold")).pack(side="left")
        tk.Label(adv_head, text="Realized, closed-trade basis", bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, FS_MICRO)).pack(side="right")

        adv_grid = tk.Frame(adv_card.inner, bg=BG_CARD)
        adv_grid.pack(fill="x", padx=SP_XL, pady=(0, SP_LG))
        for i in range(4):
            adv_grid.columnconfigure(i, weight=1, uniform="kpi")

        self._adv_profit_factor = self._make_kpi_tile(adv_grid, "PROFIT FACTOR", "gross win ÷ gross loss", 0, 0)
        self._adv_expectancy    = self._make_kpi_tile(adv_grid, "EXPECTANCY", "avg $ per closed trade", 0, 1)
        self._adv_avg_win       = self._make_kpi_tile(adv_grid, "AVG WIN", "mean winning trade", 0, 2)
        self._adv_avg_loss      = self._make_kpi_tile(adv_grid, "AVG LOSS", "mean losing trade", 0, 3)
        self._adv_payoff        = self._make_kpi_tile(adv_grid, "PAYOFF RATIO", "avg win ÷ avg loss", 1, 0)
        self._adv_max_dd        = self._make_kpi_tile(adv_grid, "MAX DRAWDOWN", "peak-to-trough equity", 1, 1)
        self._adv_wl            = self._make_kpi_tile(adv_grid, "WIN / LOSS", "closed trade record", 1, 2)
        self._adv_consistency   = self._make_kpi_tile(adv_grid, "CONSISTENCY", "return mean ÷ std dev", 1, 3)

        # ================================================================
        # CHARTS ROW 1 — Equity Curve + Profit by Symbol
        # ================================================================
        charts_row1 = tk.Frame(scroll_frame, bg=BG_PRIMARY)
        charts_row1.pack(fill="x", pady=(0, 14))
        charts_row1.columnconfigure(0, weight=3)
        charts_row1.columnconfigure(1, weight=2)

        # Equity curve (cumulative P/L over time)
        eq_card = RoundedFrame(charts_row1, bg_color=BG_CARD, border_color=BORDER, radius=14)
        eq_card.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        tk.Label(eq_card.inner, text="Cumulative P/L Over Time", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 8))
        self._equity_canvas = tk.Canvas(eq_card.inner, bg=BG_CARD, height=200,
                                        bd=0, highlightthickness=0)
        self._equity_canvas.pack(fill="x", padx=20, pady=(0, 16))

        # Profit by symbol bar chart
        sym_bar_card = RoundedFrame(charts_row1, bg_color=BG_CARD, border_color=BORDER, radius=14)
        sym_bar_card.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        tk.Label(sym_bar_card.inner, text="Profit by Symbol", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 8))
        self._sym_bar_canvas = tk.Canvas(sym_bar_card.inner, bg=BG_CARD, height=200,
                                         bd=0, highlightthickness=0)
        self._sym_bar_canvas.pack(fill="x", padx=20, pady=(0, 16))

        # ================================================================
        # CHARTS ROW 2 — Broker Donut + Daily Activity
        # ================================================================
        charts_row2 = tk.Frame(scroll_frame, bg=BG_PRIMARY)
        charts_row2.pack(fill="x", pady=(0, 14))
        charts_row2.columnconfigure(0, weight=1)
        charts_row2.columnconfigure(1, weight=1)

        # Broker volume donut
        donut_card = RoundedFrame(charts_row2, bg_color=BG_CARD, border_color=BORDER, radius=14)
        donut_card.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        tk.Label(donut_card.inner, text="Volume by Broker", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 8))
        self._donut_canvas = tk.Canvas(donut_card.inner, bg=BG_CARD, height=200,
                                       bd=0, highlightthickness=0)
        self._donut_canvas.pack(fill="x", padx=20, pady=(0, 16))

        # Daily trade activity
        daily_card = RoundedFrame(charts_row2, bg_color=BG_CARD, border_color=BORDER, radius=14)
        daily_card.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        tk.Label(daily_card.inner, text="Daily Trade Activity", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 8))
        self._daily_canvas = tk.Canvas(daily_card.inner, bg=BG_CARD, height=200,
                                       bd=0, highlightthickness=0)
        self._daily_canvas.pack(fill="x", padx=20, pady=(0, 16))

        # ================================================================
        # CHARTS ROW 3 — Monthly P/L + Return Distribution
        # ================================================================
        charts_row3 = tk.Frame(scroll_frame, bg=BG_PRIMARY)
        charts_row3.pack(fill="x", pady=(0, 14))
        charts_row3.columnconfigure(0, weight=1)
        charts_row3.columnconfigure(1, weight=1)

        # Monthly realized P/L
        monthly_card = RoundedFrame(charts_row3, bg_color=BG_CARD, border_color=BORDER, radius=14)
        monthly_card.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        tk.Label(monthly_card.inner, text="Monthly Realized P/L", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 8))
        self._monthly_canvas = tk.Canvas(monthly_card.inner, bg=BG_CARD, height=200,
                                         bd=0, highlightthickness=0)
        self._monthly_canvas.pack(fill="x", padx=20, pady=(0, 16))

        # Return distribution histogram
        dist_card = RoundedFrame(charts_row3, bg_color=BG_CARD, border_color=BORDER, radius=14)
        dist_card.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        tk.Label(dist_card.inner, text="Return Distribution", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 8))
        self._dist_canvas = tk.Canvas(dist_card.inner, bg=BG_CARD, height=200,
                                      bd=0, highlightthickness=0)
        self._dist_canvas.pack(fill="x", padx=20, pady=(0, 16))

        # ================================================================
        # DAILY REALIZED P/L, AND WHICH BROKER MADE IT
        # ================================================================
        # Monthly answers "is this working"; daily answers "what happened
        # today", which is the question actually asked after a sell run. The
        # per-broker split matters because the brokers are not interchangeable:
        # only three hold fractions, so a day's profit landing entirely at
        # Public and Robinhood means something different from the same figure
        # spread across ten.
        daily_pl_card = RoundedFrame(scroll_frame, bg_color=BG_CARD,
                                     border_color=BORDER, radius=14)
        daily_pl_card.pack(fill="x", pady=(0, 14))

        dp_head = tk.Frame(daily_pl_card.inner, bg=BG_CARD)
        dp_head.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(dp_head, text="Daily Realized P/L", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(side="left")
        self._daily_pl_sub = tk.Label(dp_head, text="", bg=BG_CARD, fg=TEXT_MUTED,
                                      font=(FONT_FAMILY, 9))
        self._daily_pl_sub.pack(side="left", padx=(10, 0))

        self._daily_pl_canvas = tk.Canvas(daily_pl_card.inner, bg=BG_CARD, height=190,
                                          bd=0, highlightthickness=0)
        self._daily_pl_canvas.pack(fill="x", padx=20, pady=(0, 10))

        dp_cols = ("date", "pl", "brokers", "trades")
        self._daily_pl_tree = ttk.Treeview(
            daily_pl_card.inner, columns=dp_cols, show="headings", height=9,
            selectmode="none")
        for col, heading, w, anchor in [
            ("date", "Day", 100, "w"),
            ("pl", "Realized", 100, "center"),
            ("brokers", "Where it came from", 460, "w"),
            ("trades", "Sells", 60, "center"),
        ]:
            self._daily_pl_tree.heading(col, text=heading)
            self._daily_pl_tree.column(col, width=w, anchor=anchor)
        self._daily_pl_tree.pack(fill="x", padx=20, pady=(0, 16))
        self._daily_pl_tree.tag_configure("win", foreground=GREEN)
        self._daily_pl_tree.tag_configure("loss", foreground=RED)

        # ================================================================
        # CLOSED TRADES TABLE — the money table
        # ================================================================
        closed_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        closed_card.pack(fill="x", pady=(0, 14))

        closed_header = tk.Frame(closed_card.inner, bg=BG_CARD)
        closed_header.pack(fill="x", padx=20, pady=(16, 12))
        tk.Label(closed_header, text="Closed Trades — Realized P/L", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(side="left")
        self._closed_total_label = tk.Label(closed_header, text="", bg=BG_CARD,
                                            fg=GREEN, font=(FONT_MONO, 12, "bold"))
        self._closed_total_label.pack(side="right")

        closed_cols = ("symbol", "shares", "avg_buy", "avg_sell", "cost", "revenue", "profit", "return_pct")
        closed_tree_frame = tk.Frame(closed_card.inner, bg=BG_CARD)
        closed_tree_frame.pack(fill="x", padx=20, pady=(0, 16))
        self._closed_trades_tree = ttk.Treeview(
            closed_tree_frame, columns=closed_cols, show="headings", height=10,
            selectmode="none")
        closed_scroll = ttk.Scrollbar(closed_tree_frame, orient="vertical",
                                      command=self._closed_trades_tree.yview)
        self._closed_trades_tree.configure(yscrollcommand=closed_scroll.set)
        for col, heading, w in [
            ("symbol", "Symbol", 90),
            ("shares", "Shares", 80),
            ("avg_buy", "Avg Buy", 90),
            ("avg_sell", "Avg Sell", 90),
            ("cost", "Cost Basis", 100),
            ("revenue", "Revenue", 100),
            ("profit", "Net Profit", 110),
            ("return_pct", "Return %", 90),
        ]:
            self._closed_trades_tree.heading(col, text=heading)
            self._closed_trades_tree.column(col, width=w, anchor="center" if col != "symbol" else "w")
        self._closed_trades_tree.pack(side="left", fill="x", expand=True)
        closed_scroll.pack(side="right", fill="y")

        # ================================================================
        # TRADE SUMMARY GRID
        # ================================================================
        summary_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        summary_card.pack(fill="x", pady=(0, 14))

        tk.Label(summary_card.inner, text="Trade Summary", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 12))

        summary_grid = tk.Frame(summary_card.inner, bg=BG_CARD)
        summary_grid.pack(fill="x", padx=20, pady=(0, 16))
        for i in range(4):
            summary_grid.columnconfigure(i, weight=1)

        self._stat_buys = self._make_mini_stat(summary_grid, "Total Buys", "0", 0, 0)
        self._stat_sells = self._make_mini_stat(summary_grid, "Total Sells", "0", 0, 1)
        self._stat_symbols = self._make_mini_stat(summary_grid, "Symbols Traded", "0", 0, 2)
        self._stat_avg_trade = self._make_mini_stat(summary_grid, "Avg Trade Size", "$0.00", 0, 3)
        self._stat_volume = self._make_mini_stat(summary_grid, "Total Volume", "$0.00", 1, 0)
        self._stat_shares = self._make_mini_stat(summary_grid, "Shares Traded", "0", 1, 1)
        self._stat_brokers_used = self._make_mini_stat(summary_grid, "Brokers Used", "0", 1, 2)
        self._stat_accounts_used = self._make_mini_stat(summary_grid, "Accounts Used", "0", 1, 3)

        # ================================================================
        # PER-BROKER PERFORMANCE TABLE
        # ================================================================
        broker_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        broker_card.pack(fill="x", pady=(0, 14))

        tk.Label(broker_card.inner, text="Per-Broker Performance", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 12))

        cols = ("broker", "trades", "buys", "sells", "volume", "avg_size", "pl")
        self._broker_stats_tree = ttk.Treeview(
            broker_card.inner, columns=cols, show="headings", height=10,
            selectmode="none")
        for col, heading, w in [
            ("broker", "Broker", 120),
            ("trades", "Trades", 70),
            ("buys", "Buys", 60),
            ("sells", "Sells", 60),
            ("volume", "Volume", 110),
            ("avg_size", "Avg Size", 90),
            ("pl", "P/L", 100),
        ]:
            self._broker_stats_tree.heading(col, text=heading)
            self._broker_stats_tree.column(col, width=w, anchor="center" if col != "broker" else "w")
        self._broker_stats_tree.pack(fill="x", padx=20, pady=(0, 16))

        # ================================================================
        # SYMBOL PERFORMANCE TABLE
        # ================================================================
        symbol_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        symbol_card.pack(fill="x", pady=(0, 14))

        tk.Label(symbol_card.inner, text="Symbol Performance", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 12))

        sym_cols = ("symbol", "trades", "shares_bought", "shares_sold", "avg_buy", "avg_sell", "net_position", "pl")
        self._symbol_stats_tree = ttk.Treeview(
            symbol_card.inner, columns=sym_cols, show="headings", height=10,
            selectmode="none")
        for col, heading, w in [
            ("symbol", "Symbol", 90),
            ("trades", "Trades", 70),
            ("shares_bought", "Bought", 80),
            ("shares_sold", "Sold", 80),
            ("avg_buy", "Avg Buy $", 90),
            ("avg_sell", "Avg Sell $", 90),
            ("net_position", "Net Shares", 80),
            ("pl", "P/L", 100),
        ]:
            self._symbol_stats_tree.heading(col, text=heading)
            self._symbol_stats_tree.column(col, width=w, anchor="center" if col != "symbol" else "w")
        self._symbol_stats_tree.pack(fill="x", padx=20, pady=(0, 16))

        # ================================================================
        # RECENT TRADES
        # ================================================================
        recent_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        recent_card.pack(fill="x", pady=(0, 14))

        tk.Label(recent_card.inner, text="Recent Trades", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 12))

        recent_cols = ("time", "broker", "account", "side", "symbol", "qty", "price", "total")
        recent_tree_frame = tk.Frame(recent_card.inner, bg=BG_CARD)
        recent_tree_frame.pack(fill="x", padx=20, pady=(0, 16))
        self._recent_trades_tree = ttk.Treeview(
            recent_tree_frame, columns=recent_cols, show="headings", height=20,
            selectmode="none")
        recent_scroll = ttk.Scrollbar(recent_tree_frame, orient="vertical",
                                      command=self._recent_trades_tree.yview)
        self._recent_trades_tree.configure(yscrollcommand=recent_scroll.set)
        for col, heading, w in [
            ("time", "Date", 130),
            ("broker", "Broker", 80),
            ("account", "Account", 180),
            ("side", "Side", 50),
            ("symbol", "Symbol", 70),
            ("qty", "Qty", 50),
            ("price", "Price", 80),
            ("total", "Total", 80),
        ]:
            self._recent_trades_tree.heading(col, text=heading)
            self._recent_trades_tree.column(col, width=w, anchor="center" if col not in ("broker", "symbol", "account") else "w")
        self._recent_trades_tree.pack(side="left", fill="x", expand=True)
        recent_scroll.pack(side="right", fill="y")

        # ================================================================
        # TRADE SIMULATOR
        # ================================================================
        sim_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        sim_card.pack(fill="x", pady=(0, 16))

        tk.Label(sim_card.inner, text="Trade Simulator", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 8))
        tk.Label(sim_card.inner, text="Estimate profit from a round-trip trade across multiple accounts",
                 bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 8)).pack(anchor="w", padx=20, pady=(0, 12))

        sim_form = tk.Frame(sim_card.inner, bg=BG_CARD)
        sim_form.pack(fill="x", padx=20, pady=(0, 12))

        tk.Label(sim_form, text="TICKER", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_ticker = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        self._sim_ticker.grid(row=0, column=1, sticky="w", padx=(0, 16), pady=(0, 6))

        PillButton(sim_form, text="Fetch Price", command=self._sim_fetch_price,
                   width=100, height=28).grid(row=0, column=2, sticky="w", padx=(0, 16), pady=(0, 6))

        tk.Label(sim_form, text="BUY PRICE", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_buy_price = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        self._sim_buy_price.grid(row=1, column=1, sticky="w", padx=(0, 16), pady=(0, 6))

        tk.Label(sim_form, text="SELL PRICE", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_sell_price = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        self._sim_sell_price.grid(row=1, column=3, sticky="w", padx=(0, 16), pady=(0, 6))

        tk.Label(sim_form, text="SHARES / ACCT", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=2, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_qty = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        self._sim_qty.insert(0, "1")
        self._sim_qty.grid(row=2, column=1, sticky="w", padx=(0, 16), pady=(0, 6))

        tk.Label(sim_form, text="ACCOUNTS", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=2, column=2, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_accounts = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        total_accts = sum(
            _KNOWN_ACCOUNT_COUNTS.get(b, 1) if _broker_has_creds(b) else 0
            for b in BROKER_MODULES
        )
        self._sim_accounts.insert(0, str(total_accts))
        self._sim_accounts.grid(row=2, column=3, sticky="w", padx=(0, 16), pady=(0, 6))

        calc_row = tk.Frame(sim_card.inner, bg=BG_CARD)
        calc_row.pack(fill="x", padx=20, pady=(0, 8))
        PillButton(calc_row, text="Calculate", command=self._sim_calculate,
                   width=110, height=32).pack(side="left")

        self._sim_result = tk.Label(sim_card.inner, text="", bg=BG_CARD, fg=TEXT_PRIMARY,
                                    font=(FONT_MONO, 10), justify="left", anchor="w")
        self._sim_result.pack(fill="x", padx=20, pady=(0, 16))

        # Store chart data for redraw on resize
        self._chart_all_trades: list = []
        self._chart_trades: list = []
        self._chart_sym_data: dict = {}
        self._chart_broker_data: dict = {}

        # Redraw charts when canvases resize
        def _on_chart_resize(e):
            if e.width > 10:
                self._redraw_charts()

        self._chart_monthly: dict = {}
        self._chart_daily_pl: dict = {}
        self._chart_returns: list = []

        self._equity_canvas.bind("<Configure>", _on_chart_resize)
        self._sym_bar_canvas.bind("<Configure>", _on_chart_resize)
        self._donut_canvas.bind("<Configure>", _on_chart_resize)
        self._daily_canvas.bind("<Configure>", _on_chart_resize)
        self._monthly_canvas.bind("<Configure>", _on_chart_resize)
        self._daily_pl_canvas.bind("<Configure>", _on_chart_resize)
        self._dist_canvas.bind("<Configure>", _on_chart_resize)

        # Initial load
        self.after(200, self._refresh_stats)

    def _redraw_charts(self) -> None:
        """Redraw all charts with cached data (called on canvas resize)."""
        if (self._chart_trades or self._chart_sym_data or self._chart_broker_data
                or self._chart_monthly or self._chart_returns
                or self._chart_daily_pl):
            self._draw_equity_curve(self._chart_trades, self._chart_all_trades)
            self._draw_symbol_bars(self._chart_sym_data, self._chart_all_trades)
            self._draw_broker_donut(self._chart_broker_data)
            self._draw_daily_activity(self._chart_trades)
            self._draw_monthly_pl(self._chart_monthly)
            self._draw_daily_pl(self._chart_daily_pl)
            self._draw_return_dist(self._chart_returns)

    def _make_kpi_tile(self, parent, title: str, hint: str, row: int, col: int) -> tk.Label:
        """Enterprise stat tile: subtle panel with uppercase label, value, hint."""
        tile = tk.Frame(parent, bg=BG_CARD_ALT, highlightbackground=BORDER,
                        highlightthickness=1)
        tile.grid(row=row, column=col, sticky="nsew",
                  padx=(0, SP_SM) if col < 3 else (0, 0),
                  pady=(0, SP_SM))
        tk.Frame(tile, bg=_blend(ACCENT, BG_CARD_ALT, 0.55), height=2).pack(
            fill="x")
        inner = tk.Frame(tile, bg=BG_CARD_ALT)
        inner.pack(fill="both", expand=True, padx=SP_MD, pady=SP_MD)
        tk.Label(inner, text=title, bg=BG_CARD_ALT, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, FS_MICRO, "bold")).pack(anchor="w")
        val_lbl = tk.Label(inner, text="—", bg=BG_CARD_ALT, fg=TEXT_PRIMARY,
                           font=(FONT_MONO, 17, "bold"))
        val_lbl.pack(anchor="w", pady=(SP_XS, 0))
        tk.Label(inner, text=hint, bg=BG_CARD_ALT, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, FS_NANO)).pack(anchor="w")
        return val_lbl

    def _set_stats_period(self, period: str) -> None:
        self._stats_period.set(period)
        for pv, chip in self._stats_period_chips.items():
            self._style_chip(chip, pv == period)
        self._refresh_stats()

    def _make_hero_mini(self, parent, title: str, value: str, row: int, col: int) -> tk.Label:
        cell = tk.Frame(parent, bg=BG_HERO)
        cell.grid(row=row, column=col, sticky="nsew", padx=(0, 20), pady=(0, 8))
        tk.Label(cell, text=title, bg=BG_HERO, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 7, "bold")).pack(anchor="e")
        val_lbl = tk.Label(cell, text=value, bg=BG_HERO, fg=TEXT_PRIMARY,
                           font=(FONT_MONO, 14, "bold"))
        val_lbl.pack(anchor="e")
        return val_lbl

    def _make_stat_card(self, parent, title: str, value: str, col: int) -> tk.Label:
        card = RoundedFrame(parent, bg_color=BG_CARD, border_color=BORDER, radius=12, height=90)
        card.grid(row=0, column=col, sticky="nsew", padx=(0, 10) if col < 4 else (0, 0))

        tk.Label(card.inner, text=title, bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).pack(anchor="w", padx=16, pady=(12, 2))

        val_lbl = tk.Label(card.inner, text=value, bg=BG_CARD, fg=TEXT_PRIMARY,
                           font=(FONT_FAMILY, 18, "bold"))
        val_lbl.pack(anchor="w", padx=16, pady=(0, 12))
        return val_lbl

    def _make_mini_stat(self, parent, title: str, value: str, row: int, col: int) -> tk.Label:
        cell = tk.Frame(parent, bg=BG_CARD)
        cell.grid(row=row, column=col, sticky="nsew", padx=(0, 16), pady=(0, 12))

        tk.Label(cell, text=title, bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 8)).pack(anchor="w")
        val_lbl = tk.Label(cell, text=value, bg=BG_CARD, fg=TEXT_PRIMARY,
                           font=(FONT_MONO, 13, "bold"))
        val_lbl.pack(anchor="w")
        return val_lbl

    # ---- Chart drawing helpers -------------------------------------------

    def _draw_equity_curve(self, trades: list, all_trades: list = None) -> None:
        """Draw cumulative P/L line chart on the equity canvas."""
        c = self._equity_canvas
        c.delete("all")
        c.update_idletasks()
        W = max(c.winfo_width(), 300)
        H = max(c.winfo_height(), 180)
        pad_l, pad_r, pad_t, pad_b = 60, 20, 10, 30

        # Build all-time avg buy cost per symbol (so period-filtered sells
        # still know their cost basis even when buys predate the period)
        sym_cost: Dict[str, float] = {}
        sym_qty: Dict[str, float] = {}
        for t in (all_trades or trades):
            if t["side"] != "buy":
                continue
            s = t["symbol"]
            sym_qty[s] = sym_qty.get(s, 0) + t["qty"]
            sym_cost[s] = sym_cost.get(s, 0) + (t["fill_price"] or 0) * t["qty"]

        # Build cumulative P/L series by date (only from period sells)
        from collections import OrderedDict
        daily_pl: Dict[str, float] = OrderedDict()
        for t in trades:
            if t["side"] != "sell":
                continue
            s = t["symbol"]
            price = t["fill_price"] or 0
            date = t.get("timestamp", "")[:10]
            avg_b = sym_cost.get(s, 0) / sym_qty.get(s, 1) if sym_qty.get(s, 0) else 0
            pl = (price - avg_b) * t["qty"]
            daily_pl[date] = daily_pl.get(date, 0) + pl

        if not daily_pl:
            c.create_text(W // 2, H // 2, text="No closed trades yet",
                          fill=TEXT_MUTED, font=(FONT_FAMILY, 10))
            return

        # Cumulative series
        dates = sorted(daily_pl.keys())
        cum = []
        running = 0.0
        for d in dates:
            running += daily_pl[d]
            cum.append(running)

        min_v = min(0, min(cum))
        max_v = max(0, max(cum))
        spread = max_v - min_v if max_v != min_v else 1

        plot_w = W - pad_l - pad_r
        plot_h = H - pad_t - pad_b

        # Grid lines
        for i in range(5):
            y = pad_t + plot_h * i / 4
            val = max_v - spread * i / 4
            c.create_line(pad_l, y, W - pad_r, y, fill=GRID_LINE, dash=(2, 4))
            c.create_text(pad_l - 6, y, text=f"${val:,.0f}", fill=TEXT_MUTED,
                          font=(FONT_FAMILY, FS_NANO), anchor="e")

        # Zero line
        zero_y = pad_t + plot_h * (max_v / spread) if spread else pad_t + plot_h / 2
        c.create_line(pad_l, zero_y, W - pad_r, zero_y, fill=TEXT_MUTED, width=1)

        def _xy(i, val):
            x = pad_l + (plot_w * i / max(len(cum) - 1, 1))
            y = pad_t + plot_h * ((max_v - val) / spread)
            return x, y

        # Running high-water mark (peak equity) for drawdown visualization
        hw = []
        peak = cum[0]
        for v in cum:
            peak = max(peak, v)
            hw.append(peak)

        points = [_xy(i, v) for i, v in enumerate(cum)]
        hw_points = [_xy(i, v) for i, v in enumerate(hw)]

        if len(points) >= 2:
            # Drawdown band: area between the peak envelope and the equity line
            band = hw_points + list(reversed(points))
            c.create_polygon([co for pt in band for co in pt],
                             fill=RED_SOFT, outline="")

            # Fill under the equity curve down to the zero line
            fill_pts = list(points) + [(points[-1][0], zero_y), (points[0][0], zero_y)]
            fill_color = GREEN_DIM if cum[-1] >= 0 else RED_DIM
            c.create_polygon([co for pt in fill_pts for co in pt],
                             fill=fill_color, outline="")

            # High-water mark envelope (faint dashed)
            c.create_line([co for pt in hw_points for co in pt],
                          fill=TEXT_MUTED, width=1, dash=(3, 3))

            # Equity line — soft glow pass underneath the crisp line
            line_color = GREEN if cum[-1] >= 0 else RED
            c.create_line([co for pt in points for co in pt],
                          fill=_blend(line_color, BG_CARD, 0.72), width=6,
                          smooth=True)
            c.create_line([co for pt in points for co in pt],
                          fill=line_color, width=2, smooth=True)

            # End dot + value annotation
            ex, ey = points[-1]
            c.create_oval(ex - 4, ey - 4, ex + 4, ey + 4, fill=line_color, outline=BG_CARD, width=2)
            lbl = f"${cum[-1]:+,.0f}"
            tx = ex - 6
            c.create_text(tx, max(ey - 12, pad_t + 6), text=lbl, fill=line_color,
                          font=(FONT_MONO, FS_MICRO, "bold"), anchor="e")

        # Date labels
        if len(dates) > 0:
            step = max(1, len(dates) // 5)
            for i in range(0, len(dates), step):
                x = pad_l + (plot_w * i / max(len(dates) - 1, 1))
                c.create_text(x, H - 8, text=dates[i][5:],  # MM-DD
                              fill=TEXT_MUTED, font=(FONT_FAMILY, FS_NANO))

    def _draw_symbol_bars(self, sym_data: dict, all_trades: list = None) -> None:
        """Draw horizontal bar chart of profit per symbol."""
        c = self._sym_bar_canvas
        c.delete("all")
        c.update_idletasks()
        W = max(c.winfo_width(), 300)
        H = max(c.winfo_height(), 180)

        # All-time buy cost for accurate P/L
        alltime_buy: Dict[str, Dict] = {}
        for t in (all_trades or []):
            if t["side"] != "buy":
                continue
            ab = alltime_buy.setdefault(t["symbol"], {"qty": 0.0, "cost": 0.0})
            ab["qty"] += t["qty"]
            ab["cost"] += (t["fill_price"] or 0) * t["qty"]

        # Compute profits
        profits = []
        for s, d in sym_data.items():
            if not d.get("sold"):
                continue
            ab = alltime_buy.get(s)
            if not ab or not ab["qty"]:
                continue
            avg_b = ab["cost"] / ab["qty"]
            profit = d["sell_rev"] - avg_b * d["sold"]
            profits.append((s, profit))

        if not profits:
            c.create_text(W // 2, H // 2, text="No closed trades yet",
                          fill=TEXT_MUTED, font=(FONT_FAMILY, 10))
            return

        profits.sort(key=lambda x: x[1], reverse=True)
        profits = profits[:10]  # top 10

        pad_l, pad_r, pad_t, pad_b = 60, 40, 10, 10
        plot_w = W - pad_l - pad_r
        plot_h = H - pad_t - pad_b

        max_abs = max(abs(p) for _, p in profits) or 1
        bar_h = min(20, plot_h / len(profits) - 4)
        spacing = plot_h / len(profits)

        for i, (sym, val) in enumerate(profits):
            y = pad_t + spacing * i + spacing / 2
            bar_w = (abs(val) / max_abs) * plot_w * 0.8
            color = GREEN if val >= 0 else RED

            c.create_text(pad_l - 6, y, text=sym, fill=TEXT_PRIMARY,
                          font=(FONT_FAMILY, 8, "bold"), anchor="e")
            c.create_rectangle(pad_l, y - bar_h / 2, pad_l + bar_w, y + bar_h / 2,
                               fill=color, outline="")
            c.create_text(pad_l + bar_w + 6, y, text=f"${val:+,.2f}",
                          fill=color, font=(FONT_MONO, 8), anchor="w")

    def _draw_broker_donut(self, broker_data: dict) -> None:
        """Draw a donut chart of volume by broker."""
        import math
        c = self._donut_canvas
        c.delete("all")
        c.update_idletasks()
        W = max(c.winfo_width(), 300)
        H = max(c.winfo_height(), 180)

        total_vol = sum(d["volume"] for d in broker_data.values())
        if not total_vol:
            c.create_text(W // 2, H // 2, text="No trades yet",
                          fill=TEXT_MUTED, font=(FONT_FAMILY, 10))
            return

        # Monochrome brand ramp — same palette as every other chart
        palette = CHART_PALETTE

        cx = W // 3
        cy = H // 2
        r_outer = min(cx - 10, cy - 10, 80)
        r_inner = r_outer * 0.55

        sorted_brokers = sorted(broker_data.items(), key=lambda x: x[1]["volume"], reverse=True)
        start = 90  # start from top

        for i, (broker, d) in enumerate(sorted_brokers):
            extent = (d["volume"] / total_vol) * 360
            color = palette[i % len(palette)]

            # Draw arc (outer)
            c.create_arc(cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer,
                         start=start, extent=-extent, fill=color, outline=BG_CARD, width=2)
            start -= extent

        # Inner circle (donut hole)
        c.create_oval(cx - r_inner, cy - r_inner, cx + r_inner, cy + r_inner,
                      fill=BG_CARD, outline=BG_CARD)
        c.create_text(cx, cy - 8, text=f"${total_vol:,.0f}",
                      fill=TEXT_PRIMARY, font=(FONT_MONO, 10, "bold"))
        c.create_text(cx, cy + 8, text="total",
                      fill=TEXT_MUTED, font=(FONT_FAMILY, 7))

        # Legend on right side
        legend_x = cx + r_outer + 30
        legend_y = 20
        for i, (broker, d) in enumerate(sorted_brokers):
            color = palette[i % len(palette)]
            pct = d["volume"] / total_vol * 100
            c.create_rectangle(legend_x, legend_y, legend_x + 10, legend_y + 10,
                               fill=color, outline="")
            c.create_text(legend_x + 16, legend_y + 5,
                          text=f"{broker.capitalize()} ({pct:.0f}%)",
                          fill=TEXT_SECONDARY, font=(FONT_FAMILY, 8), anchor="w")
            legend_y += 18

    def _draw_daily_activity(self, trades: list) -> None:
        """Draw daily trade count bar chart."""
        c = self._daily_canvas
        c.delete("all")
        c.update_idletasks()
        W = max(c.winfo_width(), 300)
        H = max(c.winfo_height(), 180)

        from collections import OrderedDict
        daily: Dict[str, Dict[str, int]] = OrderedDict()
        for t in trades:
            date = t.get("timestamp", "")[:10]
            if not date:
                continue
            d = daily.setdefault(date, {"buys": 0, "sells": 0})
            if t["side"] == "buy":
                d["buys"] += 1
            elif t["side"] == "sell":
                d["sells"] += 1

        if not daily:
            c.create_text(W // 2, H // 2, text="No trades yet",
                          fill=TEXT_MUTED, font=(FONT_FAMILY, 10))
            return

        dates = sorted(daily.keys())[-30:]  # last 30 days
        pad_l, pad_r, pad_t, pad_b = 40, 10, 10, 30
        plot_w = W - pad_l - pad_r
        plot_h = H - pad_t - pad_b

        max_count = max(d["buys"] + d["sells"] for d in daily.values()) or 1
        bar_w = max(3, plot_w / len(dates) - 2)

        # Grid lines
        for i in range(5):
            y = pad_t + plot_h * i / 4
            val = max_count * (4 - i) / 4
            c.create_line(pad_l, y, W - pad_r, y, fill=BORDER, dash=(2, 4))
            if val == int(val):
                c.create_text(pad_l - 6, y, text=str(int(val)), fill=TEXT_MUTED,
                              font=(FONT_FAMILY, 7), anchor="e")

        for i, date in enumerate(dates):
            d = daily.get(date, {"buys": 0, "sells": 0})
            x = pad_l + (plot_w * i / max(len(dates) - 1, 1)) - bar_w / 2
            total = d["buys"] + d["sells"]
            buy_h = (d["buys"] / max_count) * plot_h
            sell_h = (d["sells"] / max_count) * plot_h

            # Stacked: buys on bottom, sells on top
            base_y = pad_t + plot_h
            if buy_h > 0:
                c.create_rectangle(x, base_y - buy_h, x + bar_w, base_y,
                                   fill=GREEN, outline="")
            if sell_h > 0:
                c.create_rectangle(x, base_y - buy_h - sell_h, x + bar_w, base_y - buy_h,
                                   fill=RED, outline="")

            # Date labels (every few bars)
            if i % max(1, len(dates) // 6) == 0:
                c.create_text(x + bar_w / 2, H - 8, text=date[5:],
                              fill=TEXT_MUTED, font=(FONT_FAMILY, 7))

        # Legend
        c.create_rectangle(W - 100, 8, W - 90, 18, fill=GREEN, outline="")
        c.create_text(W - 86, 13, text="Buys", fill=TEXT_MUTED, font=(FONT_FAMILY, 7), anchor="w")
        c.create_rectangle(W - 55, 8, W - 45, 18, fill=RED, outline="")
        c.create_text(W - 41, 13, text="Sells", fill=TEXT_MUTED, font=(FONT_FAMILY, 7), anchor="w")

    def _draw_daily_pl(self, daily: dict) -> None:
        """Realized P/L per day, each bar stacked by the broker that made it.

        Stacked rather than grouped: the height is the day's total, which is
        the number being looked for, and the segments answer "where from"
        without a second chart. Losses hang below the zero line in the same
        stack, so a day that made money at Public and lost it at Fidelity reads
        as the small net it actually was rather than two unrelated bars.
        """
        c = self._daily_pl_canvas
        c.delete("all")
        c.update_idletasks()
        W = max(c.winfo_width(), 300)
        H = max(c.winfo_height(), 170)

        days = sorted(daily.keys())[-30:]        # a month of trading
        if not days:
            c.create_text(W // 2, H // 2, text="No closed trades yet",
                          fill=TEXT_MUTED, font=(FONT_FAMILY, 10))
            return

        pad_l, pad_r, pad_t, pad_b = 52, 12, 14, 26
        iw = max(W - pad_l - pad_r, 40)
        ih = max(H - pad_t - pad_b, 40)

        totals = {d: sum(daily[d].values()) for d in days}
        hi = max([v for v in totals.values() if v > 0] or [0])
        lo = min([v for v in totals.values() if v < 0] or [0])
        span = (hi - lo) or 1.0
        zero_y = pad_t + ih * (hi / span)

        # zero line + the two extremes, which is all the scale this needs
        c.create_line(pad_l, zero_y, W - pad_r, zero_y, fill=BORDER)
        for val, y in ((hi, pad_t), (lo, pad_t + ih)):
            if val:
                c.create_text(pad_l - 8, y, text=f"${val:,.0f}", anchor="e",
                              fill=TEXT_MUTED, font=(FONT_FAMILY, 8))

        # A stable colour per broker, taken from the palette rather than
        # generated, so the same broker is the same colour every render.
        palette = [ACCENT, GREEN, YELLOW, "#a78bfa", "#22d3ee", "#fb6f84",
                   "#5b6172", "#9d9aff", "#34d39e", "#f2c14e"]
        brokers = sorted({b for d in days for b in daily[d]})
        colour = {b: palette[i % len(palette)] for i, b in enumerate(brokers)}

        slot = iw / len(days)
        bw = max(2.0, min(slot * 0.66, 26.0))
        for i, d in enumerate(days):
            cx = pad_l + slot * (i + 0.5)
            up = zero_y
            down = zero_y
            for b, v in sorted(daily[d].items(), key=lambda kv: -kv[1]):
                h = abs(v) / span * ih
                if h < 0.5:
                    continue
                if v > 0:
                    c.create_rectangle(cx - bw / 2, up - h, cx + bw / 2, up,
                                       fill=colour[b], outline="")
                    up -= h
                else:
                    c.create_rectangle(cx - bw / 2, down, cx + bw / 2, down + h,
                                       fill=colour[b], outline="")
                    down += h
            # Only label days that fit, newest always.
            if len(days) <= 10 or i == len(days) - 1 or i % max(1, len(days) // 6) == 0:
                c.create_text(cx, H - pad_b + 12, text=d[5:], anchor="n",
                              fill=TEXT_MUTED, font=(FONT_FAMILY, 7))

        # Legend, so a colour never has to be guessed.
        x = pad_l
        for b in brokers:
            c.create_rectangle(x, 2, x + 8, 10, fill=colour[b], outline="")
            c.create_text(x + 12, 6, text=b.capitalize(), anchor="w",
                          fill=TEXT_MUTED, font=(FONT_FAMILY, 7))
            x += 16 + len(b) * 5.5
            if x > W - 60:
                break

    def _draw_monthly_pl(self, monthly: dict) -> None:
        """Vertical bar chart of realized P/L grouped by month."""
        c = self._monthly_canvas
        c.delete("all")
        c.update_idletasks()
        W = max(c.winfo_width(), 300)
        H = max(c.winfo_height(), 180)

        months = sorted(monthly.keys())[-12:]  # last 12 months
        if not months:
            c.create_text(W // 2, H // 2, text="No closed trades yet",
                          fill=TEXT_MUTED, font=(FONT_FAMILY, 10))
            return

        vals = [monthly[m] for m in months]
        pad_l, pad_r, pad_t, pad_b = 52, 14, 16, 28
        plot_w = W - pad_l - pad_r
        plot_h = H - pad_t - pad_b

        max_v = max(0.0, max(vals))
        min_v = min(0.0, min(vals))
        spread = (max_v - min_v) or 1
        zero_y = pad_t + plot_h * (max_v / spread)

        # gridlines + y labels
        for i in range(5):
            y = pad_t + plot_h * i / 4
            val = max_v - spread * i / 4
            c.create_line(pad_l, y, W - pad_r, y, fill=GRID_LINE, dash=(2, 4))
            c.create_text(pad_l - 6, y, text=f"${val:,.0f}", fill=TEXT_MUTED,
                          font=(FONT_FAMILY, FS_NANO), anchor="e")

        slot = plot_w / len(months)
        bar_w = min(34, slot * 0.6)
        for i, (m, v) in enumerate(zip(months, vals)):
            cx = pad_l + slot * i + slot / 2
            bar_top = pad_t + plot_h * ((max_v - v) / spread)
            color = GREEN if v >= 0 else RED
            x0, x1 = cx - bar_w / 2, cx + bar_w / 2
            if v >= 0:
                c.create_rectangle(x0, bar_top, x1, zero_y, fill=color, outline="")
                c.create_text(cx, bar_top - 7, text=f"${v:,.0f}", fill=color,
                              font=(FONT_MONO, FS_NANO), anchor="s")
            else:
                c.create_rectangle(x0, zero_y, x1, bar_top, fill=color, outline="")
                c.create_text(cx, bar_top + 7, text=f"${v:,.0f}", fill=color,
                              font=(FONT_MONO, FS_NANO), anchor="n")
            # month label (MM/YY)
            yy, mm = m.split("-")
            c.create_text(cx, H - 8, text=f"{mm}/{yy[2:]}", fill=TEXT_MUTED,
                          font=(FONT_FAMILY, FS_NANO))

        # zero baseline
        c.create_line(pad_l, zero_y, W - pad_r, zero_y, fill=TEXT_MUTED, width=1)

    def _draw_return_dist(self, returns: list) -> None:
        """Histogram of per-trade % returns, colored by sign."""
        c = self._dist_canvas
        c.delete("all")
        c.update_idletasks()
        W = max(c.winfo_width(), 300)
        H = max(c.winfo_height(), 180)

        if not returns:
            c.create_text(W // 2, H // 2, text="No closed trades yet",
                          fill=TEXT_MUTED, font=(FONT_FAMILY, 10))
            return

        lo = min(returns)
        hi = max(returns)
        if hi - lo < 1e-9:
            lo -= 1
            hi += 1
        n_bins = min(9, max(4, len(returns)))
        width = (hi - lo) / n_bins
        counts = [0] * n_bins
        centers = []
        for b in range(n_bins):
            centers.append(lo + width * (b + 0.5))
        for r in returns:
            idx = int((r - lo) / width)
            if idx >= n_bins:
                idx = n_bins - 1
            counts[idx] += 1

        pad_l, pad_r, pad_t, pad_b = 36, 14, 16, 30
        plot_w = W - pad_l - pad_r
        plot_h = H - pad_t - pad_b
        max_c = max(counts) or 1

        # y gridlines (counts)
        for i in range(4):
            y = pad_t + plot_h * i / 3
            val = max_c * (3 - i) / 3
            c.create_line(pad_l, y, W - pad_r, y, fill=GRID_LINE, dash=(2, 4))
            if val == int(val):
                c.create_text(pad_l - 6, y, text=str(int(val)), fill=TEXT_MUTED,
                              font=(FONT_FAMILY, FS_NANO), anchor="e")

        slot = plot_w / n_bins
        bar_w = slot * 0.82
        base_y = pad_t + plot_h
        for b in range(n_bins):
            x0 = pad_l + slot * b + (slot - bar_w) / 2
            x1 = x0 + bar_w
            h = (counts[b] / max_c) * plot_h
            color = GREEN if centers[b] >= 0 else RED
            if counts[b] > 0:
                c.create_rectangle(x0, base_y - h, x1, base_y, fill=color, outline="")
                c.create_text((x0 + x1) / 2, base_y - h - 6, text=str(counts[b]),
                              fill=TEXT_SECONDARY, font=(FONT_MONO, FS_NANO), anchor="s")
            # x tick (bin center %)
            if b % max(1, n_bins // 5) == 0:
                c.create_text((x0 + x1) / 2, H - 8, text=f"{centers[b]:+.0f}%",
                              fill=TEXT_MUTED, font=(FONT_FAMILY, FS_NANO))

    # ---- Stats helpers ---------------------------------------------------

    def _stats_ticker_lookup(self) -> None:
        """Fetch and display current price for the ticker in the search box."""
        ticker = self._stats_search.get().strip().upper()
        if not ticker:
            return
        self._stats_price_lbl.configure(text="...", fg=TEXT_MUTED)

        def _worker():
            price = self._fetch_market_price(ticker)
            if price is not None:
                self.after(0, lambda: self._stats_price_lbl.configure(
                    text=f"${price:.4f}", fg=GREEN))
            else:
                self.after(0, lambda: self._stats_price_lbl.configure(
                    text="not found", fg=RED))

        threading.Thread(target=_worker, daemon=True).start()

    # ---- Stats refresh ---------------------------------------------------

    def _refresh_stats(self) -> None:
        # Split-adjusted, for the same reason as the Command Center hero: every
        # figure below subtracts a buy price from a sell price, and a reverse
        # split silently puts those two in different units. The recent-trades
        # table further down re-reads the executed fill off each row, because a
        # history has to show what actually happened at the broker.
        all_trades = trade_journal.split_adjusted()

        # Filter by ticker search
        search_q = ""
        if hasattr(self, "_stats_search"):
            search_q = self._stats_search.get().strip().upper()
        if search_q:
            all_trades = [t for t in all_trades if search_q in t["symbol"].upper()]

        # Filter by selected period
        period = self._stats_period.get() if hasattr(self, "_stats_period") else "all"
        now = datetime.now()
        if period == "week":
            # Monday of this week
            start = now - __import__("datetime").timedelta(days=now.weekday())
            start = start.replace(hour=0, minute=0, second=0, microsecond=0)
            trades = [t for t in all_trades if t.get("timestamp", "") >= start.isoformat()]
        elif period == "month":
            start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            trades = [t for t in all_trades if t.get("timestamp", "") >= start.isoformat()]
        elif period == "last_month":
            this_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            if now.month == 1:
                last_month_start = this_month_start.replace(year=now.year - 1, month=12)
            else:
                last_month_start = this_month_start.replace(month=now.month - 1)
            trades = [t for t in all_trades if last_month_start.isoformat() <= t.get("timestamp", "") < this_month_start.isoformat()]
        elif period == "year":
            start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            trades = [t for t in all_trades if t.get("timestamp", "") >= start.isoformat()]
        else:
            trades = all_trades

        # ---- Compute all data first ----
        total = len(trades)
        buys = [t for t in trades if t["side"] == "buy"]
        sells = [t for t in trades if t["side"] == "sell"]
        symbols = set(t["symbol"] for t in trades)
        brokers_used = set(t["broker"] for t in trades)
        accounts_used = set((t["broker"], t["account_id"]) for t in trades)

        total_shares = sum(t["qty"] for t in trades)
        total_volume = sum((t["fill_price"] or 0) * t["qty"] for t in trades)
        avg_trade = total_volume / total if total else 0

        # ---- Per-symbol analysis (period-filtered for display) ----
        sym_data: Dict[str, Dict] = {}
        for t in trades:
            s = t["symbol"]
            d = sym_data.setdefault(s, {
                "trades": 0, "bought": 0.0, "sold": 0.0,
                "buy_cost": 0.0, "sell_rev": 0.0})
            d["trades"] += 1
            price = t["fill_price"] or 0
            if t["side"] == "buy":
                d["bought"] += t["qty"]
                d["buy_cost"] += price * t["qty"]
            elif t["side"] == "sell":
                # elif, not else: a "close" is a position that dissolved (cash
                # in lieu at a broker that holds no fractions), and counting it
                # as a sale would invent proceeds nobody received — then divide
                # them into avg_s and report the result as realized profit.
                d["sold"] += t["qty"]
                d["sell_rev"] += price * t["qty"]

        # ---- All-time cost basis (needed for P/L when buys predate the period) ----
        alltime_buy: Dict[str, Dict] = {}
        for t in all_trades:
            if t["side"] != "buy":
                continue
            s = t["symbol"]
            ab = alltime_buy.setdefault(s, {"qty": 0.0, "cost": 0.0})
            ab["qty"] += t["qty"]
            ab["cost"] += (t["fill_price"] or 0) * t["qty"]

        # ---- Win/loss / P/L analysis ----
        # Use all-time avg buy price as cost basis, but only count sells in
        # the current period as realized P/L for that period.
        realized_pl = 0.0
        wins = 0
        losses = 0
        best = 0.0
        worst = 0.0
        closed_list = []

        # Gather all symbols that had sells in the period
        period_sold_syms = {t["symbol"] for t in trades if t["side"] == "sell"}
        for sym in period_sold_syms:
            ab = alltime_buy.get(sym)
            if not ab or not ab["qty"]:
                continue
            avg_b = ab["cost"] / ab["qty"]
            sd = sym_data.get(sym, {})
            sold_qty = sd.get("sold", 0)
            sell_rev = sd.get("sell_rev", 0)
            if not sold_qty:
                continue
            avg_s = sell_rev / sold_qty
            cost_basis = avg_b * sold_qty
            revenue = sell_rev
            profit = revenue - cost_basis
            ret_pct = (profit / cost_basis * 100) if cost_basis else 0
            realized_pl += profit
            # Build display dict merging alltime buys with period sells
            display_d = dict(sd)
            display_d["bought"] = sd.get("bought", 0) or ab["qty"]
            display_d["buy_cost"] = sd.get("buy_cost", 0) or ab["cost"]
            closed_list.append((sym, display_d, profit, ret_pct, cost_basis, revenue, avg_b, avg_s))
            if profit > 0:
                wins += 1
                best = max(best, profit)
            elif profit < 0:
                losses += 1
                worst = min(worst, profit)

        # What the figure above cannot see. Computed from the same two maps the
        # P/L loop just used, so it can never disagree with the number it
        # qualifies.
        self._render_coverage(period_sold_syms, alltime_buy, sym_data, all_trades)

        closed_count = wins + losses
        win_rate = (wins / closed_count * 100) if closed_count > 0 else 0
        grand_cost = sum(c[4] for c in closed_list)
        grand_ret = (realized_pl / grand_cost * 100) if grand_cost else 0
        avg_ret_per = grand_ret / closed_count if closed_count else 0

        # ---- Advanced / risk metrics (per closed-symbol sample) ----
        import statistics
        profits = [c[2] for c in closed_list]
        rets = [c[3] for c in closed_list]
        win_p = [p for p in profits if p > 0]
        loss_p = [p for p in profits if p < 0]
        gross_profit = sum(win_p)
        gross_loss = -sum(loss_p)  # positive magnitude
        profit_factor = (gross_profit / gross_loss) if gross_loss else (gross_profit and float("inf"))
        avg_win = (gross_profit / len(win_p)) if win_p else 0.0
        avg_loss = (sum(loss_p) / len(loss_p)) if loss_p else 0.0  # negative
        payoff = (avg_win / abs(avg_loss)) if avg_loss else (avg_win and float("inf"))
        expectancy = (realized_pl / closed_count) if closed_count else 0.0
        if len(rets) >= 2 and statistics.pstdev(rets) > 1e-9:
            consistency = statistics.mean(rets) / statistics.pstdev(rets)
        else:
            consistency = 0.0

        # ---- Realized P/L by date (drawdown) and by month ----
        daily_real: Dict[str, float] = {}
        monthly_pl: Dict[str, float] = {}
        for t in trades:
            if t["side"] != "sell":
                continue
            ab = alltime_buy.get(t["symbol"])
            if not ab or not ab["qty"]:
                continue
            avg_b = ab["cost"] / ab["qty"]
            pl = ((t["fill_price"] or 0) - avg_b) * t["qty"]
            ts = t.get("timestamp", "")
            daily_real[ts[:10]] = daily_real.get(ts[:10], 0.0) + pl
            monthly_pl[ts[:7]] = monthly_pl.get(ts[:7], 0.0) + pl

        # Max drawdown from the cumulative realized equity curve
        cum_eq = 0.0
        peak_eq = 0.0
        max_dd = 0.0
        for d in sorted(daily_real):
            cum_eq += daily_real[d]
            peak_eq = max(peak_eq, cum_eq)
            max_dd = min(max_dd, cum_eq - peak_eq)

        # ---- Per-broker data ----
        broker_data: Dict[str, Dict] = {}
        # Per-broker per-symbol tracking for period sells
        broker_sym_sells: Dict[str, Dict[str, Dict]] = {}
        for t in trades:
            b = t["broker"]
            d = broker_data.setdefault(b, {"trades": 0, "buys": 0, "sells": 0, "volume": 0.0})
            d["trades"] += 1
            price = t["fill_price"] or 0
            if t["side"] == "buy":
                d["buys"] += 1
            elif t["side"] == "sell":
                d["sells"] += 1
                bs = broker_sym_sells.setdefault(b, {})
                sd = bs.setdefault(t["symbol"], {"sold": 0.0, "sell_rev": 0.0})
                sd["sold"] += t["qty"]
                sd["sell_rev"] += price * t["qty"]
            d["volume"] += price * t["qty"]

        # All-time per-broker per-symbol buy cost (for P/L)
        alltime_broker_buy: Dict[str, Dict[str, Dict]] = {}
        for t in all_trades:
            if t["side"] != "buy":
                continue
            b = t["broker"]
            bs = alltime_broker_buy.setdefault(b, {})
            sd = bs.setdefault(t["symbol"], {"bought": 0.0, "buy_cost": 0.0})
            sd["bought"] += t["qty"]
            sd["buy_cost"] += (t["fill_price"] or 0) * t["qty"]

        # ---- Daily realized P/L, split by the broker that produced it -------
        #
        # Priced per (broker, symbol), NOT off the symbol-wide average. Where a
        # play was bought is where it was priced, and the same name routinely
        # costs different amounts at different brokers — ARTL was $1.20 at
        # Fidelity and $1.2299 at Robinhood. Using one blended figure would
        # quietly move profit between brokers on this very breakdown.
        #
        # A close contributes nothing: a dissolved position was never sold, so
        # attributing a day's profit to it would be inventing money.
        daily_pl: Dict[str, Dict[str, float]] = {}
        daily_sells: Dict[str, int] = {}
        for t in trades:
            if t["side"] != "sell":
                continue
            day = (t.get("timestamp") or "")[:10]
            if not day:
                continue
            ab = alltime_broker_buy.get(t["broker"], {}).get(t["symbol"])
            if not ab or not ab["bought"]:
                continue          # no basis at this broker: cannot be priced
            avg_b = ab["buy_cost"] / ab["bought"]
            profit = ((t["fill_price"] or 0) - avg_b) * t["qty"]
            daily_pl.setdefault(day, {})
            daily_pl[day][t["broker"]] = daily_pl[day].get(t["broker"], 0.0) + profit
            daily_sells[day] = daily_sells.get(day, 0) + 1

        self._chart_daily_pl = daily_pl
        self._draw_daily_pl(daily_pl)

        self._daily_pl_tree.delete(*self._daily_pl_tree.get_children())
        for day in sorted(daily_pl, reverse=True)[:40]:
            per = daily_pl[day]
            tot = sum(per.values())
            where = "   ".join(
                f"{b.capitalize()} {v:+,.2f}"
                for b, v in sorted(per.items(), key=lambda kv: -abs(kv[1])))
            self._daily_pl_tree.insert("", "end", values=(
                day, f"${tot:+,.2f}", where, daily_sells.get(day, 0)),
                tags=("win" if tot > 0 else "loss" if tot < 0 else "",))
        if daily_pl:
            best_day = max(daily_pl, key=lambda d: sum(daily_pl[d].values()))
            self._daily_pl_sub.configure(
                text=f"{len(daily_pl)} trading days   ·   best "
                     f"${sum(daily_pl[best_day].values()):+,.2f} on {best_day}")
        else:
            self._daily_pl_sub.configure(text="")

        # ================================================================
        # UPDATE HERO CARD
        # ================================================================
        pl_color = GREEN if realized_pl >= 0 else RED
        self._hero_pl.configure(text=f"${realized_pl:+,.2f}", fg=pl_color)
        sub_parts = []
        if grand_ret:
            sub_parts.append(f"{grand_ret:+,.1f}% return")
        sub_parts.append(f"{closed_count} closed trade{'s' if closed_count != 1 else ''}")
        sub_parts.append(f"{wins}W / {losses}L")
        self._hero_pl_sub.configure(text="  |  ".join(sub_parts))

        wr_color = GREEN if win_rate >= 50 else RED if closed_count > 0 else TEXT_PRIMARY
        self._hero_win_rate.configure(text=f"{win_rate:.0f}%", fg=wr_color)
        self._hero_best.configure(
            text=f"${best:+,.2f}" if best != 0 else "—",
            fg=GREEN if best > 0 else TEXT_PRIMARY)
        self._hero_worst.configure(
            text=f"${worst:+,.2f}" if worst != 0 else "—",
            fg=RED if worst < 0 else TEXT_PRIMARY)
        self._hero_trades.configure(text=str(total))
        self._hero_volume.configure(text=f"${total_volume:,.0f}")
        self._hero_avg_return.configure(
            text=f"{avg_ret_per:+,.1f}%" if closed_count else "—",
            fg=GREEN if avg_ret_per > 0 else RED if avg_ret_per < 0 else TEXT_PRIMARY)

        # ================================================================
        # RISK & PERFORMANCE METRIC TILES
        # ================================================================
        def _inf(x):
            return x == float("inf")

        if closed_count:
            self._adv_profit_factor.configure(
                text="∞" if _inf(profit_factor) else f"{profit_factor:.2f}",
                fg=GREEN if (profit_factor == float("inf") or profit_factor >= 1) else RED)
            self._adv_expectancy.configure(
                text=f"${expectancy:+,.2f}",
                fg=GREEN if expectancy > 0 else RED if expectancy < 0 else TEXT_PRIMARY)
            self._adv_payoff.configure(
                text="∞" if _inf(payoff) else (f"{payoff:.2f}" if payoff else "—"),
                fg=TEXT_PRIMARY)
            self._adv_max_dd.configure(
                text=f"${max_dd:,.2f}" if max_dd < 0 else "$0.00",
                fg=RED if max_dd < 0 else TEXT_PRIMARY)
            self._adv_wl.configure(text=f"{wins} / {losses}",
                                   fg=GREEN if wins >= losses else RED)
            self._adv_consistency.configure(
                text=f"{consistency:.2f}" if len(rets) >= 2 else "—",
                fg=GREEN if consistency > 0 else RED if consistency < 0 else TEXT_PRIMARY)
        else:
            for lbl in (self._adv_profit_factor, self._adv_expectancy,
                        self._adv_payoff, self._adv_max_dd, self._adv_wl,
                        self._adv_consistency):
                lbl.configure(text="—", fg=TEXT_PRIMARY)
        self._adv_avg_win.configure(
            text=f"${avg_win:,.2f}" if win_p else "—",
            fg=GREEN if win_p else TEXT_PRIMARY)
        self._adv_avg_loss.configure(
            text=f"${avg_loss:,.2f}" if loss_p else "—",
            fg=RED if loss_p else TEXT_PRIMARY)

        # ================================================================
        # DRAW CHARTS — cache data for resize redraws
        # ================================================================
        self._chart_all_trades = all_trades
        self._chart_trades = trades
        self._chart_sym_data = sym_data
        self._chart_broker_data = broker_data
        self._chart_monthly = monthly_pl
        self._chart_returns = rets
        # Defer drawing slightly so canvases have real dimensions
        self.after(50, self._redraw_charts)

        # ================================================================
        # CLOSED TRADES TABLE
        # ================================================================
        self._closed_trades_tree.delete(*self._closed_trades_tree.get_children())
        self._closed_trades_tree.tag_configure("win", foreground=GREEN)
        self._closed_trades_tree.tag_configure("loss", foreground=RED)

        closed_list.sort(key=lambda x: x[2], reverse=True)
        for sym, d, profit, ret_pct, cost_basis, revenue, avg_b, avg_s in closed_list:
            tag = "win" if profit >= 0 else "loss"
            self._closed_trades_tree.insert("", "end", values=(
                sym,
                f"{d['sold']:,.0f}",
                f"${avg_b:,.4f}",
                f"${avg_s:,.4f}",
                f"${cost_basis:,.2f}",
                f"${revenue:,.2f}",
                f"${profit:+,.2f}",
                f"{ret_pct:+,.1f}%"),
                tags=(tag,))

        self._closed_total_label.configure(
            text=f"${realized_pl:+,.2f}  ({grand_ret:+,.1f}%)",
            fg=pl_color)

        # ================================================================
        # TRADE SUMMARY
        # ================================================================
        self._stat_buys.configure(text=str(len(buys)))
        self._stat_sells.configure(text=str(len(sells)))
        self._stat_symbols.configure(text=str(len(symbols)))
        self._stat_brokers_used.configure(text=str(len(brokers_used)))
        self._stat_accounts_used.configure(text=str(len(accounts_used)))
        self._stat_shares.configure(text=f"{total_shares:,.0f}")
        self._stat_volume.configure(text=f"${total_volume:,.2f}")
        self._stat_avg_trade.configure(text=f"${avg_trade:,.2f}")

        # ================================================================
        # PER-BROKER TABLE (now with P/L column)
        # ================================================================
        self._broker_stats_tree.delete(*self._broker_stats_tree.get_children())
        self._broker_stats_tree.tag_configure("win", foreground=GREEN)
        self._broker_stats_tree.tag_configure("loss", foreground=RED)
        for b in sorted(broker_data):
            d = broker_data[b]
            avg = d["volume"] / d["trades"] if d["trades"] else 0
            # Broker P/L: for each symbol sold in this period, use all-time buy cost
            b_pl = 0.0
            has_closed = False
            for sym, sell_d in broker_sym_sells.get(b, {}).items():
                buy_d = alltime_broker_buy.get(b, {}).get(sym)
                if buy_d and buy_d["bought"]:
                    avg_b = buy_d["buy_cost"] / buy_d["bought"]
                    b_pl += sell_d["sell_rev"] - avg_b * sell_d["sold"]
                    has_closed = True
            pl_str = f"${b_pl:+,.2f}" if has_closed else "—"
            tag = "win" if b_pl > 0 else "loss" if b_pl < 0 else ""
            self._broker_stats_tree.insert("", "end", values=(
                b.capitalize(), d["trades"], d["buys"], d["sells"],
                f"${d['volume']:,.2f}", f"${avg:,.2f}", pl_str),
                tags=(tag,) if tag else ())

        # ================================================================
        # SYMBOL PERFORMANCE TABLE
        # ================================================================
        self._symbol_stats_tree.delete(*self._symbol_stats_tree.get_children())
        self._symbol_stats_tree.tag_configure("win", foreground=GREEN)
        self._symbol_stats_tree.tag_configure("loss", foreground=RED)
        for s in sorted(sym_data):
            d = sym_data[s]
            avg_b = d["buy_cost"] / d["bought"] if d["bought"] else 0
            avg_s = d["sell_rev"] / d["sold"] if d["sold"] else 0
            net = d["bought"] - d["sold"]
            pl = d["sell_rev"] - (avg_b * d["sold"]) if d["sold"] and d["bought"] else 0
            pl_str = f"${pl:+,.2f}" if d["sold"] and d["bought"] else "—"
            tag = "win" if pl > 0 else "loss" if pl < 0 else ""
            self._symbol_stats_tree.insert("", "end", values=(
                s, d["trades"],
                f"{d['bought']:,.0f}", f"{d['sold']:,.0f}",
                f"${avg_b:,.4f}" if avg_b else "—",
                f"${avg_s:,.4f}" if avg_s else "—",
                f"{net:,.0f}",
                pl_str),
                tags=(tag,) if tag else ())

        # ================================================================
        # RECENT TRADES TABLE
        # ================================================================
        self._recent_trades_tree.delete(*self._recent_trades_tree.get_children())
        for t in reversed(trades[-100:]):
            ts = t.get("timestamp", "")[:19].replace("T", " ")
            # The FILL, not the split-adjusted restatement the P/L above needs.
            # This table is a record of what happened at the broker; showing
            # "1.0 @ $1.00" for an order that really sold 0.1 @ $10.00 would be
            # a nicer number and a false one.
            qty = t.get("executed_qty", t["qty"])
            price = t.get("executed_price", t["fill_price"])
            total_val = (price or 0) * qty
            side_tag = t["side"].upper()
            # ,.0f rounded a 0.1-share split remnant to "0". Whole shares still
            # print whole; only a fraction spends the two decimals.
            qty_str = f"{qty:,.0f}" if abs(qty - round(qty)) < 1e-9 else f"{qty:,.2f}"
            self._recent_trades_tree.insert("", "end", values=(
                ts,
                t["broker"].capitalize(),
                t.get("account_id", ""),
                side_tag,
                t["symbol"],
                qty_str,
                f"${price:,.4f}" if price else "\u2014",
                f"${total_val:,.2f}"),
                tags=(t["side"],))

        self._recent_trades_tree.tag_configure("buy", foreground=GREEN)
        self._recent_trades_tree.tag_configure("sell", foreground=RED)

        self._log("Stats: refreshed")

    def _render_coverage(self, sold_syms, alltime_buy, sym_data, all_trades) -> None:
        """Say out loud what the realized figure excludes, or hide entirely.

        Three faults, and they do NOT all push the same way, which is why they
        are listed separately rather than summed into one apology:

          no recorded buy    the symbol is skipped outright, so real proceeds
                             are missing from the total. UNDERSTATES.
          buys with no price   cost divides out to zero and the whole of the
                             proceeds books as profit. OVERSTATES.
          some buys unpriced   cost is summed over the priced ones and divided
                             by all of them, so the average is too low and the
                             profit too high. OVERSTATES, invisibly — the
                             symbol is present and nothing looks wrong.
        """
        if not hasattr(self, "_cov_lines"):
            return
        for w in self._cov_lines.winfo_children():
            w.destroy()

        no_buy, no_price, partial = {}, {}, {}
        for sym in sold_syms:
            ab = alltime_buy.get(sym)
            rev = (sym_data.get(sym) or {}).get("sell_rev", 0.0)
            if not ab or not ab["qty"]:
                no_buy[sym] = rev
            elif ab["cost"] <= 0:
                no_price[sym] = rev
            else:
                nulls = sum(1 for t in all_trades
                            if t["symbol"] == sym and t["side"] == "buy"
                            and t.get("fill_price") is None)
                if nulls:
                    total = sum(1 for t in all_trades
                                if t["symbol"] == sym and t["side"] == "buy")
                    partial[sym] = (nulls, total)

        estimated = sum(1 for t in all_trades if trade_journal.is_estimated(t))

        rows = []
        if no_buy:
            rows.append((RED,
                         f"${sum(no_buy.values()):,.2f} of sales are missing from this "
                         f"total — no buy was ever recorded for "
                         f"{', '.join(sorted(no_buy))}, so there is no cost to subtract."))
        if no_price:
            rows.append((YELLOW,
                         f"${sum(no_price.values()):,.2f} counts as pure profit — every "
                         f"recorded buy of {', '.join(sorted(no_price))} has no fill "
                         f"price, so its cost works out to $0.00."))
        if partial:
            detail = ", ".join(f"{s} ({n} of {t})" for s, (n, t) in sorted(partial.items()))
            rows.append((YELLOW,
                         f"Cost basis is understated where some buys carry no price: "
                         f"{detail}. Those symbols look more profitable than they were."))
        if estimated:
            rows.append((TEXT_MUTED,
                         f"{estimated:,} of {len(all_trades):,} trades are priced from a "
                         f"market QUOTE, not an executed fill — one lookup per batch, "
                         f"stamped onto every account. Treat every figure here as an "
                         f"estimate until brokers report real fills."))

        if not rows:
            self._cov_card.pack_forget()
            return

        # Dismissal is remembered against the WORDING of these warnings, not as
        # a plain "hidden" flag. Hiding it forever would be the one failure this
        # card exists to prevent: a total that overstates itself with nothing on
        # screen admitting it. Sell a new symbol with no recorded buy and the
        # fingerprint changes, so the card comes back unread.
        self._cov_fingerprint = _coverage_fingerprint(rows)
        if self._cov_fingerprint == _load_coverage_read():
            self._cov_card.pack_forget()
            return

        for colour, text in rows:
            tk.Label(self._cov_lines, text="•  " + text, bg=BG_CARD, fg=colour,
                     font=(FONT_FAMILY, 9), justify="left", anchor="w",
                     wraplength=820).pack(fill="x", pady=(0, 5))
        # Directly under the hero it qualifies and above everything derived from
        # it. `before` a widget captured at build time, not an index into a
        # child list that changes — pack() on its own would append it to the
        # bottom of the page, four cards away from the number it is about.
        if getattr(self, "_cov_before", None) is not None:
            self._cov_card.pack(fill="x", pady=(0, 14), before=self._cov_before)
        else:
            self._cov_card.pack(fill="x", pady=(0, 14))

    def _mark_coverage_read(self) -> None:
        """Acknowledge the coverage warnings currently on screen."""
        fingerprint = getattr(self, "_cov_fingerprint", "")
        if not fingerprint:
            return
        _save_coverage_read(fingerprint)
        self._cov_card.pack_forget()
        self._show_toast("Marked as read — it returns if these figures change.",
                         "info")

    # ---- Simulator --------------------------------------------------------

    def _sim_fetch_price(self) -> None:
        """Fetch current price for the ticker using Yahoo Finance CSV endpoint."""
        ticker = self._sim_ticker.get().strip().upper()
        if not ticker:
            return

        def _worker():
            try:
                url = f"https://query1.finance.yahoo.com/v8/finance/chart/{ticker}?range=1d&interval=1d"
                req = urllib.request.Request(url, headers={"User-Agent": "RSAMAXXED/1.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    import json
                    data = json.loads(resp.read().decode())
                    price = data["chart"]["result"][0]["meta"]["regularMarketPrice"]
                    self.after(0, lambda: self._sim_set_price(price))
            except Exception as ex:
                self.after(0, lambda: self._sim_result.configure(
                    text=f"Could not fetch price for {ticker}: {ex}", fg=RED))

        threading.Thread(target=_worker, daemon=True).start()

    def _sim_set_price(self, price: float) -> None:
        self._sim_buy_price.delete(0, "end")
        self._sim_buy_price.insert(0, f"{price:.4f}")
        self._sim_result.configure(text=f"Price fetched: ${price:.4f}", fg=TEXT_PRIMARY)

    def _sim_calculate(self) -> None:
        """Calculate theoretical profit from a round-trip trade."""
        try:
            buy = float(self._sim_buy_price.get().strip())
            sell = float(self._sim_sell_price.get().strip())
            qty = float(self._sim_qty.get().strip())
            accts = int(self._sim_accounts.get().strip())
        except (ValueError, AttributeError):
            self._sim_result.configure(text="Fill in all fields with valid numbers.", fg=RED)
            return

        total_shares = qty * accts
        cost = buy * total_shares
        revenue = sell * total_shares
        profit = revenue - cost
        pct = (profit / cost * 100) if cost else 0

        lines = [
            f"Accounts: {accts}   |   Shares/acct: {qty:,.0f}   |   Total shares: {total_shares:,.0f}",
            f"Buy  @ ${buy:.4f}  =  ${cost:,.2f}",
            f"Sell @ ${sell:.4f}  =  ${revenue:,.2f}",
            f"",
            f"Profit: ${profit:+,.2f}  ({pct:+.1f}%)",
        ]
        color = GREEN if profit >= 0 else RED
        self._sim_result.configure(text="\n".join(lines), fg=color)

    # ---- Settings / Mirror Trading -----------------------------------------

    def _load_mirror_state(self) -> Dict[str, Any]:
        """Load mirror trading state from disk."""
        import json
        if MIRROR_STATE_FILE.exists():
            try:
                return json.loads(MIRROR_STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"enabled": False, "brokers": [], "executed": [],
                "last_slot": "", "failed": []}

    def _repair_mirror_executed(self) -> None:
        """One-shot: drop 'executed' entries that were never actually executed.

        Every earlier enable stamped the whole feed as executed, so saved state
        can hold fresh picks that were never bought and can never be bought —
        the switch that was supposed to buy them is what buried them. Release a
        key only when all three are true, which pins it to that bug and nothing
        else:

          * mirror never opened a run for it (mirror_runs.json) — so this is not
            a run that died mid-fan-out after real orders went out,
          * it is not in `failed` — those filled nowhere and are deliberately
            never retried,
          * the journal shows no buy and the pick is still fresh.

        Runs once, the first time the pick feed lands.
        """
        if getattr(self, "_mirror_repaired", True):
            return
        self._mirror_repaired = True
        if not getattr(self, "_mirror_executed", None):
            return
        try:
            picks = list(self._quick_picks or [])
            bought = self._mirror_bought_keys(picks)
            attempted = {(str(r.get("symbol") or "").upper(),
                          str(r.get("pick_date") or ""))
                         for r in mirror_journal.runs()}
            fresh_unbought = {
                self._mirror_key(p) for p in picks
                if str(p.get("note", "")).lower() in MIRROR_NOTES
                and _pick_is_fresh(p)
                and self._mirror_journal_key(p) not in bought
                and self._mirror_journal_key(p) not in attempted}
        except Exception:
            return
        stale = {k for k in self._mirror_executed
                 if k in fresh_unbought and k not in self._mirror_failed}
        if not stale:
            return
        self._mirror_executed -= stale
        self._save_mirror_state()
        syms = ", ".join(sorted(k[1] for k in stale))
        self._log(f"Mirror: released {len(stale)} pick(s) marked executed but "
                  f"never bought — {syms}")

    def _save_mirror_state(self) -> None:
        """Persist mirror trading state to disk."""
        import json
        state = {
            "enabled": self._mirror_enabled.get(),
            "brokers": list(self._mirror_selected_brokers),
            "executed": list(self._mirror_executed),
            # Which scheduled check last ran, so restarting the app mid-session
            # doesn't re-run a slot that already fired today.
            "last_slot": self._mirror_last_slot,
            "failed": [list(k) for k in self._mirror_failed],
        }
        MIRROR_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def _build_settings(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["settings"] = frame

        # Scrollable
        canvas = tk.Canvas(frame, bg=BG_PRIMARY, bd=0, highlightthickness=0)
        scroll_frame = tk.Frame(canvas, bg=BG_PRIMARY)
        scroll_frame.bind("<Configure>",
                          lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        cw = canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(cw, width=e.width))
        canvas.pack(fill="both", expand=True)

        def _settings_mw(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        frame.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", _settings_mw))
        frame.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

        # ---- Mirror Trading Card ----
        mirror_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        mirror_card.pack(fill="x", pady=(0, 16))

        # Header
        mirror_header = tk.Frame(mirror_card.inner, bg=BG_CARD)
        mirror_header.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(mirror_header, text=icon("automation"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 13)).pack(side="left", padx=(0, 9))
        tk.Label(mirror_header, text="Mirror Trading", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 14, "bold")).pack(side="left")

        # Load saved state
        saved = self._load_mirror_state()
        self._mirror_enabled = tk.BooleanVar(value=False)  # always start OFF
        self._mirror_selected_brokers: set = set(saved.get("brokers", []))
        self._mirror_executed: set = set(
            tuple(x) if isinstance(x, list) else x
            for x in saved.get("executed", []))
        self._mirror_poll_id: Optional[str] = None
        self._mirror_last_slot: str = str(saved.get("last_slot", "") or "")
        self._mirror_failed: set = set(
            tuple(x) if isinstance(x, list) else x
            for x in saved.get("failed", []))
        # Repaired once the picks actually land — see _render_quick_picks. The
        # feed is still empty at build time.
        self._mirror_repaired = False

        # Status indicator
        self._mirror_status_frame = tk.Frame(mirror_header, bg=BG_CARD)
        self._mirror_status_frame.pack(side="right")
        self._mirror_status_dot = StatusDot(self._mirror_status_frame, color=RED, size=8)
        self._mirror_status_dot.pack(side="left", padx=(0, 6))
        self._mirror_status_lbl = tk.Label(self._mirror_status_frame, text="OFF",
                                           bg=BG_CARD, fg=RED, font=(FONT_FAMILY, 9, "bold"))
        self._mirror_status_lbl.pack(side="left")

        # Safety explanation
        safety_card = tk.Frame(mirror_card.inner, bg=BG_INPUT, padx=16, pady=12)
        safety_card.pack(fill="x", padx=20, pady=(4, 12))

        tk.Label(safety_card, text="What is Mirror Trading?", bg=BG_INPUT, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 10, "bold")).pack(anchor="w", pady=(0, 6))

        explanation = (
            "Mirror Trading automatically executes BUY orders when new Quick Picks "
            "appear. It monitors the picks list every 60 seconds and places trades "
            "on your selected brokers.\n"
        )
        tk.Label(safety_card, text=explanation, bg=BG_INPUT, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9), wraplength=600, justify="left").pack(anchor="w")

        tk.Label(safety_card, text="Safety Measures:", bg=BG_INPUT, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(anchor="w", pady=(6, 4))

        safety_points = [
            "\u2713  Only executes on \"Reg Alert\" picks — skips OTC, conditional, and custom notes",
            "\u2713  Always buys exactly 1 share per account — never more",
            "\u2713  BUY only — will never auto-sell your positions",
            "\u2713  Each pick is only executed once — duplicates are tracked and skipped",
            "\u2713  Only runs on brokers YOU select below",
            "\u2713  Checks every 60 seconds — does not rapid-fire",
            "\u2713  Stops immediately when toggled off",
            "\u2713  All auto-trades are logged and appear in your trade journal",
        ]
        for point in safety_points:
            tk.Label(safety_card, text=point, bg=BG_INPUT, fg=GREEN,
                     font=(FONT_FAMILY, 8), anchor="w").pack(anchor="w", pady=1)

        tk.Label(safety_card, text="\nYou can disable Mirror Trading at any time. "
                 "It will NOT execute trades for picks that existed before you turned it on.",
                 bg=BG_INPUT, fg=TEXT_MUTED, font=(FONT_FAMILY, 8),
                 wraplength=600, justify="left").pack(anchor="w")

        # Broker selection for mirror trading
        broker_section = tk.Frame(mirror_card.inner, bg=BG_CARD)
        broker_section.pack(fill="x", padx=20, pady=(0, 12))

        tk.Label(broker_section, text="BROKERS TO MIRROR ON", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(anchor="w", pady=(0, 6))

        self._mirror_broker_chips: Dict[str, Dict[str, Any]] = {}
        mirror_chips_frame = tk.Frame(broker_section, bg=BG_CARD)
        mirror_chips_frame.pack(anchor="w")

        linked_brokers = sorted([b for b in BROKER_MODULES if _broker_has_creds(b)])
        chip_row = tk.Frame(mirror_chips_frame, bg=BG_CARD)
        chip_row.pack(anchor="w")

        for idx, broker in enumerate(linked_brokers):
            if idx > 0 and idx % 5 == 0:
                chip_row = tk.Frame(mirror_chips_frame, bg=BG_CARD)
                chip_row.pack(anchor="w", pady=(2, 0))

            is_selected = broker in self._mirror_selected_brokers
            chip = self._make_chip(chip_row, broker.capitalize(),
                                   lambda b=broker: self._toggle_mirror_broker(b),
                                   selected=is_selected)
            chip.pack(side="left", padx=(0, 6), pady=2)
            self._mirror_broker_chips[broker] = {"label": chip, "selected": is_selected}

        # Activity log for mirror trading
        activity_section = tk.Frame(mirror_card.inner, bg=BG_CARD)
        activity_section.pack(fill="x", padx=20, pady=(0, 12))

        tk.Label(activity_section, text="MIRROR ACTIVITY", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(anchor="w", pady=(0, 6))

        self._mirror_log = tk.Text(activity_section, bg=BG_INPUT, fg=TEXT_PRIMARY,
                                   font=(FONT_MONO, 9), height=6, bd=0,
                                   state="disabled", insertbackground=TEXT_PRIMARY,
                                   highlightthickness=0, padx=8, pady=8)
        self._mirror_log.pack(fill="x")

        # Picks that filled on NO broker. Mirror never retries (a second pass
        # would double-buy the accounts that did fill), so without this they
        # would just disappear from the log and never be dealt with.
        self._mirror_failed_frame = tk.Frame(mirror_card.inner, bg=BG_CARD)
        self._mirror_failed_frame.pack(fill="x", padx=20)
        self._render_mirror_failed()

        # Toggle button
        toggle_frame = tk.Frame(mirror_card.inner, bg=BG_CARD)
        toggle_frame.pack(fill="x", padx=20, pady=(4, 20))

        self._mirror_toggle_btn = PillButton(
            toggle_frame, text="Enable Mirror Trading",
            command=self._toggle_mirror_trading,
            width=200, height=40, font_size=11)
        self._mirror_toggle_btn.pack(side="left")

        # Executed picks count
        count = len(self._mirror_executed)
        self._mirror_exec_count = tk.Label(
            toggle_frame, text=f"{count} pick(s) already executed",
            bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 8))
        self._mirror_exec_count.pack(side="left", padx=(16, 0))

        # ---- Discord auto-import card (feeds the picks Mirror Trading buys) ----
        self._build_discord_card(scroll_frame)

        # Account linking now lives on the Brokers page — see _build_accounts.

    # ---- RSAMAXXED Cloud sync ---------------------------------------------------

    def _build_cloud_card(self, parent) -> None:
        """Pair this machine with an RSAMAXXED account. This is how the play
        feed reaches the terminal — buys, exits and the round-up board — as well
        as how the trade journal reaches the website."""
        self._cloud_pending = None          # PendingPair while a code is live
        self._cloud_poll_stop = threading.Event()

        card = RoundedFrame(parent, bg_color=BG_CARD, border_color=BORDER, radius=14)
        card.pack(fill="x", pady=(0, 16))

        header = tk.Frame(card.inner, bg=BG_CARD)
        header.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(header, text=icon("globe"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 13)).pack(side="left", padx=(0, 9))
        tk.Label(header, text="RSAMAXXED Cloud", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 14, "bold")).pack(side="left")
        status_wrap = tk.Frame(header, bg=BG_CARD)
        status_wrap.pack(side="right")
        self._cloud_dot = StatusDot(status_wrap, color=RED, size=8)
        self._cloud_dot.pack(side="left", padx=(0, 6))
        self._cloud_status_lbl = tk.Label(status_wrap, text="NOT LINKED", bg=BG_CARD,
                                          fg=RED, font=(FONT_FAMILY, 9, "bold"))
        self._cloud_status_lbl.pack(side="left")

        info = tk.Frame(card.inner, bg=BG_INPUT, padx=16, pady=12)
        info.pack(fill="x", padx=20, pady=(4, 12))
        # Be precise about what this does and does NOT gate. The plays arrive
        # without it — claiming otherwise sends people hunting for an account
        # they don't need when their Watchlist looks empty.
        tk.Label(info, text="Optional — your plays already work without this",
                 bg=BG_INPUT, fg=TEXT_PRIMARY, font=(FONT_FAMILY, 10, "bold")).pack(anchor="w")
        tk.Label(info, text="Buy alerts, exits and the round-up board arrive on their own, "
                 "refreshed every hour, with no account and no Discord. Linking is only for "
                 "seeing your realized P/L, positions and trade history on the website — handy "
                 "from your phone, and nothing else depends on it. Broker logins, cookies and "
                 "2FA secrets never leave this computer.",
                 bg=BG_INPUT, fg=TEXT_SECONDARY, font=(FONT_FAMILY, 9),
                 wraplength=620, justify="left").pack(anchor="w", pady=(4, 0))

        if not CLOUD_AVAILABLE:
            tk.Label(card.inner, text="Cloud sync unavailable — the 'requests' package is missing.",
                     bg=BG_CARD, fg=YELLOW, font=(FONT_FAMILY, 9)).pack(
                         anchor="w", padx=20, pady=(0, 16))
            return

        # Big monospace code, revealed once a pairing code is live.
        self._cloud_code_lbl = tk.Label(card.inner, text="", bg=BG_CARD, fg=ACCENT,
                                        font=(FONT_MONO, 30, "bold"))
        self._cloud_hint_lbl = tk.Label(card.inner, text="", bg=BG_CARD, fg=TEXT_MUTED,
                                        font=(FONT_FAMILY, 9), wraplength=620, justify="left")

        actions = tk.Frame(card.inner, bg=BG_CARD)
        actions.pack(fill="x", padx=20, pady=(0, 16))
        self._cloud_btn = PillButton(actions, text="Generate code",
                                     command=self._cloud_begin_pairing,
                                     bg_color=ACCENT, fg_color="#ffffff", width=150)
        self._cloud_btn.pack(side="left")
        self._cloud_sync_btn = PillButton(actions, text="Sync now",
                                          command=lambda: self._cloud_push_async(force=False),
                                          bg_color=BG_ELEVATED, fg_color=TEXT_PRIMARY, width=120)
        self._cloud_unlink_btn = PillButton(actions, text="Unlink",
                                            command=self._cloud_unlink,
                                            bg_color=BG_ELEVATED, fg_color=RED, width=100)

        self._cloud_refresh_ui()

        # Catch up on anything journaled while this machine was offline or the
        # app was closed. _cloud_push is a no-op when unlinked.
        self.after(3000, self._cloud_push_async)

    def _cloud_refresh_ui(self) -> None:
        """Redraw the card from cloud_state.json. Safe to call from the UI thread."""
        if not CLOUD_AVAILABLE or not hasattr(self, "_cloud_btn"):
            return
        linked = cloud_sync.CloudSync().is_linked
        email = cloud_sync.CloudSync().linked_email

        self._cloud_dot.itemconfig("all", fill=GREEN if linked else RED)
        self._cloud_status_lbl.configure(text="LINKED" if linked else "NOT LINKED",
                                         fg=GREEN if linked else RED)
        if linked:
            self._cloud_code_lbl.pack_forget()
            self._cloud_hint_lbl.configure(
                text=f"Synced to {email or 'your account'}. Trades upload after every batch.")
            self._cloud_hint_lbl.pack(anchor="w", padx=20, pady=(0, 10))
            self._cloud_btn.pack_forget()
            self._cloud_sync_btn.pack(side="left")
            self._cloud_unlink_btn.pack(side="left", padx=(8, 0))
        else:
            self._cloud_sync_btn.pack_forget()
            self._cloud_unlink_btn.pack_forget()
            self._cloud_btn.pack(side="left")
            self._cloud_btn.configure_text("Generate code")

    def _cloud_begin_pairing(self) -> None:
        if not CLOUD_AVAILABLE:
            return
        self._cloud_btn.configure_text("Contacting…")
        self._cloud_poll_stop.clear()

        def work():
            client = cloud_sync.CloudSync()
            try:
                pending = client.begin_pairing()
            except Exception as ex:
                self.after(0, lambda: self._cloud_fail(str(ex)))
                return
            self.after(0, lambda: self._cloud_show_code(pending))

            status = client.await_pairing(pending, should_stop=self._cloud_poll_stop.is_set)
            if status == "claimed":
                self.after(0, self._cloud_linked)
                self._cloud_push(force=True)     # backfill the whole journal
            elif status == "expired":
                self.after(0, lambda: self._cloud_fail("That code expired. Generate a new one."))
            elif status != "cancelled":
                self.after(0, lambda: self._cloud_fail(f"Pairing ended: {status}"))

        threading.Thread(target=work, daemon=True).start()

    def _cloud_show_code(self, pending) -> None:
        self._cloud_pending = pending
        self._cloud_code_lbl.configure(text="  ".join(pending.code))
        self._cloud_code_lbl.pack(anchor="w", padx=20, pady=(2, 2))
        self._cloud_hint_lbl.configure(
            text=f"Type this code at {pending.pair_url} while signed in. "
                 "It expires in 10 minutes. Waiting…")
        self._cloud_hint_lbl.pack(anchor="w", padx=20, pady=(0, 10))
        self._cloud_btn.configure_text("Waiting…")

    def _cloud_linked(self) -> None:
        self._cloud_code_lbl.configure(text="")
        self._cloud_refresh_ui()
        self._push_notification("Device linked to RSAMAXXED Cloud", "success")

    def _cloud_fail(self, msg: str) -> None:
        self._cloud_code_lbl.pack_forget()
        self._cloud_hint_lbl.configure(text=msg)
        self._cloud_hint_lbl.pack(anchor="w", padx=20, pady=(0, 10))
        self._cloud_btn.configure_text("Generate code")
        self._push_notification(f"Cloud: {msg}", "error")

    def _cloud_unlink(self) -> None:
        if not messagebox.askyesno(
            "Unlink from RSAMAXXED Cloud",
            "Stop syncing this machine?\n\nTrades already uploaded stay on the website. "
            "To revoke the token properly, use the Devices page there."
        ):
            return
        self._cloud_poll_stop.set()
        cloud_sync.CloudSync().unlink()
        self._cloud_refresh_ui()
        self._push_notification("Unlinked from RSAMAXXED Cloud", "info")

    def _cloud_push(self, force: bool = False) -> None:
        """Blocking push. Call from a worker thread only. Never raises."""
        if not CLOUD_AVAILABLE:
            return
        client = cloud_sync.CloudSync()
        if not client.is_linked:
            return
        try:
            result = client.push_trades(force=force)
        except Exception as ex:
            # A dead network must never interrupt trading. Log and move on.
            self.after(0, lambda: self._log(f"Cloud sync failed: {ex}"))
            return
        if result.get("inserted"):
            self.after(0, lambda: self._log(
                f"Cloud sync: uploaded {result['inserted']} new trade(s)"))
        self.after(0, self._cloud_refresh_ui)

    def _cloud_push_async(self, force: bool = False) -> None:
        threading.Thread(target=self._cloud_push, kwargs={"force": force},
                         daemon=True).start()

    def _toggle_mirror_broker(self, broker: str) -> None:
        chip = self._mirror_broker_chips[broker]
        chip["selected"] = not chip["selected"]
        self._style_chip(chip["label"], chip["selected"])
        if chip["selected"]:
            self._mirror_selected_brokers.add(broker)
        else:
            self._mirror_selected_brokers.discard(broker)
        self._save_mirror_state()

    def _mirror_log_msg(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._mirror_log.configure(state="normal")
        self._mirror_log.insert("end", f"[{ts}]  {msg}\n")
        self._mirror_log.see("end")
        self._mirror_log.configure(state="disabled")
        self._log(f"Mirror: {msg}")

    def _toggle_mirror_trading(self) -> None:
        if self._mirror_enabled.get():
            # Turning OFF
            self._mirror_enabled.set(False)
            if self._mirror_poll_id:
                self.after_cancel(self._mirror_poll_id)
                self._mirror_poll_id = None
            self._mirror_status_dot.itemconfig("all", fill=RED, outline=RED)
            self._mirror_status_lbl.configure(text="OFF", fg=RED)
            self._mirror_toggle_btn.configure_text("Enable Mirror Trading")
            self._mirror_log_msg("Mirror trading DISABLED")
            self._save_mirror_state()
            return

        # Turning ON — require confirmation
        if not self._mirror_selected_brokers:
            messagebox.showwarning("No Brokers",
                                   "Select at least one broker for mirror trading first.",
                                   parent=self)
            return

        brokers_str = ", ".join(sorted(self._mirror_selected_brokers))
        pending = self._mirror_pending_picks()
        if pending:
            names = ", ".join(f"{p.get('symbol', '?')} ({p.get('date', '')})"
                              for p in pending[:6])
            if len(pending) > 6:
                names += f", +{len(pending) - 6} more"
            pending_txt = (f"{len(pending)} pick(s) have no buy on record yet and "
                           f"will be bought at the next check:\n\n  {names}\n\n")
        else:
            pending_txt = "Nothing is waiting to be bought right now.\n\n"

        confirm = messagebox.askyesno(
            "Enable Mirror Trading",
            f"Are you sure you want to enable Mirror Trading?\n\n"
            f"This will automatically BUY 1 share of any new Reg Alert pick "
            f"on the following brokers:\n\n"
            f"  {brokers_str}\n\n"
            f"{pending_txt}"
            f"You can disable it at any time.",
            parent=self)
        if not confirm:
            return

        # Suppress every Reg Alert pick that is NOT pending — already bought,
        # already mirrored, or past its round-up window. What survives is work
        # still owed, and enabling mirror must not bury it.
        pending_keys = {self._mirror_key(p) for p in pending}
        for pick in self._quick_picks:
            if str(pick.get("note", "")).lower() not in MIRROR_NOTES:
                continue
            key = self._mirror_key(pick)
            if key not in pending_keys:
                self._mirror_executed.add(key)

        self._mirror_enabled.set(True)
        self._mirror_status_dot.itemconfig("all", fill=GREEN, outline=GREEN)
        self._mirror_status_lbl.configure(text="ACTIVE", fg=GREEN)
        self._mirror_toggle_btn.configure_text("Disable Mirror Trading")
        self._mirror_log_msg(f"Mirror trading ENABLED on: {brokers_str}")
        self._mirror_log_msg(
            f"Checking for new Reg Alert picks at {_mirror_schedule_label()} on market days")
        if pending:
            self._mirror_log_msg(
                f"{len(pending)} unbought pick(s) queued: "
                + ", ".join(str(p.get("symbol", "?")) for p in pending))
        self._save_mirror_state()

        # Start the schedule heartbeat
        self._mirror_poll()

    def _render_mirror_failed(self) -> None:
        """List picks mirror tried and could not fill anywhere."""
        frame = getattr(self, "_mirror_failed_frame", None)
        if frame is None:
            return
        for w in frame.winfo_children():
            w.destroy()
        if not self._mirror_failed:
            return

        tk.Label(frame, text="NEEDS ATTENTION — FILLED NOWHERE", bg=BG_CARD,
                 fg=RED, font=(FONT_FAMILY, 9, "bold")).pack(anchor="w",
                                                             pady=(10, 6))
        for date_str, sym in sorted(self._mirror_failed, reverse=True):
            row = tk.Frame(frame, bg=BG_INPUT)
            row.pack(fill="x", pady=(0, 4))
            tk.Frame(row, bg=RED, width=3).pack(side="left", fill="y")
            inner = tk.Frame(row, bg=BG_INPUT)
            inner.pack(side="left", fill="x", expand=True, padx=(10, 12), pady=7)
            tk.Label(inner, text=sym, bg=BG_INPUT, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 11, "bold")).pack(side="left")
            tk.Label(inner, text=f"  {date_str} · no broker filled",
                     bg=BG_INPUT, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 9)).pack(side="left")
            clear = tk.Label(inner, text="Dismiss", bg=BG_INPUT, fg=TEXT_MUTED,
                             font=(FONT_FAMILY, 8), cursor="hand2")
            clear.pack(side="right")
            clear.bind("<Button-1>",
                       lambda e, k=(date_str, sym): self._mirror_clear_failed(k))
            trade = tk.Label(inner, text="Trade manually →",
                             bg=_blend(ACCENT, BG_INPUT, 0.82), fg=ACCENT_HOVER,
                             font=(FONT_FAMILY, 9, "bold"), padx=10, pady=3,
                             cursor="hand2")
            trade.pack(side="right", padx=(0, 12))
            trade.bind("<Button-1>",
                       lambda e, s=sym: self._prefill_trade(s, "buy", "1"))

    def _mirror_clear_failed(self, key: tuple) -> None:
        self._mirror_failed.discard(tuple(key))
        self._save_mirror_state()
        self._render_mirror_failed()

    def _mirror_record_outcome(self, key: tuple, symbol: str,
                               total_ok: int, total_fail: int) -> None:
        """Record how a mirror batch actually landed.

        Mirror deliberately does not retry: the pick is already marked executed
        before the orders go out, because a second pass would double-buy every
        account that DID fill. The cost of that is a pick which filled nowhere
        (an OTC name under $1, say) silently disappearing — so record it and
        put it in front of the user instead.
        """
        key = tuple(key)
        if total_ok > 0:
            if key in self._mirror_failed:
                self._mirror_failed.discard(key)
                self._save_mirror_state()
                self._render_mirror_failed()
            return
        self._mirror_failed.add(key)
        self._save_mirror_state()
        self._mirror_log_msg(
            f"{symbol}: filled on NO broker ({total_fail} account(s) rejected) "
            f"— not retried, handle it manually")
        self._push_notification(
            f"Mirror: {symbol} filled on no broker — needs manual action", "error")
        self._render_mirror_failed()

    def _mirror_pending_picks(self) -> List[Dict[str, str]]:
        """Reg Alert picks mirror still owes: fresh, and with no buy on record.

        Enabling mirror used to stamp *every* pick in the feed as executed, on
        the theory that anything already listed had been dealt with. It hadn't —
        a pick imported this morning and not yet bought is precisely the pick
        mirror is being turned on for, and it went into the executed set unbought
        and was never looked at again. Whether the journal shows a buy is the
        real test; whether the pick predates the switch is not.

        Picks past PICK_MAX_AGE_DAYS stay suppressed regardless: their round-up
        window has closed, and flipping the switch must never open a month of
        old positions at once.
        """
        bought = self._mirror_bought_keys(self._quick_picks)
        pending: List[Dict[str, str]] = []
        for pick in self._quick_picks:
            if str(pick.get("note", "")).lower() not in MIRROR_NOTES:
                continue
            if self._mirror_key(pick) in self._mirror_executed:
                continue
            if self._mirror_journal_key(pick) in bought:
                continue
            if not _pick_is_fresh(pick):
                continue
            pending.append(pick)
        return pending

    def _mirror_bought_keys(self, picks: List[Dict[str, str]]) -> set:
        """Journal keys mirror has nothing left to do on.

        This is the guard that stops the executed set pretending to be a record
        of what we own: a pick bought from the Trade Desk is bought, and mirror
        must not buy it again just because it never placed that order itself.

        Scoped to the brokers mirror actually trades, and only when EVERY one of
        them already holds the pick. Testing "anyone bought it" instead would
        silence exactly the case mirror exists for — a name bought by hand at
        Chase and Wells Fargo, with Public and Robinhood still owed.
        """
        try:
            selected = set(self._mirror_selected_brokers)
            holders = _pick_broker_map(picks)
            done = _load_done_picks()
        except Exception:
            return set()
        if not selected:
            return set(done)
        return {k for k, brokers in holders.items()
                if selected <= brokers} | set(done)

    @staticmethod
    def _mirror_journal_key(pick: Dict[str, str]) -> tuple:
        """(SYMBOL, date) — the journal/coverage key order, which is the REVERSE
        of _mirror_key's (date, SYMBOL). Two orders in play, so never pass one
        where the other is expected."""
        return (str(pick.get("symbol", "")).strip().upper(),
                str(pick.get("date", "")).strip())

    @staticmethod
    def _mirror_key(pick: Dict[str, str]) -> tuple:
        """Canonical dedup key for a pick. MUST be built identically everywhere
        (snapshot, poll, execute) or an already-bought pick reads as 'new' and
        gets bought a second time. Symbol is normalized to upper-case."""
        return (str(pick.get("date", "")).strip(),
                str(pick.get("symbol", "")).strip().upper())

    def _mirror_poll(self) -> None:
        """Schedule heartbeat: run the pick check only when a slot comes due.

        This wakes every few minutes but only *fetches* at the times in
        MIRROR_CHECK_TIMES_ET. Waking often is what makes the schedule survive
        a sleeping laptop or a clock jump — a single long after() would drift
        straight past a slot.
        """
        if not self._mirror_enabled.get():
            return

        _state, _label, now = _market_status()
        slot = _mirror_due_slot(now)
        if slot and slot != self._mirror_last_slot:
            self._mirror_last_slot = slot
            self._save_mirror_state()
            self._mirror_check_now(slot.split("@", 1)[-1])

        self._mirror_poll_id = self.after(MIRROR_HEARTBEAT_MS, self._mirror_poll)

    def _mirror_check_now(self, when: str = "manual",
                          trigger: str = "") -> None:
        """One pass over the pick feed; buys anything new and eligible."""
        if not self._mirror_enabled.get():
            return
        trigger = trigger or ("manual" if when == "manual" else "schedule")
        self._mirror_log_msg(f"Scheduled check ({when})...")

        def _worker():
            try:
                picks = _fetch_quick_picks()
                bought = self._mirror_bought_keys(picks)
                new_picks = []
                skipped: List[Dict[str, str]] = []
                for pick in picks:
                    note = pick.get("note", "").lower()
                    sym = str(pick.get("symbol", "")).upper()
                    # Only Reg Alert / alert / early access
                    if note not in MIRROR_NOTES:
                        # Recorded, not just dropped: "why didn't it buy TOMZ"
                        # is the question the Mirror page exists to answer, and
                        # 'conditional' vs 'OTC' are different answers.
                        skipped.append({"symbol": sym,
                                        "reason": _mirror_skip_reason(note)})
                        continue
                    if self._mirror_key(pick) in self._mirror_executed:
                        skipped.append({"symbol": sym, "reason": "already executed"})
                        continue
                    # Bought by hand, or by an earlier install: the executed set
                    # only knows about orders mirror itself placed, so without
                    # this a Trade Desk buy gets bought a second time.
                    if self._mirror_journal_key(pick) in bought:
                        skipped.append({"symbol": sym, "reason": "already bought"})
                        continue
                    if not _pick_is_fresh(pick):
                        skipped.append({"symbol": sym,
                                        "reason": "past its round-up window"})
                        continue
                    new_picks.append(pick)

                try:
                    mirror_journal.record_scan(
                        trigger=trigger,
                        slot=when, considered=len(picks),
                        queued=len(new_picks), skipped=skipped)
                except Exception:
                    pass
                self.after(0, lambda: self._invalidate_page("mirror"))

                if new_picks:
                    self.after(0, lambda: self._mirror_execute(new_picks, when, trigger))
                else:
                    self.after(0, lambda: self._mirror_log_msg("No new picks"))
            except Exception as e:
                # A transient fetch/parse error must not strand the schedule.
                # The heartbeat owns rescheduling, so a failure here only costs
                # this slot — the next one still runs.
                self.after(0, lambda err=e: self._mirror_log_msg(
                    f"Check failed (next check {_mirror_schedule_label()}): {err}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _mirror_execute(self, picks: List[Dict[str, str]],
                        when: str = "manual", trigger: str = "") -> None:
        """Execute BUY 1 share for each new pick on the brokers still owed it."""
        if not self._mirror_selected_brokers:
            self._mirror_log_msg("No brokers selected — skipping")
            return

        # Which brokers already hold each pick. A pick reaches here when at
        # least one selected broker still owes it — buying blind on the whole
        # set would double up on the ones that already filled.
        holders = _pick_broker_map(picks)

        for pick in picks:
            symbol = pick.get("symbol", "").upper()
            key = self._mirror_key(pick)

            # Double-check not already executed
            if key in self._mirror_executed:
                continue

            self._mirror_executed.add(key)
            held = holders.get(self._mirror_journal_key(pick), set())
            selected = sorted(self._mirror_selected_brokers - held)
            if not selected:
                continue
            skipping = sorted(self._mirror_selected_brokers & held)
            self._mirror_log_msg(f"NEW PICK: {symbol} — executing BUY 1 share")
            if skipping:
                self._mirror_log_msg(
                    f"  skipping {', '.join(skipping)} — already holds {symbol}")
            self._mirror_exec_count.configure(
                text=f"{len(self._mirror_executed)} pick(s) already executed")

            # Route through a batch (origin=mirror) so it gets the same live
            # strip + completion receipt as a manual trade, and reuse the worker.
            try:
                run_id = mirror_journal.start_run(
                    symbol=symbol, side="buy", qty="1", brokers=selected,
                    trigger=trigger or ("manual" if when == "manual" else "schedule"),
                    slot=when, note=str(pick.get("note", "")),
                    pick_date=str(pick.get("date", "")), dry_run=False)
            except Exception:
                run_id = ""
            batch = {
                "pending": set(selected),
                "all_brokers": selected,
                "results": [],
                "side": "buy",
                "symbol": symbol,
                "qty": "1",
                "dry_run": False,
                "origin": "mirror",
                "mirror_key": key,
                "mirror_run": run_id,
                "finished": False,
                "started": datetime.now(),
            }
            self._live_start(batch)
            for broker in selected:
                self._mirror_log_msg(f"  {broker}: sending BUY 1 {symbol}...")
                self._run_in_thread(self._trade_worker, broker, "buy", symbol, "1", False, batch)

            # Play notification sound
            try:
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass

        self._save_mirror_state()

    # ---- Discord pick feed ------------------------------------------------

    def _build_discord_card(self, parent) -> None:
        self._discord_state = _load_discord_state()
        self._discord_poll_id: Optional[str] = None

        card = RoundedFrame(parent, bg_color=BG_CARD, border_color=BORDER, radius=14)
        card.pack(fill="x", pady=(0, 16))

        header = tk.Frame(card.inner, bg=BG_CARD)
        header.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(header, text=icon("bell"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 13)).pack(side="left", padx=(0, 9))
        tk.Label(header, text="Discord Pick Feed", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 14, "bold")).pack(side="left")
        status_wrap = tk.Frame(header, bg=BG_CARD)
        status_wrap.pack(side="right")
        on = bool(self._discord_state.get("enabled"))
        self._discord_status_dot = StatusDot(status_wrap, color=GREEN if on else RED, size=8)
        self._discord_status_dot.pack(side="left", padx=(0, 6))
        self._discord_status_lbl = tk.Label(
            status_wrap, text="ON" if on else "OFF", bg=BG_CARD,
            fg=GREEN if on else RED, font=(FONT_FAMILY, 9, "bold"))
        self._discord_status_lbl.pack(side="left")

        info = tk.Frame(card.inner, bg=BG_INPUT, padx=16, pady=12)
        info.pack(fill="x", padx=20, pady=(4, 12))
        tk.Label(info, text="Auto-import RSA plays from the Discord channels you're in",
                 bg=BG_INPUT, fg=TEXT_PRIMARY, font=(FONT_FAMILY, 10, "bold")).pack(anchor="w")
        tk.Label(info, text="Reads new messages with your account token (no bot/webhook needed). "
                 "BUY alerts go straight into Quick Picks — which Mirror Trading can then "
                 "auto-buy. SELL alerts are recorded as exits and round-up confirmations, and "
                 "are never auto-traded: an alerter selling says nothing about what you hold. "
                 "Pulls once a day (one request per channel — the app only reads, never posts).",
                 bg=BG_INPUT, fg=TEXT_SECONDARY, font=(FONT_FAMILY, 9),
                 wraplength=620, justify="left").pack(anchor="w", pady=(4, 8))
        tk.Label(info, text="⚠  Using a user token to read messages breaks Discord's ToS and "
                 "could flag your account. Personal use, at your own risk.",
                 bg=BG_INPUT, fg=YELLOW, font=(FONT_FAMILY, 8), wraplength=620,
                 justify="left").pack(anchor="w")
        tk.Label(info, text="How to get them: Discord → Settings → Advanced → Developer Mode ON. "
                 "Right-click the channel → Copy Channel ID. Token: open Discord in your browser, "
                 "DevTools (F12) → Network → click any request → Headers → 'authorization'.",
                 bg=BG_INPUT, fg=TEXT_MUTED, font=(FONT_FAMILY, 8), wraplength=620,
                 justify="left").pack(anchor="w", pady=(6, 0))

        # ---- Config lock -------------------------------------------------
        # The feed ships pre-configured, so a downloaded copy pulls plays with
        # nothing to fill in. The fields stay read-only behind an unlock code
        # to stop a casual edit from silently breaking the feed for everyone.
        # This is a fumble-guard, not security: the values still live in .env
        # on disk and anyone with the files can read them.
        lock_bar = tk.Frame(card.inner, bg=BG_INPUT, padx=16, pady=10)
        lock_bar.pack(fill="x", padx=20, pady=(0, 8))
        self._discord_locked = True
        tk.Label(lock_bar, text=icon("lock"), bg=BG_INPUT, fg=TEXT_SECONDARY,
                 font=(ICON_FONT, 11)).pack(side="left", padx=(0, 8))
        self._discord_lock_lbl = tk.Label(
            lock_bar, text="Feed settings are locked — plays load automatically",
            bg=BG_INPUT, fg=TEXT_SECONDARY, font=(FONT_FAMILY, 9))
        self._discord_lock_lbl.pack(side="left")
        self._discord_lock_btn = PillButton(
            lock_bar, text="Unlock", bg_color=BG_CARD_ALT, hover_color=ACCENT,
            command=self._toggle_discord_lock, width=90, height=28, font_size=9)
        self._discord_lock_btn.pack(side="right")

        form = tk.Frame(card.inner, bg=BG_CARD)
        form.pack(fill="x", padx=20, pady=(0, 10))
        tk.Label(form, text="DISCORD TOKEN", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_MONO, 8)).grid(row=0, column=0, sticky="w", pady=4, padx=(0, 10))
        self._discord_token_entry = ttk.Entry(form, width=46, show="•",
                                              font=(FONT_MONO, 9))
        self._discord_token_entry.insert(0, _env("DISCORD_TOKEN"))
        self._discord_token_entry.grid(row=0, column=1, sticky="w", pady=4)
        tk.Label(form, text="SERVER (optional)", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_MONO, 8)).grid(row=1, column=0, sticky="w", pady=4, padx=(0, 10))
        self._discord_server_entry = ttk.Entry(form, width=46, font=(FONT_MONO, 9))
        self._discord_server_entry.insert(0, _env("DISCORD_SERVER"))
        self._discord_server_entry.grid(row=1, column=1, sticky="w", pady=4)
        tk.Label(form, text="BUY CHANNEL (name or ID)", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_MONO, 8)).grid(row=2, column=0, sticky="w", pady=4, padx=(0, 10))
        self._discord_chan_entry = ttk.Entry(form, width=46, font=(FONT_MONO, 9))
        self._discord_chan_entry.insert(0, _env("DISCORD_CHANNEL") or _env("DISCORD_CHANNEL_ID"))
        self._discord_chan_entry.grid(row=2, column=1, sticky="w", pady=4)
        tk.Label(form, text='e.g.  BUY   (the channel name) — or paste a numeric ID',
                 bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 8)).grid(
                     row=3, column=1, sticky="w")

        tk.Label(form, text="SELL CHANNEL (optional)", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_MONO, 8)).grid(row=4, column=0, sticky="w", pady=4, padx=(0, 10))
        self._discord_sell_entry = ttk.Entry(form, width=46, font=(FONT_MONO, 9))
        self._discord_sell_entry.insert(
            0, _env("DISCORD_SELL_CHANNEL") or _env("DISCORD_SELL_CHANNEL_ID"))
        self._discord_sell_entry.grid(row=4, column=1, sticky="w", pady=4)
        tk.Label(form, text='e.g.  SELL — exits and round-up confirmations. Never auto-traded.',
                 bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 8)).grid(
                     row=5, column=1, sticky="w")

        btns = tk.Frame(card.inner, bg=BG_CARD)
        btns.pack(fill="x", padx=20, pady=(6, 10))
        save_btn = PillButton(btns, text="Save", bg_color=BG_CARD_ALT, hover_color=ACCENT,
                              command=self._save_discord_creds, width=70, height=30,
                              font_size=9)
        save_btn.pack(side="left", padx=(0, 8))
        find_btn = PillButton(btns, text="Find Channel", bg_color=BG_CARD_ALT,
                              hover_color=ACCENT, command=self._discord_find_channel,
                              width=115, height=30, font_size=9)
        find_btn.pack(side="left", padx=(0, 8))
        # Only the *editing* controls lock. Test / Import Now / the enable
        # toggle stay live so a locked copy can still pull plays.
        self._discord_locked_widgets = [
            self._discord_token_entry, self._discord_server_entry,
            self._discord_chan_entry, self._discord_sell_entry,
            save_btn, find_btn,
        ]
        self._apply_discord_lock()
        PillButton(btns, text="Test", bg_color=BG_CARD_ALT, hover_color=ACCENT,
                   command=self._test_discord, width=70, height=30,
                   font_size=9).pack(side="left", padx=(0, 8))
        PillButton(btns, text="Import Now", bg_color=BG_CARD_ALT, hover_color=ACCENT,
                   command=self._discord_import_now, width=110, height=30,
                   font_size=9).pack(side="left")

        tk.Label(card.inner, text="FEED ACTIVITY", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(anchor="w", padx=20, pady=(4, 6))
        self._discord_log = tk.Text(card.inner, bg=BG_INPUT, fg=TEXT_PRIMARY,
                                    font=(FONT_MONO, 9), height=5, bd=0,
                                    state="disabled", insertbackground=TEXT_PRIMARY,
                                    highlightthickness=0, padx=8, pady=8)
        self._discord_log.pack(fill="x", padx=20)

        toggle_row = tk.Frame(card.inner, bg=BG_CARD)
        toggle_row.pack(fill="x", padx=20, pady=(10, 20))
        self._discord_toggle_btn = PillButton(
            toggle_row,
            text="Disable Auto-Import" if on else "Enable Auto-Import",
            command=self._toggle_discord_import, width=190, height=40, font_size=11)
        self._discord_toggle_btn.pack(side="left")

        if on:
            # Launch always pulls, even if today's scheduled pull already ran in
            # an earlier session.
            self.after(2000, lambda: self._discord_daily_check(force=True))

    def _apply_discord_lock(self) -> None:
        """Push self._discord_locked out to the widgets and the lock bar."""
        state = "disabled" if self._discord_locked else "normal"
        for w in getattr(self, "_discord_locked_widgets", []):
            try:
                w.configure(state=state)
            except Exception:
                pass
        self._discord_lock_lbl.configure(
            text="Feed settings are locked — plays load automatically"
                 if self._discord_locked else
                 "Unlocked — changes here affect every copy that syncs this feed",
            fg=TEXT_SECONDARY if self._discord_locked else YELLOW)
        self._discord_lock_btn.configure_text(
            "Unlock" if self._discord_locked else "Lock")

    def _toggle_discord_lock(self) -> None:
        if not self._discord_locked:
            self._discord_locked = True
            self._apply_discord_lock()
            return
        code = self._ask_inline(
            "Unlock Feed Settings",
            "Enter the access code to edit the Discord feed settings:",
            show="*")
        if code is None:
            return
        if code != DISCORD_CONFIG_UNLOCK:
            messagebox.showerror("Incorrect Code",
                                 "That access code is not correct.", parent=self)
            return
        self._discord_locked = False
        self._apply_discord_lock()

    def _discord_log_msg(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._discord_log.configure(state="normal")
        self._discord_log.insert("end", f"[{ts}]  {msg}\n")
        self._discord_log.see("end")
        self._discord_log.configure(state="disabled")

    # The two channel roles and the .env keys each one uses. Adding a third
    # stream later is a row here, not a new branch in every method below.
    _CHANNEL_KEYS = {
        "buy":  ("DISCORD_CHANNEL", "DISCORD_CHANNEL_ID"),
        "sell": ("DISCORD_SELL_CHANNEL", "DISCORD_SELL_CHANNEL_ID"),
    }

    def _save_discord_creds(self) -> None:
        updates = {
            "DISCORD_TOKEN": self._discord_token_entry.get().strip(),
            "DISCORD_SERVER": self._discord_server_entry.get().strip(),
        }
        for role, entry in (("buy", self._discord_chan_entry),
                            ("sell", self._discord_sell_entry)):
            name_key, id_key = self._CHANNEL_KEYS[role]
            raw = entry.get().strip()
            updates[name_key] = raw
            # A numeric entry IS the channel id. Otherwise clear the cached id
            # so it re-resolves from the (possibly changed) name.
            if raw.isdigit():
                updates[id_key] = raw
            elif raw.lower() != (_env(name_key) or "").lower():
                updates[id_key] = ""
        _save_env_file(updates)
        self._discord_log_msg("Saved.")

    def _ensure_discord_channel_id(self, role: str = "buy", required: bool = True):
        """Return (channel_id, error). Resolves a channel NAME → id once and
        caches the id so daily pulls stay at one request per channel."""
        name_key, id_key = self._CHANNEL_KEYS[role]
        cid = _env(id_key)
        if cid:
            return cid, None
        raw = _env(name_key)
        if not raw:
            if not required:
                return None, None   # sell channel is optional; not an error
            return None, "Enter a channel name (e.g. BUY) or ID first."
        cid, gname, err = _discord_resolve_channel(
            _env("DISCORD_TOKEN"), raw, _env("DISCORD_SERVER"))
        if cid:
            _save_env_file({id_key: cid})
            if gname:
                self.after(0, lambda: self._discord_log_msg(
                    f"Resolved #{raw} → '{gname}' (id {cid})"))
        return cid, err

    def _discord_find_channel(self) -> None:
        self._save_discord_creds()
        self._discord_log_msg("Looking up channels...")

        def worker():
            for role, label in (("buy", "BUY"), ("sell", "SELL")):
                cid, err = self._ensure_discord_channel_id(role, required=(role == "buy"))
                if err:
                    self.after(0, lambda l=label, e=err: self._discord_log_msg(f"{l}: {e}"))
                elif cid:
                    self.after(0, lambda l=label, c=cid: self._discord_log_msg(
                        f"{l} channel ready (id {c})."))
                else:
                    self.after(0, lambda l=label: self._discord_log_msg(
                        f"{l}: not set — exits won't be imported."))
        threading.Thread(target=worker, daemon=True).start()

    def _test_discord(self) -> None:
        self._save_discord_creds()
        self._discord_log_msg("Testing connection...")

        def worker():
            cid, cerr = self._ensure_discord_channel_id("buy")
            if cerr:
                self.after(0, lambda: self._discord_log_msg(f"FAILED: {cerr}"))
                return
            buy_msgs, err = _discord_fetch(cid, _env("DISCORD_TOKEN"), limit=10)
            if err:
                self.after(0, lambda: self._discord_log_msg(f"FAILED: {err}"))
                return

            sell_msgs = []
            sell_cid, _ = self._ensure_discord_channel_id("sell", required=False)
            if sell_cid:
                sell_msgs, serr = _discord_fetch(sell_cid, _env("DISCORD_TOKEN"), limit=10)
                if serr:
                    sell_msgs = []
                    self.after(0, lambda: self._discord_log_msg(f"SELL failed: {serr}"))

            # Preview exactly what a real import would produce.
            batch = rsa_feed.parse_messages(buy_msgs, sell_msgs)
            syms = sorted({b.symbol for b in batch.buys})
            self.after(0, lambda: self._discord_log_msg(
                f"BUY  — read {len(buy_msgs)} messages, tickers: "
                + (", ".join(syms) if syms else "none (check message format)")))
            if sell_cid:
                exits = sorted({s.symbol for s in batch.sells})
                ru = sorted({r.symbol for r in batch.roundups})
                self.after(0, lambda: self._discord_log_msg(
                    f"SELL — read {len(sell_msgs)} messages, "
                    f"{len(batch.sells)} exit(s): " + (", ".join(exits) or "none")
                    + (f" | round-ups: {', '.join(ru)}" if ru else "")))
            else:
                self.after(0, lambda: self._discord_log_msg(
                    "SELL — not configured (optional; exits won't be imported)."))
        threading.Thread(target=worker, daemon=True).start()

    def _extract_picks_from_text(self, text: str) -> List[Dict[str, str]]:
        """Plain-text fallback: (TICKER) parser first, then $cashtag."""
        picks = self._parse_discord_picks(text)
        if not picks:
            seen = set()
            for m in re.findall(r"\$([A-Za-z]{1,5})\b", text):
                sym = m.upper()
                if sym not in seen and sym not in ("A", "I"):
                    seen.add(sym)
                    picks.append({"symbol": sym, "note": "Reg Alert"})
        return picks

    @staticmethod
    def _rsa_note(desc: str, title: str) -> str:
        """Map an RSA Alert type to a pick note. Thin wrapper over rsa_feed so
        the mapping exists in exactly one place."""
        return rsa_feed._PICK_NOTES.get(rsa_feed._kind_from(desc, title), "Reg Alert")

    @staticmethod
    def _parse_rsa_date(value: str) -> Optional[str]:
        """'6/18/26 (Thu)' -> '2026-06-18'."""
        return rsa_feed.parse_rsa_date(value)

    def _extract_picks_from_message(self, msg: Dict[str, Any]) -> List[Dict[str, str]]:
        """One BUY-channel message -> the pick rows Quick Picks stores.

        The parsing itself lives in rsa_feed.parse_buy_message, which keeps far
        more than three fields (ratio, entry price, last day to buy...). Those
        richer rows go to the cloud feed; picks.json still holds the same three
        keys it always has, so the mirror queue is untouched.
        """
        return rsa_feed.to_picks(rsa_feed.parse_buy_message(msg))

    def _import_picks_from_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        existing = list(self._quick_picks) if self._quick_picks else _fetch_quick_picks()
        existing_keys = {(p.get("date"), p.get("symbol")) for p in existing}
        added: List[Dict[str, str]] = []
        for msg in messages:
            for p in self._extract_picks_from_message(msg):
                k = (p.get("date"), p.get("symbol"))
                if k not in existing_keys:
                    existing_keys.add(k)
                    existing.append(p)
                    added.append(p)
        if added:
            self._persist_picks(existing)
        return added

    def _persist_picks(self, all_picks: List[Dict[str, str]]) -> None:
        """Write picks locally + best-effort remote sync, then re-render."""
        all_picks, _ = _prune_stale_picks(all_picks)  # never persist stale picks
        try:
            PICKS_FILE.write_text(json.dumps(all_picks, indent=2), encoding="utf-8")
        except Exception:
            pass
        _push_picks_remote(all_picks)
        self.after(0, lambda: self._render_quick_picks(all_picks))

    def _discord_import_now(self) -> None:
        self._save_discord_creds()
        self._discord_log_msg("Importing latest messages...")
        self._run_in_thread(self._discord_import_worker, False)

    def _discord_import_worker(self, use_after: bool) -> None:
        """One pull of both alert channels.

        BUY drives Quick Picks (and therefore Mirror Trading) exactly as before.
        SELL is new: exits and round-up confirmations. Neither triggers a trade
        — a sell alert says the alerter sold, not that you hold anything — so it
        is recorded and published, never executed.
        """
        buy_msgs, sell_msgs = [], []

        cid, cerr = self._ensure_discord_channel_id()
        if cerr:
            self.after(0, lambda: self._discord_log_msg(f"Error: {cerr}"))
            return
        after = self._discord_state.get("last_id") if use_after else None
        buy_msgs, err = _discord_fetch(cid, _env("DISCORD_TOKEN"), after=after, limit=50)
        if err:
            self.after(0, lambda: self._discord_log_msg(f"Error: {err}"))
            return

        # The sell channel is optional: a user who only configured BUY keeps
        # working, they just don't get exits.
        sell_cid, sell_err = self._ensure_discord_channel_id(role="sell", required=False)
        if sell_cid:
            sell_after = self._discord_state.get("last_sell_id") if use_after else None
            sell_msgs, serr = _discord_fetch(
                sell_cid, _env("DISCORD_TOKEN"), after=sell_after, limit=50)
            if serr:
                self.after(0, lambda: self._discord_log_msg(f"Sell channel: {serr}"))
                sell_msgs = []
        elif sell_err and not use_after:
            self.after(0, lambda: self._discord_log_msg(f"Sell channel: {sell_err}"))

        if not buy_msgs and not sell_msgs:
            self.after(0, lambda: self._discord_log_msg("No new messages."))
            return

        batch = rsa_feed.parse_messages(buy_msgs, sell_msgs)

        # --- BUY side: unchanged behaviour, straight into Quick Picks.
        added = self._import_picks_from_messages(buy_msgs) if buy_msgs else []
        if buy_msgs:
            self._discord_state["last_id"] = str(max(int(m["id"]) for m in buy_msgs))
        if sell_msgs:
            self._discord_state["last_sell_id"] = str(max(int(m["id"]) for m in sell_msgs))
        _save_discord_state(self._discord_state)

        if added:
            syms = ", ".join(sorted({p["symbol"] for p in added}))
            self.after(0, lambda: self._discord_log_msg(
                f"Imported {len(added)} pick(s): {syms}"))
            self.after(0, lambda: self._push_notification(
                f"Discord: imported {syms}", "success"))
            self.after(0, lambda: self._mirror_after_import(added))
        elif buy_msgs:
            self.after(0, lambda: self._discord_log_msg("No new tickers found."))

        # --- SELL side: report what closed and what rounded up.
        if batch.sells:
            lines = ", ".join(
                f"{s.symbol} {s.proceeds_text}" for s in batch.sells[-6:])
            self.after(0, lambda: self._discord_log_msg(
                f"{len(batch.sells)} exit(s): {lines}"))
            # Persist them: exits used to exist only as this one log line, so
            # the brokerage each alert named was lost the moment it scrolled.
            incoming = batch.to_json().get("sells") or []
            _save_sells(_merge_sells(_load_sells(), incoming))
            self.after(0, self._render_sell_alerts)
        if batch.roundups:
            ru = ", ".join(sorted({r.symbol for r in batch.roundups}))
            self.after(0, lambda: self._discord_log_msg(f"Round-up confirmed: {ru}"))
            self.after(0, lambda: self._push_notification(
                f"Round-up confirmed: {ru}", "success"))

        self._publish_feed(batch)

    def _mirror_after_import(self, added: List[Dict[str, str]]) -> None:
        """Check the feed as soon as an import lands a new Reg Alert.

        The schedule runs on fixed slots, so a pick imported at 10:15 — or by
        the launch pull — otherwise sits unbought until the next one. This only
        fires inside a window the schedule would itself act in: _mirror_due_slot
        is None at night, at weekends and after 16:00 ET, so an evening import
        can never place an order.
        """
        if not getattr(self, "_mirror_enabled", None) or not self._mirror_enabled.get():
            return
        if not any(str(p.get("note", "")).lower() in MIRROR_NOTES for p in added):
            return
        _state, _label, now = _market_status()
        if _mirror_due_slot(now) is None:
            self._mirror_log_msg(
                "New pick imported outside the check window — it goes at the "
                f"next scheduled check ({_mirror_schedule_label()})")
            return
        self._mirror_check_now("new pick imported", trigger="import")

    def _publish_feed(self, batch) -> None:
        """Publish the parsed batch to RSAMAXXED Cloud, if this machine is the
        one that publishes. On a customer's install there is no feed key, so
        this is a no-op and never touches the network."""
        if not batch:
            return
        try:
            from cloud_sync import CloudSync, CloudError
        except Exception:
            return
        cloud = CloudSync()
        if not cloud.can_publish_feed:
            return
        try:
            sent = cloud.publish_feed(batch.to_json())
        except CloudError as exc:
            self.after(0, lambda: self._discord_log_msg(f"Cloud publish failed: {exc}"))
            return
        if any(sent.values()):
            self.after(0, lambda: self._discord_log_msg(
                f"Published to cloud — {sent['buys']} buys, {sent['sells']} exits, "
                f"{sent['roundups']} round-ups."))

    def _toggle_discord_import(self) -> None:
        if self._discord_state.get("enabled"):
            self._discord_state["enabled"] = False
            if self._discord_poll_id:
                self.after_cancel(self._discord_poll_id)
                self._discord_poll_id = None
            self._discord_status_dot.set_color(RED)
            self._discord_status_lbl.configure(text="OFF", fg=RED)
            self._discord_toggle_btn.configure_text("Enable Auto-Import")
            self._discord_log_msg("Auto-import DISABLED")
            _save_discord_state(self._discord_state)
            return

        if not _env("DISCORD_TOKEN") or not _env("DISCORD_CHANNEL_ID"):
            self._save_discord_creds()
        if not _env("DISCORD_TOKEN") or not _env("DISCORD_CHANNEL_ID"):
            messagebox.showwarning("Missing details",
                                   "Enter and Save your Discord token and channel ID first.",
                                   parent=self)
            return
        self._discord_state["enabled"] = True
        self._discord_status_dot.set_color(GREEN)
        self._discord_status_lbl.configure(text="ON", fg=GREEN)
        self._discord_toggle_btn.configure_text("Disable Auto-Import")
        self._discord_log_msg("Auto-import ENABLED — pulls once a day")
        _save_discord_state(self._discord_state)
        self._discord_daily_check()

    def _discord_daily_check(self, force: bool = False) -> None:
        """Pull at most once per calendar day (one request/day — invisible to
        server staff, minimal account footprint). Re-checks hourly so it still
        fires on a new day if the app is left open.

        `force` is the launch pull. Opening the app is an explicit "show me what
        is current", and the once-a-day gate used to mean a copy started after
        that day's pull ran with a stale board until tomorrow — including the
        alert that landed while it was closed. The pull is incremental (it asks
        only for messages after `last_id`), so this costs one cheap request.

        The TRACK board has its own loop (`_track_loop`) — it is read-only and
        must not depend on this toggle, which exists to control whether we
        import picks.
        """
        if not self._discord_state.get("enabled"):
            return
        today = datetime.now().strftime("%Y-%m-%d")
        if force or self._discord_state.get("last_pull_date") != today:
            self._discord_state["last_pull_date"] = today
            _save_discord_state(self._discord_state)
            self._discord_log_msg("Startup pull..." if force else "Daily pull...")
            self._run_in_thread(self._discord_import_worker, True)
        else:
            self._discord_log_msg("Already pulled today — next pull tomorrow.")
        # hourly heartbeat to catch the day rollover
        self._discord_poll_id = self.after(3600000, self._discord_daily_check)

    # ---- Mirror (what automation did) --------------------------------------
    #
    # The Automation page is the CONTROLS — a switch, a broker set, a schedule.
    # This page is the RECORD, and it is deliberately a separate screen: the
    # question "is mirror on" and the question "what did it buy at 09:35 while I
    # was asleep, and which accounts refused" are asked at completely different
    # times, and cramming the second into a scrolling text box under the first
    # is why the answer used to be unavailable an hour later.
    #
    # Everything rendered here comes out of mirror_runs.json, written locally by
    # this machine's own automation. No Discord, no subscription, no network.

    _MIRROR_OUTCOMES = {
        "filled":  ("FILLED",  GREEN),
        "partial": ("PARTIAL", YELLOW),
        "failed":  ("NO FILL", RED),
        "running": ("RUNNING", ACCENT),
    }

    def _build_mirror(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["mirror"] = frame
        # Which run rows are open. Held on the app, not the widgets, so a
        # re-render (a new run landing, say) doesn't collapse what you expanded.
        self._mirror_expanded: set = set()

        head = tk.Frame(frame, bg=BG_PRIMARY)
        head.pack(fill="x", pady=(0, 10))
        self._mirror_page_summary = tk.Label(
            head, text="No automated runs yet", bg=BG_PRIMARY,
            fg=TEXT_SECONDARY, font=(FONT_FAMILY, 10))
        self._mirror_page_summary.pack(side="left")
        self._mirror_page_stamp = tk.Label(head, text="", bg=BG_PRIMARY,
                                           fg=TEXT_MUTED, font=(FONT_FAMILY, 8))
        self._mirror_page_stamp.pack(side="right")

        outer, self._mirror_body = self._make_vscroll(frame)
        outer.pack(fill="both", expand=True)
        self._render_mirror()

    def _mirror_check_clicked(self) -> None:
        """Header action. Runs a check now, or explains why it can't."""
        if not getattr(self, "_mirror_enabled", None) or not self._mirror_enabled.get():
            self._push_notification(
                "Mirror trading is off — turn it on from Automation first", "warning")
            self._show_frame("settings")
            return
        self._mirror_check_now("manual")
        self._push_notification("Mirror: checking the feed for new picks", "info")

    def _export_mirror_csv(self) -> None:
        import csv
        from tkinter import filedialog
        try:
            rows = mirror_journal.csv_rows()
        except Exception:
            rows = []
        if len(rows) <= 1:
            self._push_notification("Nothing automated yet to export", "warning")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="rsamaxxed_mirror_runs.csv", parent=self)
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)
            self._push_notification(f"Exported {len(rows) - 1} order rows", "success")
            self._log(f"Exported {len(rows) - 1} mirror order rows to {path}")
        except Exception as ex:
            self._push_notification(f"Export failed: {ex}", "error")

    # ---- Mirror page rendering ---------------------------------------------

    def _render_mirror(self) -> None:
        if not hasattr(self, "_mirror_body"):
            return
        for w in self._mirror_body.winfo_children():
            w.destroy()

        try:
            runs = mirror_journal.runs()
            stats = mirror_journal.summary(days=30)
            scans = mirror_journal.scans(limit=40)
        except Exception as exc:
            self._empty_state(self._mirror_body, "error", "Could not read the run log",
                              str(exc)[:200]).pack(fill="x")
            return

        self._mirror_render_status(self._mirror_body, stats)

        if not runs and not scans:
            self._mirror_page_summary.configure(text="No automated runs yet")
            self._mirror_page_stamp.configure(text="")
            self._empty_state(
                self._mirror_body, "lightning", "Automation hasn't run yet",
                "Turn Mirror Trading on from Automation and pick your brokers. "
                "Every check it makes and every order it places is recorded "
                "here — including the accounts that refuse, and why.").pack(fill="x")
            return

        filled = stats["ok_accounts"]
        attempted = stats["attempted"]
        self._mirror_page_summary.configure(
            text=f"{stats['runs']} run(s) · {stats['symbols']} symbol(s) · "
                 f"{filled}/{attempted} accounts filled   ·   last 30 days")
        last = stats["last_run"] or stats["last_scan"]
        stamp = (last or {}).get("started_at") or (last or {}).get("at") or ""
        self._mirror_page_stamp.configure(
            text=f"last activity {stamp.replace('T', ' ')}" if stamp else "")

        self._mirror_render_kpis(self._mirror_body, stats)

        nowhere = stats["nowhere"]
        if nowhere:
            self._mirror_render_attention(self._mirror_body, nowhere)

        self._mirror_render_runs(self._mirror_body, runs)
        self._mirror_render_scans(self._mirror_body, scans)

    def _mirror_render_status(self, parent, stats: dict) -> None:
        """Is it armed, on what, and when does it next look."""
        on = bool(getattr(self, "_mirror_enabled", None) and self._mirror_enabled.get())
        brokers = sorted(getattr(self, "_mirror_selected_brokers", ()))

        card = RoundedFrame(parent, bg_color=BG_CARD, border_color=BORDER, radius=RAD_MD)
        card.pack(fill="x", pady=(0, SP_MD))

        row = tk.Frame(card.inner, bg=BG_CARD)
        row.pack(fill="x", padx=SP_XL, pady=(SP_LG, SP_SM))
        StatusDot(row, color=GREEN if on else RED, size=9).pack(side="left", padx=(0, 9))
        tk.Label(row, text="ACTIVE" if on else "OFF", bg=BG_CARD,
                 fg=GREEN if on else RED,
                 font=(FONT_FAMILY, FS_H2, "bold")).pack(side="left")
        tk.Label(row, text="   Mirror Trading", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, FS_H2, "bold")).pack(side="left")
        PillButton(row, text="Manage", command=lambda: self._show_frame("settings"),
                   bg_color=BG_CARD_ALT, hover_color=BG_ELEVATED,
                   width=92, height=30, font_size=9).pack(side="right")

        facts = tk.Frame(card.inner, bg=BG_CARD)
        facts.pack(fill="x", padx=SP_XL, pady=(0, SP_LG))

        def _fact(label: str, value: str, fg: str = TEXT_PRIMARY) -> None:
            box = tk.Frame(facts, bg=BG_CARD)
            box.pack(side="left", padx=(0, SP_2XL))
            tk.Label(box, text=label, bg=BG_CARD, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, FS_NANO, "bold")).pack(anchor="w")
            tk.Label(box, text=value, bg=BG_CARD, fg=fg,
                     font=(FONT_FAMILY, FS_BODY)).pack(anchor="w", pady=(2, 0))

        _fact("BROKERS ARMED",
              ", ".join(b.capitalize() for b in brokers) if brokers else "none selected",
              TEXT_PRIMARY if brokers else RED)
        _fact("SCHEDULE", _mirror_schedule_label())
        _fact("BUYS", "1 share of each new Reg Alert")
        last_scan = stats.get("last_scan") or {}
        _fact("LAST CHECK",
              (last_scan.get("at") or "—").replace("T", " ")[:16] or "—")

        if not on:
            note = tk.Frame(card.inner, bg=BG_INPUT)
            note.pack(fill="x", padx=SP_XL, pady=(0, SP_LG))
            tk.Label(note, text=icon("info"), bg=BG_INPUT, fg=TEXT_MUTED,
                     font=(ICON_FONT, 11)).pack(side="left", padx=(12, 8), pady=9)
            tk.Label(note, text="Automation is off — nothing new will be bought. "
                                "The history below is kept either way.",
                     bg=BG_INPUT, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 9)).pack(side="left", pady=9)

    def _mirror_render_kpis(self, parent, stats: dict) -> None:
        card = RoundedFrame(parent, bg_color=BG_CARD, border_color=BORDER, radius=RAD_MD)
        card.pack(fill="x", pady=(0, SP_MD))
        head = tk.Frame(card.inner, bg=BG_CARD)
        head.pack(fill="x", padx=SP_XL, pady=(SP_LG, SP_SM))
        tk.Label(head, text=icon("lightning"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 13)).pack(side="left", padx=(0, 9))
        tk.Label(head, text="What automation did", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, FS_H2, "bold")).pack(side="left")
        tk.Label(head, text="last 30 days", bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, FS_MICRO)).pack(side="right")

        grid = tk.Frame(card.inner, bg=BG_CARD)
        grid.pack(fill="x", padx=SP_XL, pady=(0, SP_LG))
        for i in range(4):
            grid.columnconfigure(i, weight=1, uniform="mkpi")

        rate = stats["fill_rate"]
        tiles = [
            ("RUNS", f"{stats['runs']}", f"{stats['symbols']} symbol(s) attempted", TEXT_PRIMARY),
            ("ACCOUNTS FILLED", f"{stats['ok_accounts']}", f"of {stats['attempted']} attempted", GREEN),
            ("FILL RATE", f"{rate * 100:.0f}%" if stats["attempted"] else "—",
             "accounts filled ÷ attempted",
             GREEN if rate >= 0.9 else (YELLOW if rate >= 0.6 else RED)),
            ("FILLED NOWHERE", f"{len(stats['nowhere'])}",
             "picks no broker took", RED if stats["nowhere"] else TEXT_PRIMARY),
        ]
        for col, (label, value, hint, fg) in enumerate(tiles):
            tile = tk.Frame(grid, bg=BG_CARD_ALT, highlightbackground=BORDER,
                            highlightthickness=1)
            tile.grid(row=0, column=col, sticky="nsew",
                      padx=(0, SP_SM) if col < 3 else (0, 0))
            tk.Frame(tile, bg=_blend(ACCENT, BG_CARD_ALT, 0.55), height=2).pack(fill="x")
            inner = tk.Frame(tile, bg=BG_CARD_ALT)
            inner.pack(fill="both", expand=True, padx=SP_MD, pady=SP_MD)
            tk.Label(inner, text=label, bg=BG_CARD_ALT, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, FS_MICRO, "bold")).pack(anchor="w")
            tk.Label(inner, text=value, bg=BG_CARD_ALT, fg=fg,
                     font=(FONT_MONO, 17, "bold")).pack(anchor="w", pady=(SP_XS, 0))
            tk.Label(inner, text=hint, bg=BG_CARD_ALT, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, FS_NANO)).pack(anchor="w")

    def _mirror_render_attention(self, parent, nowhere: list) -> None:
        """Runs that filled at no broker. Mirror never retries, so these are
        the only ones that still need a human."""
        self._exits_group_header(
            parent, "NEEDS ATTENTION", "No broker filled these — mirror does not "
            "retry, so they are still unbought", len(nowhere))
        for run in reversed(nowhere):
            row = tk.Frame(parent, bg=BG_INPUT)
            row.pack(fill="x", pady=(0, 4))
            tk.Frame(row, bg=RED, width=3).pack(side="left", fill="y")
            inner = tk.Frame(row, bg=BG_INPUT)
            inner.pack(side="left", fill="x", expand=True, padx=(12, 12), pady=8)
            tk.Label(inner, text=run.get("symbol", "?"), bg=BG_INPUT, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 11, "bold")).pack(side="left")
            tk.Label(inner,
                     text=f"   {(run.get('started_at') or '').replace('T', ' ')[:16]}"
                          f" · {run.get('fail_accounts', 0)} account(s) rejected",
                     bg=BG_INPUT, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 9)).pack(side="left")
            buy = tk.Label(inner, text="Trade manually →",
                           bg=_blend(ACCENT, BG_INPUT, 0.82), fg=ACCENT_HOVER,
                           font=(FONT_FAMILY, 9, "bold"), padx=10, pady=3,
                           cursor="hand2")
            buy.pack(side="right")
            buy.bind("<Button-1>",
                     lambda e, s=run.get("symbol", ""): self._prefill_trade(s, "buy", "1"))

    def _mirror_render_runs(self, parent, runs: list) -> None:
        if not runs:
            return
        self._exits_group_header(
            parent, "RUN HISTORY",
            "One row per pick automation acted on — click a row for every "
            "broker and account it touched", len(runs))

        day = ""
        for run in runs:
            started = (run.get("started_at") or "")
            rday = started[:10]
            if rday != day:
                day = rday
                tk.Label(parent, text=rday or "—", bg=BG_PRIMARY, fg=TEXT_MUTED,
                         font=(FONT_FAMILY, 8, "bold")).pack(anchor="w", pady=(10, 4))
            self._mirror_run_row(parent, run)

    def _mirror_run_row(self, parent, run: dict) -> None:
        outcome = mirror_journal.run_outcome(run)
        label, color = self._MIRROR_OUTCOMES.get(outcome, ("—", TEXT_MUTED))
        run_id = run.get("id", "")
        opened = run_id in self._mirror_expanded

        wrap = tk.Frame(parent, bg=BG_CARD)
        wrap.pack(fill="x", pady=(0, 4))
        tk.Frame(wrap, bg=color, width=3).pack(side="left", fill="y")
        body = tk.Frame(wrap, bg=BG_CARD)
        body.pack(side="left", fill="x", expand=True)

        row = tk.Frame(body, bg=BG_CARD)
        row.pack(fill="x", padx=(12, 14), pady=9)
        tk.Label(row, text=icon("chevdown" if opened else "chevright"), bg=BG_CARD,
                 fg=TEXT_MUTED, font=(ICON_FONT, 9)).pack(side="left", padx=(0, 8))
        tk.Label(row, text=(run.get("started_at") or "")[11:16], bg=BG_CARD,
                 fg=TEXT_MUTED, font=(FONT_MONO, 9)).pack(side="left", padx=(0, 12))
        tk.Label(row, text=run.get("symbol", "?"), bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 11, "bold")).pack(side="left")
        tk.Label(row, text=f"  {run.get('side', 'buy').upper()} {run.get('qty', '1')}",
                 bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9)).pack(side="left", padx=(0, 12))
        tk.Label(row, text=label, bg=_blend(color, BG_CARD, 0.82), fg=color,
                 font=(FONT_FAMILY, 8, "bold"), padx=8, pady=2).pack(side="left")

        ok = int(run.get("ok_accounts") or 0)
        fail = int(run.get("fail_accounts") or 0)
        tk.Label(row, text=f"  {ok}/{ok + fail} accounts", bg=BG_CARD,
                 fg=TEXT_SECONDARY, font=(FONT_MONO, 9)).pack(side="left", padx=(10, 0))

        meta = []
        if run.get("dry_run"):
            meta.append("DRY RUN")
        meta.append({"schedule": "scheduled",
                     "import": "on import"}.get(run.get("trigger"), "manual"))
        if run.get("slot") and run.get("slot") != "manual":
            meta.append(run["slot"])
        if run.get("elapsed"):
            meta.append(f"{float(run['elapsed']):.1f}s")
        tk.Label(row, text=" · ".join(meta), bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 8)).pack(side="right")

        def _toggle(_e=None, rid=run_id):
            if rid in self._mirror_expanded:
                self._mirror_expanded.discard(rid)
            else:
                self._mirror_expanded.add(rid)
            self._invalidate_page("mirror")
            self._render_mirror()

        self._bind_row_click(row, _toggle)

        if not opened:
            return

        detail = tk.Frame(body, bg=BG_CARD)
        detail.pack(fill="x", padx=(30, 14), pady=(0, 10))

        legs = run.get("legs") or []
        reported = {l.get("broker") for l in legs}
        for leg in sorted(legs, key=lambda l: l.get("broker", "")):
            self._mirror_leg_block(detail, leg)
        # A broker that was armed but never reported: the run died before it
        # got there. Silence would read as "it wasn't tried".
        for broker in run.get("brokers") or []:
            if broker not in reported:
                tk.Label(detail, text=f"{broker.capitalize()} — no result recorded "
                                      f"(run did not complete)",
                         bg=BG_CARD, fg=YELLOW,
                         font=(FONT_FAMILY, 9)).pack(anchor="w", pady=(6, 0))
        if run.get("note"):
            tk.Label(detail, text=f"pick note: {run['note']}  ·  alerted "
                                  f"{run.get('pick_date') or '—'}",
                     bg=BG_CARD, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, 8)).pack(anchor="w", pady=(8, 0))

    def _mirror_leg_block(self, parent, leg: dict) -> None:
        ok = int(leg.get("ok_accounts") or 0)
        fail = int(leg.get("fail_accounts") or 0)
        color = GREEN if ok and not fail else (YELLOW if ok else RED)

        head = tk.Frame(parent, bg=BG_CARD)
        head.pack(fill="x", pady=(8, 2))
        tk.Label(head, text=str(leg.get("broker", "?")).capitalize(), bg=BG_CARD,
                 fg=TEXT_PRIMARY, font=(FONT_FAMILY, 10, "bold")).pack(side="left")
        tk.Label(head, text=f"   {ok} filled · {fail} rejected", bg=BG_CARD,
                 fg=color, font=(FONT_FAMILY, 9)).pack(side="left")
        if leg.get("fill_price") is not None:
            tk.Label(head, text=f"   @ ${float(leg['fill_price']):.4f}".rstrip("0").rstrip("."),
                     bg=BG_CARD, fg=TEXT_SECONDARY,
                     font=(FONT_MONO, 9)).pack(side="left")
        tk.Label(head, text=str(leg.get("state", "")), bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 8)).pack(side="right")

        accounts = leg.get("accounts") or []
        if not accounts:
            reason = (leg.get("errors") or ["no accounts reported"])[0]
            tk.Label(parent, text=f"    ✘  {reason[:150]}", bg=BG_CARD, fg=RED,
                     font=(FONT_FAMILY, 9), wraplength=760,
                     justify="left").pack(anchor="w")
            return
        for acct in accounts:
            good = bool(acct.get("ok"))
            line = tk.Frame(parent, bg=BG_CARD)
            line.pack(fill="x")
            tk.Label(line, text="✔" if good else "✘", bg=BG_CARD,
                     fg=GREEN if good else RED,
                     font=(FONT_FAMILY, 9)).pack(side="left", padx=(16, 8))
            tk.Label(line, text=str(acct.get("account_id") or "—"), bg=BG_CARD,
                     fg=TEXT_SECONDARY, font=(FONT_MONO, 9)).pack(side="left")
            tk.Label(line, text=f"  {str(acct.get('message') or '')[:130]}",
                     bg=BG_CARD, fg=TEXT_MUTED if good else RED,
                     font=(FONT_FAMILY, 9)).pack(side="left")

    def _mirror_render_scans(self, parent, scans: list) -> None:
        """Every time the schedule woke up — including the quiet ones.

        A check that queued nothing is the entry that proves automation is alive,
        and its skip list is where "why didn't it buy that one" gets answered.
        """
        if not scans:
            return
        self._exits_group_header(
            parent, "FEED CHECKS", "Each time automation looked at the feed, and "
            "what it passed over", len(scans))
        for scan in scans:
            row = tk.Frame(parent, bg=BG_PRIMARY)
            row.pack(fill="x", pady=(0, 2))
            tk.Label(row, text=(scan.get("at") or "").replace("T", " ")[:16],
                     bg=BG_PRIMARY, fg=TEXT_MUTED,
                     font=(FONT_MONO, 9)).pack(side="left", padx=(0, 12))
            queued = int(scan.get("queued") or 0)
            tk.Label(row, text=f"{scan.get('considered', 0)} pick(s) seen",
                     bg=BG_PRIMARY, fg=TEXT_SECONDARY,
                     font=(FONT_FAMILY, 9)).pack(side="left")
            tk.Label(row, text=f"  ·  {queued} queued" if queued else "  ·  nothing new",
                     bg=BG_PRIMARY, fg=ACCENT if queued else TEXT_MUTED,
                     font=(FONT_FAMILY, 9)).pack(side="left")
            tk.Label(row, text=scan.get("slot") or "", bg=BG_PRIMARY, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, 8)).pack(side="right")
            for skip in (scan.get("skipped") or [])[:12]:
                tk.Label(parent,
                         text=f"      {skip.get('symbol', '?')} — {skip.get('reason', 'skipped')}",
                         bg=BG_PRIMARY, fg=TEXT_MUTED,
                         font=(FONT_FAMILY, 8)).pack(anchor="w")

    # ---- Exits (the TRACK board) ------------------------------------------
    #
    # The BUY feed says what to open. This page says what to CLOSE, which the
    # app previously had no answer for at all — you had to read the Discord
    # board yourself and remember which brokers were worth trying.
    #
    # The routing rule is the whole point and lives in lifecycle.brokers_for():
    # a fractional play is only sellable at Public, Robinhood and SoFi, because
    # everyone else settled it to cash and holds nothing. A round-up leaves a
    # whole share and sells anywhere.

    def _track_channel(self) -> str:
        return _env("DISCORD_LIFECYCLE_CHANNEL") or _env("DISCORD_TRACK_CHANNEL")

    def _build_exits(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["exits"] = frame

        head = tk.Frame(frame, bg=BG_PRIMARY)
        head.pack(fill="x", pady=(0, 12))
        self._exits_summary = tk.Label(
            head, text="Board not pulled yet", bg=BG_PRIMARY, fg=TEXT_SECONDARY,
            font=(FONT_FAMILY, 10))
        self._exits_summary.pack(side="left")
        self._exits_stamp = tk.Label(head, text="", bg=BG_PRIMARY, fg=TEXT_MUTED,
                                     font=(FONT_FAMILY, 8))
        self._exits_stamp.pack(side="right")

        self._build_autosell_card(frame)

        outer, self._exits_list = self._make_vscroll(frame)
        outer.pack(fill="both", expand=True)
        self._render_exits()

    def _build_autosell_card(self, parent) -> None:
        """The arming switch, and the sentence that says what arming it means.

        Sits at the top of the page it acts on rather than in Settings: this
        places live orders without asking, and a control like that belongs where
        its consequences are listed, not two screens away from them.
        """
        card = RoundedFrame(parent, bg_color=BG_CARD, border_color=BORDER, radius=RAD_MD)
        card.pack(fill="x", pady=(0, 12))
        body = tk.Frame(card.inner, bg=BG_CARD)
        body.pack(fill="x", padx=SP_XL, pady=SP_MD)

        row = tk.Frame(body, bg=BG_CARD)
        row.pack(fill="x")
        tk.Label(row, text=f"{icon('lightning')}  AUTO-SELL FRACTIONALS", bg=BG_CARD,
                 fg=TEXT_PRIMARY, font=(ICON_FONT, 11, "bold")).pack(side="left")
        self._autosell_pill = tk.Label(row, text="", bg=BG_CARD,
                                       font=(FONT_FAMILY, 9, "bold"))
        self._autosell_pill.pack(side="right")

        tk.Label(body, bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 8),
                 justify="left", anchor="w", wraplength=760,
                 text=("A fraction is what's left when a split did NOT round you up — "
                       "there is no round-up coming, and it drifts down while it sits. "
                       "When armed, a board pull that turns a play fractional reads your "
                       "live holdings and sells it at the brokers that hold fractions "
                       "(Public, Robinhood, SoFi) without asking. Market hours only; "
                       f"at most {AUTOSELL_MAX_PER_PULL} plays per pull; never the same "
                       "play twice.")).pack(fill="x", pady=(6, 10))

        opts = tk.Frame(body, bg=BG_CARD)
        opts.pack(fill="x")
        for var, text in ((self._autosell_enabled, "Arm auto-sell"),
                          (self._autosell_dry_run, "Dry run (build the order, don't send it)"),
                          (self._autosell_roundups, "Round-ups too, not just fractionals")):
            tk.Checkbutton(
                opts, text=text, variable=var, command=self._autosell_toggled,
                bg=BG_CARD, fg=TEXT_SECONDARY, activebackground=BG_CARD,
                activeforeground=TEXT_PRIMARY, selectcolor=BG_INPUT,
                font=(FONT_FAMILY, 9), anchor="w", bd=0, highlightthickness=0,
            ).pack(anchor="w")

        # Catching up is a different job from keeping up: auto-sell fires on a
        # transition, so a position that was ALREADY fractional when you armed
        # it is never picked up. This is how the backlog gets cleared.
        self._sweep_btn = tk.Button(
            body, text="Sell all fractionals now", command=self._autosell_sweep,
            bg=BG_INPUT, fg=TEXT_PRIMARY, activebackground=BG_CARD,
            activeforeground=TEXT_PRIMARY, font=(FONT_FAMILY, 9, "bold"),
            relief="flat", bd=0, padx=14, pady=7, cursor="hand2",
        )
        btn_row = tk.Frame(body, bg=BG_CARD)
        btn_row.pack(anchor="w", pady=(10, 0))
        self._sweep_btn.pack(in_=btn_row, side="left")

        # "Sold once, ever" is what stops a re-pull selling twice, and it is
        # also what makes a play that FAILED disappear from the sweep for good.
        # Without a way back, one bad afternoon — a wedged SoFi login, a
        # position that had already left the account — silently empties the
        # worklist and the button starts reporting "nothing to sell" over a
        # board full of fractionals.
        self._retry_btn = tk.Button(
            btn_row, text="Retry skipped", command=self._autosell_clear_skipped,
            bg=BG_CARD, fg=TEXT_MUTED, activebackground=BG_CARD,
            activeforeground=TEXT_PRIMARY, font=(FONT_FAMILY, 9),
            relief="flat", bd=0, padx=12, pady=7, cursor="hand2",
        )
        self._retry_btn.pack(side="left", padx=(8, 0))

        self._autosell_toggled(save=False)

    def _autosell_clear_skipped(self) -> None:
        """Forget which plays have been attempted, so the sweep offers them again.

        Deliberately does NOT touch anything else: the journal still knows what
        actually sold, and the live holdings read still refuses to place an
        order into an empty account. The worst this can do is make auto-sell
        look at a play a second time and find nothing there.
        """
        n = len(self._autosell_sold)
        if not n:
            self._sweep_say("Nothing has been skipped")
            return
        self._autosell_sold.clear()
        self._autosell_fails.clear()
        self._save_autosell_state()
        self._log(f"Auto-sell: cleared {n} attempted play(s) — the sweep will "
                  f"offer them again.")
        self._sweep_say(f"Cleared {n} — press Sell all fractionals")

    def _autosell_toggled(self, save: bool = True) -> None:
        armed = bool(self._autosell_enabled.get())
        dry = bool(self._autosell_dry_run.get())
        if not armed:
            text, colour = "DISARMED", TEXT_MUTED
        elif dry:
            text, colour = "ARMED · DRY RUN", YELLOW
        else:
            text, colour = "ARMED · LIVE ORDERS", RED
        if hasattr(self, "_autosell_pill"):
            self._autosell_pill.configure(text=text, fg=colour)
        if save:
            self._save_autosell_state()
            if armed and not dry:
                # Said once, plainly, at the moment it becomes true.
                self._push_notification(
                    "Auto-sell is live — fractional plays will be sold without "
                    "confirmation", "warning")

    def _exits_group_header(self, parent, title: str, sub: str, count: int) -> None:
        box = tk.Frame(parent, bg=BG_PRIMARY)
        box.pack(fill="x", pady=(14, 8))
        row = tk.Frame(box, bg=BG_PRIMARY)
        row.pack(fill="x")
        tk.Label(row, text=title, bg=BG_PRIMARY, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 11, "bold")).pack(side="left")
        tk.Label(row, text=f"  {count}", bg=BG_PRIMARY, fg=ACCENT,
                 font=(FONT_FAMILY, 11, "bold")).pack(side="left")
        tk.Label(box, text=sub, bg=BG_PRIMARY, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 8)).pack(anchor="w", pady=(2, 0))

    def _render_exits(self) -> None:
        if not hasattr(self, "_exits_list"):
            return
        for w in self._exits_list.winfo_children():
            w.destroy()

        if not self._track_available():
            self._empty_state(
                self._exits_list, "warning", "No board source available",
                "The round-up board comes down with the play feed, which needs "
                "the 'requests' package installed — run "
                "py -3.13 -m pip install -r requirements.txt. Running the feed yourself? "
                "Set DISCORD_LIFECYCLE_CHANNEL in .env instead.").pack(fill="x")
            return
        if self._track_error:
            self._empty_state(
                self._exits_list, "error", "Could not read the board",
                self._track_error).pack(fill="x")
            return
        if not self._track_rows:
            self._empty_state(
                self._exits_list, "export", "Board not pulled yet",
                "Hit Refresh Board, or leave the app open — it re-reads the "
                "board every hour.").pack(fill="x")
            return

        tasks = lifecycle.sell_worklist(self._track_rows)
        frac = [t for t in tasks if t.is_fractional]
        whole = [t for t in tasks if not t.is_fractional]
        # Summary shares this worklist: recomputing it there re-read and
        # re-folded the whole trade journal a second time per render.
        self._update_exits_summary(tasks)

        if not tasks:
            self._empty_state(
                self._exits_list, "check", "Nothing to sell",
                f"{len(self._track_rows)} plays on the board, none of them "
                "resolved into a position you still hold.").pack(fill="x")
            return

        if frac:
            self._exits_group_header(
                self._exits_list, "FRACTIONAL",
                "A fraction came back. Only "
                f"{', '.join(rsa_feed.FRACTIONAL_BROKERS)} return one — everyone "
                "else already settled it to cash, so there is nothing to sell there.",
                len(frac))
            for t in frac:
                self._exits_row(t)

        if whole:
            self._exits_group_header(
                self._exits_list, "ROUND-UP / CANCELLED",
                "A whole share exists. Sellable at any broker you hold it in.",
                len(whole))
            for t in whole:
                self._exits_row(t)

    def _exits_row(self, task) -> None:
        accent = ACCENT if task.is_fractional else GREEN
        row = tk.Frame(self._exits_list, bg=BG_CARD)
        row.pack(fill="x", pady=(0, 6))
        tk.Frame(row, bg=accent, width=3).pack(side="left", fill="y")
        body = tk.Frame(row, bg=BG_CARD)
        body.pack(side="left", fill="x", expand=True, padx=16, pady=12)

        left = tk.Frame(body, bg=BG_CARD)
        left.pack(side="left")
        sym_row = tk.Frame(left, bg=BG_CARD)
        sym_row.pack(anchor="w")
        tk.Label(sym_row, text=task.symbol, bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 16, "bold")).pack(side="left")
        if task.renamed:
            # The journal knows the old ticker; only the new one can be traded.
            badge = tk.Frame(sym_row, bg=BG_ELEVATED)
            badge.pack(side="left", padx=(8, 0))
            tk.Label(badge, text=f" was {task.alert_symbol} ", bg=BG_ELEVATED,
                     fg=YELLOW, font=(FONT_FAMILY, 8, "bold")).pack()

        meta = tk.Frame(left, bg=BG_CARD)
        meta.pack(anchor="w", pady=(2, 0))
        tk.Label(meta, text=task.status.replace("_", " ").upper(), bg=BG_CARD,
                 fg=accent, font=(FONT_FAMILY, 8, "bold")).pack(side="left")
        tk.Label(meta, text=f"   ·   {task.alert_date}", bg=BG_CARD, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 8)).pack(side="left")
        tk.Label(meta,
                 text=f"   ·   {task.accounts} acct(s) at {', '.join(task.brokers)}",
                 bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8)).pack(side="left")
        if task.skipped_brokers:
            # Shown, not hidden: "why isn't Fidelity in the list" is the first
            # question this page has to answer.
            tk.Label(meta,
                     text=f"   ·   cash-in-lieu at {', '.join(task.skipped_brokers)}",
                     bg=BG_CARD, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, 8)).pack(side="left")

        act = tk.Frame(body, bg=BG_CARD)
        act.pack(side="right")
        tk.Label(act, text=icon("trade"), bg=BG_CARD, fg=TEXT_MUTED,
                 font=(ICON_FONT, 12), cursor="hand2").pack(side="right", padx=(14, 0))
        act.winfo_children()[-1].bind(
            "<Button-1>", lambda e, t=task: self._exit_trade(t))
        PillButton(act, text="Sell", command=lambda t=task: self._exit_sell(t),
                   width=76, height=30, font_size=9).pack(side="right")

    def _exit_trade(self, task) -> None:
        """Open the Trade Desk primed for this exit, without firing.

        The manual route, kept for when you want to override the quantity or add
        a broker the routing rule excluded.
        """
        self._show_frame("trade")
        try:
            self._set_trade_side("sell")
            self._trade_symbol.delete(0, "end")
            self._trade_symbol.insert(0, task.symbol)
            self._trade_qty.delete(0, "end")
            if not task.is_fractional:
                self._trade_qty.insert(0, "1")     # a round-up is exactly one

            # Preselect only the brokers that can actually fill this.
            want = {lifecycle.app_key(b) for b in task.brokers}
            for broker, chip in self._trade_broker_chips.items():
                should = broker in want
                if chip["selected"] != should:
                    self._toggle_broker_chip(broker)
        except Exception as exc:
            self._log(f"Exits: could not prime the ticket ({exc})", "warn")

        if task.is_fractional:
            self._push_notification(
                f"{task.symbol}: enter the fractional qty — it differs per account.",
                "warning")

    # ---- One-click exit: resolve the quantity, confirm, then fire ----------

    def _exit_sell(self, task) -> None:
        """Read the real balances, then show exactly what will be sold where.

        The board says a play resolved, never how much came back — a 1-for-20 on
        a $0.25 name leaves 0.05 of a share and only the broker knows the figure
        it credited. So this reads live holdings first and never guesses.
        """
        if getattr(self, "_trade_in_flight", False):
            self._push_notification(
                "A trade is already running — wait for it to finish.", "warning")
            return
        if self._exit_busy:
            return
        self._exit_busy = True
        self._push_notification(
            f"Reading {task.symbol} balances at {', '.join(task.brokers)}…", "info")
        self._run_in_thread(self._exit_resolve_worker, task)

    def _exit_resolve_worker(self, task, then=None) -> None:
        """Fetch holdings from just the eligible brokers, in parallel.

        Only the brokers that can actually fill this order are contacted — a
        fractional play never touches the seven that paid cash, so this is three
        sessions rather than ten.

        `then` receives the ResolvedExit on the UI thread. It defaults to the
        confirmation dialog, which is what a human clicking Sell wants; auto-sell
        passes its own so it can reuse this holdings read rather than keeping a
        second copy of it in step with this one.
        """
        outputs: Dict[str, Any] = {}
        lock = threading.Lock()

        def fetch(key: str) -> None:
            out = None
            try:
                out = _load_broker(key).get_holdings()
            except Exception as exc:
                self.after(0, lambda b=key, e=exc: self._log(
                    f"Exits: {b} holdings failed — {e}", "warn"))
            with lock:
                outputs[key] = out

        threads = []
        for broker in task.brokers:
            key = lifecycle.app_key(broker)
            if key not in BROKER_MODULES:
                continue
            t = threading.Thread(target=fetch, args=(key,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        resolved = lifecycle.resolve(task, outputs)
        cb = then or self._exit_confirm
        self.after(0, lambda: cb(resolved))

    def _exit_confirm(self, resolved) -> None:
        """Show the resolved order and require a click before anything is sent.

        A sell is not undoable, so the numbers are shown before they are used
        rather than reported afterwards — including every reason a broker fell
        out of the order.
        """
        self._exit_busy = False
        task = resolved.task

        if not resolved.ok:
            why = []
            if resolved.missing:
                why.append(f"no {task.symbol} position at {', '.join(resolved.missing)}")
            if resolved.errors:
                why.append(f"couldn't read {', '.join(resolved.errors)}")
            self._push_notification(
                f"{task.symbol}: nothing to sell — {'; '.join(why) or 'no balances found'}",
                "warning")
            return

        dlg = tk.Toplevel(self)
        dlg.title(f"Sell {task.symbol}")
        dlg.configure(bg=BG_CARD)
        dlg.transient(self)
        dlg.resizable(False, False)

        head = tk.Frame(dlg, bg=BG_CARD)
        head.pack(fill="x", padx=22, pady=(20, 6))
        tk.Label(head, text=f"SELL {task.symbol}", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 17, "bold")).pack(side="left")
        tk.Label(head, text=f"  {task.status.replace('_', ' ')}", bg=BG_CARD,
                 fg=ACCENT if task.is_fractional else GREEN,
                 font=(FONT_FAMILY, 9, "bold")).pack(side="left", pady=(6, 0))
        if task.renamed:
            tk.Label(dlg, text=f"Bought as {task.alert_symbol} — sells as {task.symbol}",
                     bg=BG_CARD, fg=YELLOW, font=(FONT_FAMILY, 8)).pack(
                         anchor="w", padx=22)

        tk.Label(dlg, text="Quantities read live from each broker just now:",
                 bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 8)).pack(
                     anchor="w", padx=22, pady=(10, 6))

        for leg in resolved.legs:
            row = tk.Frame(dlg, bg=BG_CARD_ALT)
            row.pack(fill="x", padx=22, pady=(0, 4))
            tk.Label(row, text=leg.broker, bg=BG_CARD_ALT, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 10, "bold"), width=14, anchor="w").pack(
                         side="left", padx=12, pady=9)
            tk.Label(row, text=f"{leg.qty}  ×  {leg.accounts} acct(s)",
                     bg=BG_CARD_ALT, fg=TEXT_PRIMARY,
                     font=(FONT_MONO, 10)).pack(side="left")
            if not leg.uniform:
                # Sending the max would reject the whole leg, so we send the
                # smallest — but that leaves shares behind and you should know.
                tk.Label(row, text=f"  accounts differ ({leg.low:g}–{leg.high:g}) — "
                                   f"{leg.stranded:g} left behind",
                         bg=BG_CARD_ALT, fg=YELLOW,
                         font=(FONT_FAMILY, 8)).pack(side="left", padx=(10, 0))

        notes = []
        if resolved.missing:
            notes.append(f"No position found at {', '.join(resolved.missing)} — skipped.")
        if resolved.errors:
            notes.append(f"Could not read {', '.join(resolved.errors)} — not sold.")
        if task.skipped_brokers:
            notes.append(f"{', '.join(task.skipped_brokers)} settled to cash-in-lieu.")
        for n in notes:
            tk.Label(dlg, text=n, bg=BG_CARD, fg=TEXT_MUTED,
                     font=(FONT_FAMILY, 8), wraplength=460, justify="left").pack(
                         anchor="w", padx=22, pady=(4, 0))

        # Dry run: every broker walks its whole ticket flow — log in, enumerate
        # accounts, build the order with this exact quantity — and stops before
        # submitting, writing a ticket log per account. It is the only way to
        # exercise a fractional sell end to end without selling anything, so it
        # is offered right here rather than buried on the Trade Desk.
        dry = tk.BooleanVar(value=False)
        dry_row = tk.Frame(dlg, bg=BG_CARD)
        dry_row.pack(fill="x", padx=22, pady=(14, 0))
        tk.Checkbutton(
            dry_row, text="  Dry run — build the order, submit nothing",
            variable=dry, bg=BG_CARD, fg=TEXT_SECONDARY, selectcolor=BG_INPUT,
            activebackground=BG_CARD, activeforeground=TEXT_PRIMARY,
            highlightthickness=0, bd=0, font=(FONT_FAMILY, 9),
            anchor="w").pack(anchor="w")

        btns = tk.Frame(dlg, bg=BG_CARD)
        btns.pack(fill="x", padx=22, pady=(18, 20))
        PillButton(btns, text=f"Sell at {len(resolved.legs)} broker(s)",
                   command=lambda: (dlg.destroy(),
                                    self._exit_fire(resolved, dry_run=dry.get())),
                   width=190, height=38, font_size=10).pack(side="right")
        PillButton(btns, text="Cancel", command=dlg.destroy,
                   bg_color=BG_CARD_ALT, hover_color=BG_ELEVATED,
                   width=96, height=38, font_size=10).pack(side="right", padx=(0, 8))
        PillButton(btns, text="Open in Desk",
                   command=lambda: (dlg.destroy(), self._exit_trade(task)),
                   bg_color=BG_CARD_ALT, hover_color=BG_ELEVATED,
                   width=124, height=38, font_size=10).pack(side="left")

        dlg.update_idletasks()
        dlg.geometry(f"+{self.winfo_rootx() + 220}+{self.winfo_rooty() + 170}")
        dlg.grab_set()

    def _exit_fire(self, resolved, dry_run: bool = False) -> None:
        """Place the sells — one thread per broker, each with its own quantity.

        Reuses the Trade Desk batch machinery so an exit gets the same live
        strip, completion receipt and double-submit guard as a manual order.

        With `dry_run` each broker builds the real ticket against its live
        session and stops short of submitting, leaving a per-account log. That
        exercises everything except the final API call: the routing, the
        holdings read, the quantity string, the session and the account fan-out.
        """
        if getattr(self, "_trade_in_flight", False):
            self._push_notification(
                "A trade is already running — wait for it to finish.", "warning")
            return

        task = resolved.task
        keys = [leg.key for leg in resolved.legs]
        batch = {
            "pending": set(keys),
            "all_brokers": sorted(keys),
            "results": [],
            "side": "sell",
            "symbol": task.symbol,
            # Informational only: the completion receipt sums the shares each
            # broker actually reported. Each leg carries its own size below,
            # and they legitimately differ, so there is no single batch qty.
            "qty": (resolved.legs[0].qty
                    if len({l.qty for l in resolved.legs}) == 1 else "mixed"),
            "dry_run": dry_run,
            "origin": "exit",
            "finished": False,
            "started": datetime.now(),
        }
        self._trade_in_flight = True
        self._trade_batch = batch
        self._log(f"Exit: SELL {task.symbol} — {resolved.describe()}"
                  + (" [DRY RUN]" if dry_run else ""))
        self._live_start(batch)
        for leg in resolved.legs:
            self._run_in_thread(self._trade_worker, leg.key, "sell",
                                task.symbol, leg.qty, dry_run, batch)

    # ---- Auto-sell fractionals ---------------------------------------------
    #
    # A fraction is a wasting asset. It exists because a reverse split did NOT
    # round the position up, so there is no round-up coming and nothing to wait
    # for — only a thin post-split name that drifts down while it sits. Selling
    # it the moment the board says "fractional" is the whole of the edge, and
    # doing that by hand means noticing a notification, opening a tab, reading
    # holdings and clicking three brokers.
    #
    # So this closes the last gap in a pipeline that already existed:
    #
    #   lifecycle.pull() -> Transition.became_fractional
    #   sell_worklist()  -> SellTask, per broker, renamed tickers handled
    #   resolve()        -> the exact fraction, read from LIVE HOLDINGS
    #   _exit_fire()     -> the order, with the batch machinery and the
    #                       double-submit guard a manual sell gets
    #
    # It places real orders with nobody watching, so every guard below is load
    # bearing and none of them is decoration:
    #
    #   OFF BY DEFAULT     it must be switched on deliberately, once.
    #   MARKET HOURS ONLY  a market order into a closed book is how you find out
    #                      what a wide spread costs. Out of hours it queues.
    #   ONE AT A TIME      _exit_fire refuses to start while a trade is running,
    #                      so a queue that fired in parallel would silently drop
    #                      every play after the first.
    #   SOLD ONCE, EVER    keyed by alert_date:SYMBOL and remembered on disk. A
    #                      board that re-reports a row, a restart mid-pull, a
    #                      re-pull an hour later — none of them may sell twice.
    #   A CAP PER PULL     see AUTOSELL_MAX_PER_PULL.
    #   DRY RUN            builds the real ticket against the live session and
    #                      stops short of submitting, so a full cycle can be
    #                      watched before any money moves.

    def _load_autosell_state(self) -> Dict[str, Any]:
        import json
        if AUTOSELL_STATE_FILE.exists():
            try:
                return json.loads(AUTOSELL_STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"enabled": False, "dry_run": True, "include_roundups": False, "sold": []}

    def _save_autosell_state(self) -> None:
        import json
        state = {
            "enabled": bool(self._autosell_enabled.get()),
            "dry_run": bool(self._autosell_dry_run.get()),
            "include_roundups": bool(self._autosell_roundups.get()),
            # Bounded: this only has to outlive a re-pull of the same board, and
            # an unbounded list would grow for the life of the install.
            "sold": list(self._autosell_sold)[-500:],
        }
        try:
            AUTOSELL_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except OSError as exc:
            self._log(f"Auto-sell: could not save state — {exc}", "warn")

    def _autosell_key(self, task) -> str:
        """One play's identity. The ALERT symbol, deliberately: a play that
        renames mid-life (AGAE -> AIFA) is still the same position, and keying
        on the sell symbol would let it be sold once under each name."""
        return f"{task.alert_date}:{task.alert_symbol.upper()}"

    def _autosell_consider(self, changes) -> None:
        """Decide what this TRACK pull should sell, and start the queue."""
        if not getattr(self, "_autosell_enabled", None) or not self._autosell_enabled.get():
            return

        want_roundups = bool(self._autosell_roundups.get())
        fresh = [c for c in changes
                 if c.became_fractional or (want_roundups and c.became_sellable)]
        if not fresh:
            return

        # Only rows this pull moved, and only ones we hold somewhere. The
        # worklist already scopes brokers by status, so a fractional play offers
        # only the three that hold fractions.
        moved = {f"{c.alert_date}:{c.symbol.upper()}" for c in fresh}
        tasks = [t for t in lifecycle.sell_worklist(self._track_rows)
                 if f"{t.alert_date}:{t.alert_symbol.upper()}" in moved and t.brokers]

        tasks = [t for t in tasks if self._autosell_key(t) not in self._autosell_sold]
        if not tasks:
            return

        if len(tasks) > AUTOSELL_MAX_PER_PULL:
            held = [t.symbol for t in tasks[AUTOSELL_MAX_PER_PULL:]]
            self._log(f"Auto-sell: {len(tasks)} plays became sellable at once — "
                      f"selling {AUTOSELL_MAX_PER_PULL}, leaving {', '.join(held)} "
                      f"for you. That many at once usually means the board "
                      f"changed shape, not that {len(tasks)} splits resolved.", "warn")
            self._push_notification(
                f"Auto-sell held back {len(held)} plays — check the Exits tab", "warning")
            tasks = tasks[:AUTOSELL_MAX_PER_PULL]

        state, label, _ = _market_status()
        if state != "open":
            # Queued, not dropped. The next pull inside the session picks them
            # up because they are still unsold and still on the board.
            self._log(f"Auto-sell: {len(tasks)} play(s) ready but {label.lower()} — "
                      f"holding until the open.", "meta")
            self._push_notification(
                f"{len(tasks)} fractional play(s) waiting for the open", "info")
            return

        self._autosell_queue.extend(tasks)
        self._log(f"Auto-sell: queued {len(tasks)} play(s) — "
                  f"{', '.join(t.symbol for t in tasks)}"
                  + (" [DRY RUN]" if self._autosell_dry_run.get() else ""))
        self._autosell_pump()

    def _autosell_sweep(self) -> None:
        """Sell everything fractional you are holding RIGHT NOW.

        Auto-sell above fires on a TRANSITION — a play the board just moved into
        fractional. That is correct for keeping up, and useless for catching up:
        `became_fractional` is false for a row that was already fractional when
        you armed it, so the backlog you had on day one would sit there forever
        while every new play sailed past it.

        So this is the other half, and it is a button rather than automatic
        because sweeping a backlog is a decision with a date on it — the
        positions have been sitting a while and the reason may not be inertia.
        Everything downstream is identical: the same queue, the same one-at-a-
        time pump, the same sold-once record, the same dry-run switch.
        """
        # Every refusal below says so ON THE BUTTON. A notification in the bell
        # and a line in the Activity log are both on other screens, so a sweep
        # that declined to run was indistinguishable from a sweep that did
        # nothing — you press it twice and watch an unchanged page.
        if not self._track_rows:
            self._sweep_say("Pull the board first")
            self._push_notification("Pull the board first — nothing to sweep.", "warning")
            return

        fractional = [t for t in lifecycle.sell_worklist(self._track_rows)
                      if t.brokers and t.is_fractional]
        tasks = [t for t in fractional
                 if self._autosell_key(t) not in self._autosell_sold]
        if not tasks:
            # "Nothing to sell" and "everything here has already been tried" are
            # completely different answers, and showing the first when the
            # second is true is how a full worklist reads as an empty one.
            held_back = len(fractional)
            if held_back:
                self._sweep_say(f"All {held_back} already tried — use Retry skipped",
                                hold_ms=5000)
                self._push_notification(
                    f"{held_back} fractional play(s) on the board have already been "
                    f"attempted. Retry skipped to try them again.", "info")
            else:
                self._sweep_say("Nothing fractional to sell")
                self._push_notification("No fractional positions to sell.", "info")
            return

        state, label, _ = _market_status()
        if state != "open":
            self._sweep_say(f"{label} — not selling")
            self._push_notification(
                f"{label} — a market order now would pay the whole spread. "
                f"{len(tasks)} play(s) ready when it opens.", "warning")
            return

        if getattr(self, "_trade_in_flight", False):
            self._sweep_say("A trade is already running")
            return

        # Two clicks, and the second one knows the count. No modal: the button
        # states what it is about to do and waits, which is the same protection
        # with none of the dialog's ability to be dismissed by reflex.
        if not getattr(self, "_sweep_armed", False):
            self._sweep_armed = True
            syms = ", ".join(t.symbol for t in tasks[:6])
            more = f" +{len(tasks) - 6} more" if len(tasks) > 6 else ""
            self._sweep_btn.configure(
                text=f"Confirm: sell {len(tasks)} — {syms}{more}", bg=RED)
            # Long enough to actually read the tickers before deciding. At 8s
            # this expired while you were still reading it, so the second click
            # only re-armed and the button appeared to do nothing.
            self.after(20000, self._autosell_sweep_disarm)
            return

        self._sweep_armed = False
        self._autosell_queue.extend(tasks)
        self._log(f"Sweep: queued {len(tasks)} fractional play(s) — "
                  f"{', '.join(t.symbol for t in tasks)}"
                  + (" [DRY RUN]" if self._autosell_dry_run.get() else ""))
        # Reading holdings across three brokers takes tens of seconds and every
        # word of progress goes to the Activity log on another page. Without
        # this the button falls straight back to its resting label and the whole
        # sweep looks like a click that did nothing.
        self._sweep_progress()
        self._autosell_pump()

    def _sweep_say(self, msg: str, hold_ms: int = 3000) -> None:
        """Put a sentence on the button, then let it go back to normal."""
        if not hasattr(self, "_sweep_btn"):
            return
        self._sweep_armed = False
        self._sweep_btn.configure(text=msg, bg=BG_INPUT)
        self.after(hold_ms, self._autosell_sweep_disarm)

    def _sweep_progress(self) -> None:
        """Follow the queue on the button until it drains."""
        if not hasattr(self, "_sweep_btn"):
            return
        left = len(self._autosell_queue)
        busy = getattr(self, "_trade_in_flight", False)
        if not left and not busy:
            self._sweep_btn.configure(text="Done — check Activity for the fills",
                                      bg=BG_INPUT)
            self.after(6000, self._autosell_sweep_disarm)
            return
        self._sweep_btn.configure(
            text=(f"Working… {left} left" if left else "Working… placing the order"),
            bg=BG_INPUT)
        self.after(1500, self._sweep_progress)

    def _autosell_sweep_disarm(self) -> None:
        self._sweep_armed = False
        if not hasattr(self, "_sweep_btn"):
            return
        # The arm timer is still pending when a sweep actually starts, so
        # without this it fires mid-run and wipes the progress label — putting
        # "Sell all fractionals now" back on screen while orders are going out.
        if self._autosell_queue or getattr(self, "_trade_in_flight", False):
            return
        self._sweep_btn.configure(text="Sell all fractionals now", bg=BG_INPUT)

    def _autosell_pump(self) -> None:
        """Start the next play once the previous one has finished.

        Strictly sequential: _exit_fire refuses to begin while a trade is in
        flight, so firing the queue in parallel would place the first order and
        silently discard the rest.
        """
        if not self._autosell_queue:
            self._autosell_waits = 0
            return
        if getattr(self, "_trade_in_flight", False):
            # Wait, but not forever. A broker that hangs holds _trade_in_flight
            # true, and without a ceiling the rest of the list waits behind it
            # in silence for the life of the process — which reads exactly like
            # auto-sell being off. Say so, then stand down rather than spinning
            # a timer every five seconds until the app is closed.
            self._autosell_waits = getattr(self, "_autosell_waits", 0) + 1
            if self._autosell_waits > AUTOSELL_WAIT_TICKS:
                left = ", ".join(t.symbol for t in self._autosell_queue)
                self._autosell_waits = 0
                self._autosell_queue.clear()
                self._log(f"Auto-sell: a trade has been running for "
                          f"{AUTOSELL_WAIT_TICKS * 5 // 60} minutes — giving up on "
                          f"{left}. They stay on the Exits tab to sell by hand.",
                          "warn")
                self._push_notification(
                    f"Auto-sell stalled behind a slow trade — {left} not sold",
                    "warning")
                return
            self.after(5000, self._autosell_pump)
            return
        self._autosell_waits = 0

        task = self._autosell_queue.pop(0)
        key = self._autosell_key(task)
        if key in self._autosell_sold:              # a re-queue between ticks
            self.after(200, self._autosell_pump)
            return

        # Claimed BEFORE the holdings read, not after the order. Everything from
        # here on can fail in ways that leave an order placed, and selling twice
        # is far worse than not selling automatically once.
        self._autosell_sold.add(key)
        self._save_autosell_state()

        self._log(f"Auto-sell: reading {task.symbol} holdings at "
                  f"{', '.join(task.brokers)}…")
        self._run_in_thread(self._autosell_resolve, task)

    def _autosell_resolve(self, task) -> None:
        """Read holdings for one play, then hand it to _autosell_fire.

        A wrapper, and it is the difference between a queue and a list that
        stops at the first bad play. _exit_resolve_worker ends by scheduling its
        callback; if anything above that line raises — a broker module blowing
        up on import, a session object in a state lifecycle.resolve did not
        expect — the callback never runs, nothing ever calls the pump again, and
        every remaining play sits in the queue forever with no error on screen.

        A queue that dies silently is worse than one that never started, because
        the first four plays sold and you have no reason to check the fifth.
        """
        try:
            self._exit_resolve_worker(task, self._autosell_fire)
        except Exception as exc:                # noqa: BLE001 — must never escape
            self.after(0, lambda t=task, e=exc: self._autosell_abandon(t, str(e)))

    def _autosell_abandon(self, task, why: str) -> None:
        """Give up on one play, say so, and keep going."""
        self._autosell_retry(task, why)         # unclaim: nothing was placed
        self._log(f"Auto-sell: {task.symbol} failed — {why}", "error")
        self._push_notification(f"Auto-sell couldn't handle {task.symbol}: {why}",
                                "warning")
        self.after(1000, self._autosell_pump)

    def _autosell_retry(self, task, why: str) -> None:
        """Give a play back so a later pull can try it again — up to a point.

        The claim in _autosell_pump is taken BEFORE the holdings read, because
        the alternative — claiming it after the order — risks selling twice.
        The cost of that choice is that anything which fails between the claim
        and the order would strand the play as "sold" forever, so every such
        path has to hand it back explicitly.

        THE POINT, and it is why this counts: handing it back unconditionally
        is a loop. A broker that cannot log in at all — SoFi sitting behind a
        Turnstile human check is the live example — fails the holdings read
        every single time, so the play is unclaimed, re-queued on the next pull,
        and drives another login attempt. Forever, once an hour, plus once per
        sweep click. "Why does SoFi keep trying to log in" is this function
        with no ceiling on it.

        After AUTOSELL_MAX_ATTEMPTS the play stays claimed and says so. It is
        still on the Exits tab to sell by hand, which is the correct escalation
        for something no amount of retrying will fix.
        """
        key = self._autosell_key(task)
        n = self._autosell_fails.get(key, 0) + 1
        self._autosell_fails[key] = n

        if n >= AUTOSELL_MAX_ATTEMPTS:
            self._log(f"Auto-sell: giving up on {task.symbol} after {n} attempts "
                      f"({why}). Sell it by hand from the Exits tab — retrying "
                      f"is only re-triggering the broker login.", "warn")
            self._push_notification(
                f"Auto-sell gave up on {task.symbol} — {why}", "warning")
            return                              # stays claimed: stop the loop

        self._autosell_sold.discard(key)
        self._save_autosell_state()
        self._log(f"Auto-sell: {task.symbol} put back — {why} "
                  f"(attempt {n} of {AUTOSELL_MAX_ATTEMPTS})", "meta")

    def _autosell_fire(self, resolved) -> None:
        """Place the resolved sell — the one step a human would have clicked."""
        task = resolved.task

        # Something else started while we were reading holdings. _exit_fire
        # would refuse, and the play was claimed before the read — so without
        # this it is marked sold and never sold.
        if getattr(self, "_trade_in_flight", False):
            self._autosell_retry(task, "another trade started mid-read")
            self._autosell_queue.insert(0, task)
            self.after(5000, self._autosell_pump)
            return

        if not resolved.ok:
            why = []
            if resolved.missing:
                why.append(f"no position at {', '.join(resolved.missing)}")
            if resolved.errors:
                why.append(f"couldn't read {', '.join(resolved.errors)}")
            # A broker we could not READ is unknown, not empty — a dead session
            # or a timeout says nothing about whether the shares are there, so
            # hand it back and let the next pull look again. An empty position
            # is a real answer (already sold by hand) and stays claimed.
            if resolved.errors:
                self._autosell_retry(task, f"couldn't read {', '.join(resolved.errors)}")
            self._log(f"Auto-sell: {task.symbol} — nothing to sell "
                      f"({'; '.join(why) or 'no balances found'})", "warn")
            self._push_notification(f"Auto-sell skipped {task.symbol}: "
                                    f"{'; '.join(why) or 'nothing to sell'}", "warning")
            self.after(1000, self._autosell_pump)
            return

        dry = bool(self._autosell_dry_run.get())
        self._push_notification(
            f"Auto-selling {task.symbol} — {resolved.describe()}"
            + (" [DRY RUN]" if dry else ""),
            "info" if dry else "success")
        try:
            self._exit_fire(resolved, dry_run=dry)
        except Exception as exc:                # noqa: BLE001
            # The order may or may not have gone out, so this does NOT unclaim
            # the play: a retry that re-sells something already filled is the
            # one outcome worse than stopping. It is loud instead, and the
            # queue carries on to the next name.
            self._log(f"Auto-sell: {task.symbol} order failed — {exc}", "error")
            self._push_notification(
                f"{task.symbol} may not have sold — check the broker", "error")
        # The next play waits for this batch; _autosell_pump re-arms itself
        # while a trade is in flight rather than racing it.
        self.after(5000, self._autosell_pump)

    # ---- TRACK polling -----------------------------------------------------

    def _feed_pull_worker(self) -> None:
        """Refresh BUYS and EXITS from the cloud feed. Runs on the hourly tick.

        Both streams, because a customer's day is not bounded by a restart. The
        pick list used to be fetched exactly once, 300ms after launch, and never
        again — so a terminal left open (which is the normal way to run it, and
        what mirror trading requires) showed yesterday's plays all day and only
        told the truth if you happened to press Reload. An alert published at
        10am is worth nothing to someone who sees it tomorrow.

        Sell alerts used to arrive only through the Discord SELL channel, which
        meant a customer without a token saw an empty card forever. Cloud rows
        are MERGED into whatever is already on disk rather than replacing it, so
        an install that once read Discord keeps its history.
        """
        if not CLOUD_AVAILABLE:
            return
        try:
            client = cloud_sync.CloudSync()
        except Exception:
            self.after(0, lambda: self._feed_result(False))
            return                      # offline; keep what we have

        # Each stream in its own try: a server hiccup on one must not cost the
        # other. Buys are the half a customer acts on, so they may not ride on
        # whether the exits call happened to succeed.
        ok = False
        try:
            picks = _fetch_quick_picks()
            # NOT simply True. _cloud_picks() swallows a refusal and hands back
            # the cache, so a copy with no board password took this path with
            # picks=[] and no exception — and the screen then told the customer
            # "nothing is live today, last checked 14:02", which is a confident
            # lie. We were never allowed to look. Treat that as a failed pull so
            # the empty state can ask for the password instead.
            ok = _PICKS_AUTH_ERROR is None
            # Render even when empty: that is exactly when the message matters,
            # and _load_picks() already refuses to let an empty feed erase a
            # populated cache, so this cannot blank anyone's plays.
            self.after(0, lambda p=picks: self._render_quick_picks(p))
        except Exception:
            pass

        try:
            incoming = client.fetch_sells()
            ok = ok or _PICKS_AUTH_ERROR is None
        except Exception:
            incoming = None
        if incoming:
            merged = _merge_sells(_load_sells(), incoming)
            _save_sells(merged)
            self.after(0, self._render_sell_alerts)

        self.after(0, lambda good=ok: self._feed_result(good))

    def _feed_result(self, ok: bool) -> None:
        """Record the outcome of a feed pull and retry soon if it failed.

        The regular tick is hourly, which is right for a healthy feed and far
        too slow for a broken one: a thirty-second outage would otherwise cost
        a customer a full hour of plays. Back off on repeated failures so a
        server that is genuinely down isn't hammered, and cap it below the
        hourly tick so the normal schedule always takes over again.
        """
        if ok:
            self._feed_last_ok = datetime.now()
            self._feed_fail_streak = 0
            self._notified_no_plays_key = False
            self._update_feed_status()
            return

        # A missing password is not an outage and retrying cannot cure it. Say
        # so once, from wherever the user happens to be standing — the empty
        # state on the picks screen only helps if they are looking at it.
        if _PICKS_AUTH_ERROR and not getattr(self, "_notified_no_plays_key", False):
            self._notified_no_plays_key = True
            self._push_notification(
                "No plays password on this copy, so the feed is empty. Set "
                "RSAMAXXED_PLAYS_KEY in .env to the password you were given, "
                "then restart.", "warning")

        self._feed_fail_streak = getattr(self, "_feed_fail_streak", 0) + 1
        self._update_feed_status()
        if self._feed_retry_id is not None:
            try:
                self.after_cancel(self._feed_retry_id)
            except Exception:
                pass
            self._feed_retry_id = None
        delay = min(300_000 * self._feed_fail_streak, 1_800_000)   # 5,10,15 … 30 min
        self._feed_retry_id = self.after(
            delay, lambda: self._run_in_thread(self._feed_pull_worker))

    def _update_feed_status(self) -> None:
        """Say when the plays last arrived, so stale never looks like current.

        Silence used to be indistinguishable from success — an unreachable feed
        left yesterday's picks on screen with nothing to suggest they were old,
        which is the worst possible failure for a product whose entire job is
        being current.
        """
        lbl = getattr(self, "_feed_status_lbl", None)
        if lbl is None:
            return
        last = getattr(self, "_feed_last_ok", None)
        streak = getattr(self, "_feed_fail_streak", 0)
        if last is None:
            lbl.configure(text="FEED  ·  connecting…", fg=TEXT_MUTED)
            return
        mins = int((datetime.now() - last).total_seconds() // 60)
        stale = streak > 0 or mins > 150        # >2 missed hourly ticks
        when = "just now" if mins < 2 else f"{mins}m ago" if mins < 120 else f"{mins // 60}h ago"
        lbl.configure(
            text=f"FEED  ·  {'not updating — ' if stale else ''}{when}",
            fg=YELLOW if stale else TEXT_MUTED)

    def _track_loop(self) -> None:
        """Hourly TRACK poll, on its own timer.

        Deliberately NOT tied to the Discord auto-import toggle. That switch
        controls whether we import picks — writing to the watchlist and the
        mirror queue. Reading the board is a different thing: someone who
        enters picks by hand still holds positions, and still needs to be told
        the moment one of them becomes sellable. Gating this behind that toggle
        left the Exits page permanently empty for them.

        Splits resolve through the trading day, so this is hourly rather than
        daily; one request an hour keeps the account footprint negligible.
        """
        if self._track_available():
            self._track_pull_now()
        # Exits ride the same tick: one hourly refresh of everything the feed
        # supplies, so no page depends on the user having Discord configured.
        self._run_in_thread(self._feed_pull_worker)
        self._track_loop_id = self.after(3600000, self._track_loop)

    def _publish_lifecycle_worker(self, rows) -> None:
        """Publish the TRACK board. Operator-only; silent no-op everywhere else.

        Lifecycle rows are a STATUS, not an event — ingest updates them in place
        on source_id — so re-sending an unchanged board costs one request and
        changes nothing. That is what makes it safe to run on every hourly poll
        rather than trying to detect when it's worth doing.
        """
        try:
            client = cloud_sync.CloudSync()
            if not client.can_publish_feed:
                return
            sent = client.publish_feed({"lifecycle": [r.to_json() for r in rows]})
        except Exception:
            return
        n = (sent or {}).get("lifecycle", 0)
        if n:
            self.after(0, lambda: self._log(
                f"TRACK: published {n} board change(s) to the feed", "ok"))

    def _track_available(self) -> bool:
        """Either source will do: the cloud feed, or a TRACK channel.

        No account check — the board is served to anyone, so the only way to
        have no source at all is having no network and no Discord channel.
        """
        return bool(CLOUD_AVAILABLE or self._track_channel())

    def _track_pull_now(self) -> None:
        if self._track_busy:
            return
        if not self._track_available():
            self._push_notification(
                "Can't read the round-up board — install the requirements "
                "(py -3.13 -m pip install -r requirements.txt), or set "
                "DISCORD_LIFECYCLE_CHANNEL to read it from Discord directly.",
                "warning")
            return
        self._track_busy = True
        self._run_in_thread(self._track_pull_worker)

    def _track_pull_worker(self) -> None:
        """One board pull, off the UI thread.

        Cloud first, Discord second — the cloud works for every subscriber and
        Discord only for whoever holds a token with access to the channel. On a
        customer's install there is no token at all, and that is the normal
        case, not the fallback.

        TRACK is a single message edited in place, so either source is re-read
        and diffed rather than polled for new messages; there never are any.
        """
        rows, changes, err = [], [], ""
        try:
            rows, changes, err = lifecycle.pull(
                self._track_channel(), _env("DISCORD_TOKEN"))
        except Exception as exc:
            err = str(exc)[:160]
        self.after(0, lambda: self._track_apply(rows, changes, err))

    def _track_apply(self, rows, changes, err: str) -> None:
        self._track_busy = False
        self._track_error = err
        if err:
            self._log(f"TRACK: {err}", "warn")
            self._render_exits()
            return

        self._track_rows = list(rows)
        self._track_pulled_at = datetime.now().strftime("%H:%M")

        # Operator machines push the board they just read back out, so every
        # other install gets it. Without this the lifecycle table only ever
        # filled when someone remembered to run publish_feed.py by hand, and a
        # customer's Exits page stayed empty no matter how correct their app
        # was. No-op on a normal install: publishing needs the feed key.
        if rows and CLOUD_AVAILABLE:
            self._run_in_thread(self._publish_lifecycle_worker, list(rows))

        # Only announce a play that crossed INTO a sellable state. A seeded
        # first pull and rows that were already sellable stay quiet, or the very
        # first launch would fire ~70 toasts and teach you to ignore them.
        newly = [c for c in changes if c.became_sellable]
        for c in newly[:6]:
            kind = "success" if c.new_status == "rounded_up" else "info"
            self._push_notification(f"{c.describe()} — ready to sell", kind)
        if len(newly) > 6:
            self._push_notification(
                f"+{len(newly) - 6} more plays became sellable", "info")
        if changes:
            self._log(f"TRACK: {len(changes)} row(s) changed, "
                      f"{len(newly)} newly sellable")

        # After the notifications, so the log reads in the order things happened
        # and a sell is never announced before the board that caused it.
        try:
            self._autosell_consider(changes)
        except Exception as exc:
            # Auto-sell must never take the TRACK pull down with it: the board
            # refreshing is worth more than the convenience on top of it.
            self._log(f"Auto-sell: skipped this pull — {exc}", "warn")

        # A fresh board is new data by definition, so drop the cached
        # fingerprint before rendering. _render_exits updates the summary.
        self._invalidate_page("exits")
        self._render_exits()

    def _update_exits_summary(self, tasks=None) -> None:
        if not hasattr(self, "_exits_summary"):
            return
        if tasks is None:
            tasks = lifecycle.sell_worklist(self._track_rows)
        frac = sum(1 for t in tasks if t.is_fractional)
        self._exits_summary.configure(
            text=f"{len(self._track_rows)} plays tracked   ·   "
                 f"{frac} fractional   ·   {len(tasks) - frac} round-up/cancelled")
        self._exits_stamp.configure(
            text=f"updated {self._track_pulled_at}" if self._track_pulled_at else "")

    # ---- Accounts ---------------------------------------------------------

    def _build_accounts(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["accounts"] = frame

        # scrollable container (mousewheel only)
        canvas = tk.Canvas(frame, bg=BG_PRIMARY, bd=0, highlightthickness=0)
        scroll_frame = tk.Frame(canvas, bg=BG_PRIMARY)

        scroll_frame.bind("<Configure>",
                          lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas_window = canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfigure(canvas_window, width=e.width))
        canvas.pack(fill="both", expand=True)

        def _acct_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _acct_enter(e):
            canvas.bind_all("<MouseWheel>", _acct_mousewheel)

        def _acct_leave(e):
            canvas.unbind_all("<MouseWheel>")

        frame.bind("<Enter>", _acct_enter)
        frame.bind("<Leave>", _acct_leave)

        # Account linking sits ABOVE the brokers, on this page, because this is
        # where every doc sends people and where anyone looks for "connect my
        # account" — it used to live on Automation, so a new user followed the
        # README to Brokers, found nothing, and concluded the plays were broken.
        # It is first because it is the one step without which nothing arrives.
        self._build_cloud_card(scroll_frame)

        self._account_widgets: Dict[str, Dict[str, Any]] = {}

        for broker in sorted(BROKER_MODULES.keys()):
            card_rf = RoundedFrame(scroll_frame, bg_color=BG_CARD,
                                   border_color=BORDER, radius=RAD_MD)
            card_rf.pack(fill="x", pady=(0, 10), padx=(0, 4))
            card = card_rf.inner

            # header row
            header = tk.Frame(card, bg=BG_CARD)
            header.pack(fill="x", padx=16, pady=(14, 8))

            dot = StatusDot(header, color=TEXT_MUTED, size=8)
            dot.pack(side="left", padx=(0, 10))

            tk.Label(header, text=broker.capitalize(), bg=BG_CARD, fg=TEXT_PRIMARY,
                     font=(FONT_FAMILY, 11, "bold")).pack(side="left")

            boot_btn = PillButton(header, text="Bootstrap",
                                  command=lambda b=broker: self._bootstrap_broker(b),
                                  width=100, height=30, font_size=9)
            boot_btn.pack(side="right", padx=(8, 0))

            status_lbl = tk.Label(header, text="", bg=BG_CARD, fg=TEXT_MUTED,
                                  font=(FONT_FAMILY, 9))
            status_lbl.pack(side="right", padx=(8, 0))

            has_creds = _broker_has_creds(broker)
            if has_creds:
                dot.set_color(GREEN)
                status_lbl.configure(text="credentials set", fg=GREEN)

            # separator
            tk.Frame(card, bg=BORDER, height=1).pack(fill="x", padx=16)

            # credential fields
            fields_frame = tk.Frame(card, bg=BG_CARD)
            fields_frame.pack(fill="x", padx=16, pady=(10, 14))

            entries: Dict[str, ttk.Entry] = {}
            for i, key in enumerate(BROKER_ENV_KEYS.get(broker, [])):
                tk.Label(fields_frame, text=key, bg=BG_CARD, fg=TEXT_SECONDARY,
                         font=(FONT_MONO, 8)).grid(row=i, column=0, sticky="w", pady=3)
                is_secret = any(s in key.lower() for s in ("password", "secret", "token"))
                entry = ttk.Entry(fields_frame, width=32,
                                  show="\u2022" if is_secret else "",
                                  font=(FONT_MONO, 10))
                entry.insert(0, _env(key))
                entry.grid(row=i, column=1, sticky="w", padx=(12, 0), pady=3)
                entries[key] = entry

            save_frame = tk.Frame(fields_frame, bg=BG_CARD)
            save_frame.grid(row=len(entries), column=1, sticky="w", padx=(12, 0), pady=(8, 0))
            PillButton(save_frame, text="Save", bg_color=BG_CARD_ALT, hover_color=ACCENT,
                       command=lambda b=broker: self._save_account_creds(b),
                       width=80, height=28, font_size=9).pack(side="left")

            self._account_widgets[broker] = {
                "dot": dot, "status": status_lbl, "entries": entries,
            }

    def _save_account_creds(self, broker: str) -> None:
        widgets = self._account_widgets[broker]
        updates = {}
        for key, entry in widgets["entries"].items():
            updates[key] = entry.get().strip()
        _save_env_file(updates)
        has = any(v for v in updates.values())
        widgets["dot"].set_color(GREEN if has else TEXT_MUTED)
        widgets["status"].configure(text="saved", fg=GREEN)
        self._log(f"Accounts: saved credentials for {broker}")
        if broker in self._broker_status_labels:
            self._broker_status_labels[broker]["dot"].set_color(GREEN if has else TEXT_MUTED)
            self._broker_status_labels[broker]["status"].configure(
                text="credentials set" if has else "not configured",
                fg=GREEN if has else TEXT_MUTED)

    def _bootstrap_all(self) -> None:
        """Bootstrap all brokers that have credentials configured."""
        self._log("Accounts: bootstrapping all configured brokers...")
        for broker in sorted(BROKER_MODULES):
            if _broker_has_creds(broker):
                self._bootstrap_broker(broker)

    def _bootstrap_broker(self, broker: str) -> None:
        self._log(f"Accounts: bootstrapping {broker}...")
        widgets = self._account_widgets[broker]
        widgets["status"].configure(text="bootstrapping...", fg=YELLOW)
        self._run_in_thread(self._bootstrap_worker, broker)

    def _bootstrap_worker(self, broker: str) -> None:
        widgets = self._account_widgets[broker]
        try:
            # Per-broker Chrome slot: different brokers bootstrap concurrently;
            # only two ops on the SAME broker serialize (shared profile).
            slot = _browser_slot(broker)
            held_slot = None
            if slot is not None:
                self.after(0, lambda busy=slot.locked(): widgets["status"].configure(
                    text="waiting for browser..." if busy else "bootstrapping...", fg=YELLOW))
                if not slot.acquire(timeout=_BROWSER_LOCK_TIMEOUT):
                    raise RuntimeError(_BROWSER_BUSY_MSG)
                held_slot = slot
                self.after(0, lambda: widgets["status"].configure(text="bootstrapping...", fg=YELLOW))
            try:
                load_dotenv(ENV_FILE, override=True)
                mod = _load_broker(broker)
                # Robinhood's login can stall on a device approval waiting on the
                # user's phone. Nothing on screen said so, and the poll has no
                # timeout, so it read as a hang.
                _approval = self._arm_device_approval_alert(mod)
                try:
                    output: BrokerOutput = mod.bootstrap()
                finally:
                    self._disarm_device_approval_alert(_approval)
            finally:
                if held_slot is not None:
                    try:
                        held_slot.release()
                    except RuntimeError:
                        pass
            log_event(broker=broker, action="bootstrap", output=output)

            def update() -> None:
                if output.state == "success":
                    widgets["dot"].set_color(GREEN)
                    widgets["status"].configure(text="connected", fg=GREEN)
                    # Count sub-accounts: use len(accounts), but also check
                    # account messages for embedded counts (e.g. "Login ok (3 accounts)")
                    n_accounts = len(output.accounts)
                    for acct in output.accounts:
                        m = re.search(r'\((\d+)\s*account', acct.message or "")
                        if m:
                            n_accounts = max(n_accounts, int(m.group(1)))
                    if broker in self._broker_status_labels:
                        self._broker_status_labels[broker]["dot"].set_color(GREEN)
                        self._broker_status_labels[broker]["status"].configure(
                            text=f"{n_accounts} account(s)", fg=GREEN)
                    if broker == "public":
                        self._apply_public_status(output)
                    # Update total accounts card (replace, not add)
                    self._update_total_accounts(broker, n_accounts)
                    self._push_notification(
                        f"{broker.capitalize()} connected — {n_accounts} account(s)",
                        "success")
                else:
                    widgets["dot"].set_color(RED)
                    widgets["status"].configure(text=output.message or "failed", fg=RED)
                    if broker in self._broker_status_labels:
                        self._broker_status_labels[broker]["dot"].set_color(RED)
                        self._broker_status_labels[broker]["status"].configure(
                            text="failed", fg=RED)
                    if broker == "public":
                        self._apply_public_status(output)
                    self._push_notification(
                        f"{broker.capitalize()} bootstrap failed", "error")
                self._log(f"Accounts: {broker} bootstrap -> {output.state}")

            self.after(0, update)
        except Exception as e:
            self.after(0, lambda: widgets["status"].configure(text=str(e)[:40], fg=RED))
            self.after(0, lambda err=e: self._log(f"Accounts: {broker} error - {err}"))

    # ---- Logs -------------------------------------------------------------

    def _build_logs(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["logs"] = frame

        # ---- Live operation strip (pulsing; hidden when idle) -------------
        self._live_card = RoundedFrame(frame, bg_color=BG_HERO,
                                       border_color=ACCENT_DIM, radius=14)
        lc = self._live_card.inner
        live_top = tk.Frame(lc, bg=BG_HERO)
        live_top.pack(fill="x", padx=18, pady=(15, 2))
        self._live_dot = StatusDot(live_top, color=ACCENT, size=12)
        self._live_dot.pack(side="left", padx=(0, 11))
        self._live_title = tk.Label(live_top, text="Working…", bg=BG_HERO,
                                    fg=TEXT_PRIMARY, font=(FONT_FAMILY, 15, "bold"))
        self._live_title.pack(side="left")
        self._live_elapsed = tk.Label(live_top, text="0:00", bg=BG_HERO,
                                      fg=ACCENT, font=(FONT_MONO, 14, "bold"))
        self._live_elapsed.pack(side="right")
        tk.Label(live_top, text="● LIVE", bg=BG_HERO, fg=ACCENT,
                 font=(FONT_FAMILY, 8, "bold")).pack(side="right", padx=(0, 12))
        self._live_sub = tk.Label(lc, text="", bg=BG_HERO, fg=TEXT_SECONDARY,
                                  font=(FONT_FAMILY, 10), anchor="w", justify="left")
        self._live_sub.pack(fill="x", padx=18, pady=(1, 9))
        self._live_bar = tk.Canvas(lc, bg=BG_HERO, height=6, bd=0,
                                   highlightthickness=0)
        self._live_bar.pack(fill="x", padx=18, pady=(0, 15))
        self._live_bar.bind("<Configure>", lambda e: self._draw_live_bar())
        self._live_progress = 0.0
        self._live_card.pack(fill="x", pady=(0, 12))
        self._live_card.pack_forget()

        # ---- Completion receipt card (the "ending screen") ---------------
        self._done_card = RoundedFrame(frame, bg_color=BG_CARD,
                                       border_color=BORDER_LIGHT, radius=14)
        dc = self._done_card.inner
        done_row = tk.Frame(dc, bg=BG_CARD)
        done_row.pack(fill="x", padx=22, pady=(18, 4))
        self._done_icon = tk.Label(done_row, text=icon("check"), bg=BG_CARD,
                                   fg=GREEN, font=(ICON_FONT, 32))
        self._done_icon.pack(side="left", padx=(0, 18))
        done_text = tk.Frame(done_row, bg=BG_CARD)
        done_text.pack(side="left", fill="x", expand=True)
        self._done_headline = tk.Label(done_text, text="", bg=BG_CARD,
                                       fg=TEXT_PRIMARY,
                                       font=(FONT_FAMILY, 19, "bold"), anchor="w")
        self._done_headline.pack(anchor="w")
        self._done_sub = tk.Label(done_text, text="", bg=BG_CARD,
                                  fg=TEXT_SECONDARY, font=(FONT_FAMILY, 10),
                                  anchor="w")
        self._done_sub.pack(anchor="w", pady=(3, 0))
        self._done_dismiss = tk.Label(done_row, text=icon("close"), bg=BG_CARD,
                                      fg=TEXT_MUTED, font=(ICON_FONT, 11),
                                      cursor="hand2")
        self._done_dismiss.pack(side="right")
        self._done_dismiss.bind("<Button-1>", lambda e: self._done_hide())
        self._done_chips = tk.Frame(dc, bg=BG_CARD)
        self._done_chips.pack(fill="x", padx=22, pady=(10, 4))
        # Retry row: only packed when a run left accounts unfilled.
        self._done_retry_row = tk.Frame(dc, bg=BG_CARD)
        self._done_retry_lbl = tk.Label(self._done_retry_row, text="", bg=BG_CARD,
                                        fg=TEXT_SECONDARY, font=(FONT_FAMILY, 9),
                                        anchor="w", justify="left")
        self._done_retry_lbl.pack(side="left", padx=(0, 12))
        self._done_retry_btn = PillButton(
            self._done_retry_row, text="Retry failed accounts",
            bg_color=BG_CARD_ALT, hover_color=ACCENT,
            command=self._retry_failed_accounts, width=170, height=30,
            font_size=9)
        self._done_retry_btn.pack(side="right")
        self._done_card.pack(fill="x", pady=(0, 12))
        self._done_card.pack_forget()

        # ---- Event feed ---------------------------------------------------
        log_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        log_card.pack(fill="both", expand=True)
        self._log_feed_card = log_card

        log_head = tk.Frame(log_card.inner, bg=BG_CARD)
        log_head.pack(fill="x", padx=16, pady=(14, 6), side="top")
        tk.Label(log_head, text=icon("activity"), bg=BG_CARD, fg=ACCENT,
                 font=(ICON_FONT, 12)).pack(side="left", padx=(0, 8))
        tk.Label(log_head, text="Session Activity", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 13, "bold")).pack(side="left")
        tk.Label(log_head, text="EVERY BROKER OP · TRADE · ALERT", bg=BG_CARD,
                 fg=TEXT_MUTED, font=(FONT_FAMILY, 7, "bold")).pack(side="right")
        tk.Frame(log_card.inner, bg=BORDER, height=1).pack(fill="x", padx=16,
                                                           side="top")

        self._log_text = tk.Text(log_card.inner, bg=BG_CARD, fg=TEXT_PRIMARY,
                                 font=(FONT_MONO, 10), bd=0, wrap="word",
                                 state="disabled", insertbackground=TEXT_PRIMARY,
                                 highlightthickness=0, padx=16, pady=12,
                                 spacing1=1, spacing3=2)
        scrollbar = ttk.Scrollbar(log_card.inner, orient="vertical",
                                  command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=scrollbar.set)
        self._log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y", pady=4)

        # color tags for status lines + completion summary
        self._log_text.tag_configure("ts", foreground=TEXT_MUTED)
        self._log_text.tag_configure("meta", foreground=TEXT_MUTED)
        self._log_text.tag_configure("success", foreground=GREEN)
        self._log_text.tag_configure("ok", foreground=GREEN)
        self._log_text.tag_configure("error", foreground=RED)
        self._log_text.tag_configure("fail", foreground=RED)
        self._log_text.tag_configure("warn", foreground=YELLOW)
        self._log_text.tag_configure(
            "banner_ok", foreground=GREEN, font=(FONT_MONO, 13, "bold"))
        self._log_text.tag_configure(
            "banner_err", foreground=RED, font=(FONT_MONO, 13, "bold"))
        self._log_text.tag_configure(
            "done_ok", foreground=GREEN, font=(FONT_FAMILY, 12, "bold"),
            spacing1=8, spacing3=6)
        self._log_text.tag_configure(
            "done_warn", foreground=YELLOW, font=(FONT_FAMILY, 12, "bold"),
            spacing1=8, spacing3=6)
        self._log_text.tag_configure(
            "done_err", foreground=RED, font=(FONT_FAMILY, 12, "bold"),
            spacing1=8, spacing3=6)

        # Category badges — a small colored pill at the head of each feed line.
        _badge_cols = {
            "trade": ACCENT, "mirror": ACCENT, "radar": YELLOW, "alert": YELLOW,
            "pick": GREEN, "watch": TEXT_SECONDARY, "dash": TEXT_SECONDARY,
            "stats": TEXT_SECONDARY, "boot": TEXT_SECONDARY, "cmd": TEXT_SECONDARY,
            "export": TEXT_SECONDARY, "sys": TEXT_MUTED,
        }
        for _key, _col in _badge_cols.items():
            self._log_text.tag_configure(
                f"badge_{_key}", foreground=_col,
                background=_blend(_col, BG_CARD, 0.78),
                font=(FONT_FAMILY, 8, "bold"))

        if self._log_lines:
            self._log_text.configure(state="normal")
            for entry in self._log_lines:
                line, tag = entry if isinstance(entry, tuple) else (entry, None)
                start = self._log_text.index("end-1c")
                self._log_text.insert("end", line + "\n")
                if tag:
                    self._log_text.tag_add(tag, start, f"{start} lineend")
            self._log_text.see("end")
            self._log_text.configure(state="disabled")

    # ---- Live activity strip + completion receipt -------------------------

    def _live_show(self) -> None:
        if hasattr(self, "_live_card") and not self._live_card.winfo_ismapped():
            self._live_card.pack(fill="x", pady=(0, 12), before=self._log_feed_card)

    def _live_hide(self) -> None:
        # NB: do NOT null _live_anim_id here — the tick loop self-terminates
        # when _live_batches is empty; nulling here could spawn a 2nd loop.
        if hasattr(self, "_live_card"):
            self._live_card.pack_forget()

    def _done_show(self) -> None:
        if hasattr(self, "_done_card") and not self._done_card.winfo_ismapped():
            self._done_card.pack(fill="x", pady=(0, 12), before=self._log_feed_card)

    def _done_hide(self) -> None:
        if hasattr(self, "_done_card"):
            self._done_card.pack_forget()

    def _live_start(self, batch: dict) -> None:
        """Show the live strip for a batch and (re)start the pulse loop."""
        if not hasattr(self, "_live_card"):
            return
        self._live_batches.append(batch)
        self._done_hide()          # a new op supersedes the last receipt
        self._live_show()
        if self._live_anim_id is None:
            self._live_frame = 0
            self._live_tick()

    def _live_tick(self) -> None:
        if not getattr(self, "_live_batches", None):
            self._live_anim_id = None
            return
        self._live_frame += 1
        pulse = [ACCENT, ACCENT_HOVER, "#b9b6ff", ACCENT_HOVER]
        try:
            self._live_dot.set_color(pulse[self._live_frame % len(pulse)])
        except Exception:
            pass
        dots = "." * (1 + (self._live_frame % 3))
        batch = self._live_batches[-1]
        started = min((b.get("started") for b in self._live_batches
                       if b.get("started")), default=datetime.now())
        secs = int((datetime.now() - started).total_seconds())
        self._live_elapsed.configure(text=f"{secs // 60}:{secs % 60:02d}")
        verb = "Purchasing" if batch.get("side") == "buy" else "Selling"
        n_ops = len(self._live_batches)
        if n_ops > 1:
            self._live_title.configure(text=f"Executing {n_ops} operations{dots}")
        else:
            self._live_title.configure(text=f"{verb} {batch.get('symbol', '')}{dots}")
        allb = batch.get("all_brokers") or []
        pend = sorted(batch.get("pending") or [])
        done = len(allb) - len(pend)
        if pend:
            waiting = ", ".join(b.capitalize() for b in pend)
            self._live_sub.configure(
                text=f"{done}/{len(allb)} brokers done · still working: {waiting}")
        else:
            self._live_sub.configure(
                text=f"{done}/{len(allb)} brokers done · finalizing…")
        self._live_progress = (done / len(allb)) if allb else 0.0
        self._draw_live_bar()
        self._live_anim_id = self.after(500, self._live_tick)

    def _draw_live_bar(self) -> None:
        if not hasattr(self, "_live_bar"):
            return
        c = self._live_bar
        c.delete("all")
        w = c.winfo_width() or 1
        h = int(c.cget("height"))
        c.create_rectangle(0, 0, w, h, fill=BG_INPUT, outline="")
        fillw = max(0.0, min(1.0, getattr(self, "_live_progress", 0.0))) * w
        if fillw > 0:
            c.create_rectangle(0, 0, fillw, h, fill=ACCENT, outline="")

    def _receipt_chip(self, parent, text: str, color: str) -> None:
        chip = tk.Frame(parent, bg=BG_INPUT, highlightthickness=1,
                        highlightbackground=color)
        StatusDot(chip, color=color, size=7).pack(side="left", padx=(9, 5), pady=4)
        tk.Label(chip, text=text, bg=BG_INPUT, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(side="left", padx=(0, 11), pady=4)
        chip.pack(side="left", padx=(0, 8), pady=3)

    def _render_done_receipt(self, *, kind, verb, shares, symbol, total_ok,
                             total_fail, ok_brokers, results, dry, elapsed,
                             batch=None) -> None:
        if not hasattr(self, "_done_card"):
            return
        color = {"ok": GREEN, "warn": YELLOW, "fail": RED}[kind]
        glyph = {"ok": icon("check"), "warn": icon("warning"),
                 "fail": icon("error")}[kind]
        self._done_icon.configure(text=glyph, fg=color)
        if kind == "fail":
            self._done_headline.configure(text=f"Nothing {verb.lower()}", fg=color)
        else:
            self._done_headline.configure(text=f"{verb} {shares} {symbol}",
                                          fg=TEXT_PRIMARY)
        dry_tag = " · DRY RUN" if dry else ""
        n_br = len(ok_brokers)
        if kind == "ok":
            sub = (f"{total_ok} account{'s' if total_ok != 1 else ''} across "
                   f"{n_br} broker{'s' if n_br != 1 else ''} · "
                   f"{elapsed:.1f}s{dry_tag}")
        else:
            sub = (f"{total_ok} filled · {total_fail} failed · "
                   f"{elapsed:.1f}s{dry_tag}")
        self._done_sub.configure(text=sub)
        for w in self._done_chips.winfo_children():
            w.destroy()
        for r in sorted(results, key=lambda x: x["broker"]):
            name = r["broker"].capitalize()
            if r["ok_accounts"] > 0 and not r["fail_accounts"]:
                self._receipt_chip(self._done_chips, f"{name}  {r['ok_accounts']}", GREEN)
            elif r["ok_accounts"] > 0:
                tot = r["ok_accounts"] + r["fail_accounts"]
                self._receipt_chip(self._done_chips, f"{name}  {r['ok_accounts']}/{tot}", YELLOW)
            else:
                self._receipt_chip(self._done_chips, f"{name}  failed", RED)
        self._render_retry_row(results=results, dry=dry, batch=batch)
        self._done_show()

    def _render_retry_row(self, *, results, dry, batch) -> None:
        """Offer a re-run of exactly the accounts that came back unfilled.

        A broker that fills 5 of 10 leaves the other 5 invisible the moment the
        receipt is dismissed, and re-running the whole broker would double-buy
        the 5 that worked. The failed account ids are already in the result, so
        the retry can name them.
        """
        if not hasattr(self, "_done_retry_row"):
            return
        self._retry_plan = {} if (dry or not batch) else self._failed_account_plan(results)
        if not self._retry_plan:
            self._retry_order = None
            self._done_retry_row.pack_forget()
            return
        n = sum(len(v) for v in self._retry_plan.values())
        where = ", ".join(f"{b.capitalize()} ({len(v)})"
                          for b, v in sorted(self._retry_plan.items()))
        # Quantity comes off the batch, never off the receipt: `shares` is the
        # total filled across every account, so retrying with it would send
        # "buy 5" to each account that was owed one share.
        self._retry_order = {"side": batch.get("side", "buy"),
                             "symbol": batch.get("symbol", ""),
                             "qty": str(batch.get("qty", "1"))}
        self._done_retry_lbl.configure(
            text=f"{n} account{'s' if n != 1 else ''} still unfilled — {where}")
        self._done_retry_row.pack(fill="x", padx=22, pady=(4, 16))

    @staticmethod
    def _failed_account_plan(results: List[dict]) -> Dict[str, List[str]]:
        """broker -> the account ids that failed, for brokers that can retarget.

        Brokers whose module can't narrow to a subset of accounts are left out:
        offering a retry that silently re-runs all of them is worse than not
        offering one.
        """
        plan: Dict[str, List[str]] = {}
        for r in results or []:
            broker = r.get("broker") or ""
            if broker not in RETRYABLE_ACCOUNT_BROKERS:
                continue
            failed = [a.get("account_id") for a in (r.get("accounts") or [])
                      if not a.get("ok") and a.get("account_id")]
            if failed:
                plan[broker] = failed
        return plan

    def _retry_failed_accounts(self) -> None:
        plan = getattr(self, "_retry_plan", None)
        order = getattr(self, "_retry_order", None)
        if not plan or not order:
            return
        if getattr(self, "_trade_in_flight", False):
            self._push_notification("A trade is already running — wait for it "
                                    "to finish", "warning")
            return
        n = sum(len(v) for v in plan.values())
        if not messagebox.askyesno(
            "Retry failed accounts",
            f"Retry {order['side'].upper()} {order['qty']} {order['symbol']} on "
            f"the {n} account(s) that did not fill?\n\n"
            + "\n".join(f"  {b}: {', '.join(v)}" for b, v in sorted(plan.items())),
                parent=self):
            return
        brokers = sorted(plan)
        batch = {
            "pending": set(brokers),
            "all_brokers": brokers,
            "results": [],
            "side": order["side"],
            "symbol": order["symbol"],
            "qty": order["qty"],
            "dry_run": False,
            "origin": "retry",
            "finished": False,
            "started": datetime.now(),
        }
        self._done_hide()
        self._live_start(batch)
        for broker in brokers:
            accts = plan[broker]
            self._log(f"  {broker}: retrying {len(accts)} failed account(s)...")
            self._run_in_thread(self._trade_worker, broker, order["side"],
                                order["symbol"], order["qty"], False, batch,
                                accts)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = App()
    app.mainloop()

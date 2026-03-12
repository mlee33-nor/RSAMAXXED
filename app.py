#!/usr/bin/env python3
"""Desktop GUI for broker automation — gotEV.

Manages all 10 brokers: credentials, bootstrap, holdings, trades, P/L.
Uses only tkinter (ships with Python) — no extra dependencies.

EXE packaging:
    pip install pyinstaller && pyinstaller --onefile --windowed app.py
"""
from __future__ import annotations

import builtins
import importlib
import os
import re
import threading
import tkinter as tk
import winsound
from datetime import datetime, timezone
from pathlib import Path
from tkinter import ttk, messagebox, simpledialog
from typing import Any, Dict, List, Optional

import urllib.request

from dotenv import load_dotenv

from modules.outputs import BrokerOutput, log_event
import trade_journal

# Quick Picks — remote stock list hosted on a public GitHub Gist.
# Update the gist JSON to push new picks to all copies of the app.
QUICK_PICKS_URL = "https://jsonblob.com/api/jsonBlob/019ce035-23d0-7f14-bcec-0c54bc1a540b"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent
ENV_FILE = ROOT_DIR / ".env"
CUSTOM_ACCOUNTS_FILE = ROOT_DIR / "custom_accounts.json"
MIRROR_STATE_FILE = ROOT_DIR / "mirror_state.json"

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
_browser_lock = threading.Lock()

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
    "public":     ["PUBLIC_SECRET_TOKEN_1"],
    "robinhood":  ["ROBINHOOD_USERNAME", "ROBINHOOD_PASSWORD"],
    "schwab":     ["SCHWAB_USERNAME", "SCHWAB_PASSWORD", "SCHWAB_TOTP_SECRET"],
    "sofi":       ["SOFI_USERNAME", "SOFI_PASSWORD", "SOFI_TOTP_SECRET"],
    "wellsfargo": ["WELLSFARGO_USERNAME", "WELLSFARGO_PASSWORD"],
}

# ---------------------------------------------------------------------------
# Modern SaaS Color Palette
# ---------------------------------------------------------------------------

BG_PRIMARY   = "#0a0a0f"   # near-black background
BG_SECONDARY = "#111118"   # slightly lighter panels
BG_CARD      = "#16161f"   # card surfaces
BG_CARD_ALT  = "#1c1c28"   # card hover / alternate
BG_INPUT     = "#1e1e2a"   # input fields
BORDER       = "#2a2a3a"   # subtle borders
BORDER_LIGHT = "#3a3a4f"   # hover borders

TEXT_PRIMARY   = "#f0f0f5"  # main text
TEXT_SECONDARY = "#8888a0"  # muted labels
TEXT_MUTED     = "#55556a"  # disabled / placeholder

ACCENT         = "#6c5ce7"  # purple accent (primary actions)
ACCENT_HOVER   = "#7f70f0"  # lighter purple hover
ACCENT_GLOW    = "#6c5ce720" # subtle glow

GREEN          = "#00d68f"  # success / profit
GREEN_DIM      = "#00d68f30"
RED            = "#ff6b6b"  # error / loss
RED_DIM        = "#ff6b6b30"
YELLOW         = "#ffd93d"  # warning
BLUE           = "#4dabf7"  # info

SIDEBAR_BG     = "#0d0d14"  # sidebar background
SIDEBAR_HOVER  = "#1a1a28"  # sidebar item hover
SIDEBAR_ACTIVE = "#6c5ce715" # active sidebar item bg

# Fonts
FONT_FAMILY = "Segoe UI"
FONT_MONO   = "Cascadia Code"  # fallback to Consolas

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

class RoundedFrame(tk.Canvas):
    """A canvas that draws a rounded rectangle background to simulate cards."""

    def __init__(self, parent, bg_color=BG_CARD, border_color=BORDER,
                 radius=12, border_width=1, **kw):
        super().__init__(parent, highlightthickness=0, bg=BG_PRIMARY, **kw)
        self._bg_color = bg_color
        self._border_color = border_color
        self._radius = radius
        self._border_width = border_width
        self._inner = tk.Frame(self, bg=bg_color)
        self.bind("<Configure>", self._redraw)
        self._inner.bind("<Configure>", self._resize_to_inner)
        self._window = self.create_window(0, 0, window=self._inner, anchor="nw")

    @property
    def inner(self) -> tk.Frame:
        return self._inner

    def _resize_to_inner(self, event=None) -> None:
        """Auto-size canvas height to fit inner content."""
        self._inner.update_idletasks()
        pad = self._border_width + 2
        needed_h = self._inner.winfo_reqheight() + pad * 2
        cur_h = self.winfo_height()
        if needed_h != cur_h:
            self.configure(height=needed_h)

    def _redraw(self, event=None) -> None:
        w = self.winfo_width()
        h = self.winfo_height()
        self.delete("bg")
        r = self._radius
        # rounded rect
        self.create_polygon(
            r, 0, w - r, 0, w, 0, w, r, w, h - r, w, h, w - r, h,
            r, h, 0, h, 0, h - r, 0, r, 0, 0,
            smooth=True, fill=self._bg_color, outline=self._border_color,
            width=self._border_width, tags="bg",
        )
        self.tag_lower("bg")
        pad = self._border_width + 2
        self.itemconfigure(self._window, width=w - pad * 2)
        self.coords(self._window, pad, pad)


class PillButton(tk.Canvas):
    """Modern pill-shaped button with hover effects."""

    def __init__(self, parent, text="", command=None, bg_color=ACCENT,
                 hover_color=ACCENT_HOVER, fg_color=TEXT_PRIMARY,
                 width=120, height=36, font_size=10):
        try:
            parent_bg = parent.cget("bg")
        except Exception:
            parent_bg = BG_PRIMARY
        super().__init__(parent, width=width, height=height,
                         highlightthickness=0, bg=parent_bg)
        self._bg = bg_color
        self._hover = hover_color
        self._fg = fg_color
        self._command = command
        self._text = text
        self._btn_w = width
        self._btn_h = height
        self._font_size = font_size
        self._draw(bg_color)
        self.bind("<Enter>", lambda e: self._draw(self._hover))
        self.bind("<Leave>", lambda e: self._draw(self._bg))
        self.bind("<ButtonRelease-1>", self._on_click)

    def _draw(self, fill: str) -> None:
        self.delete("all")
        w, h, r = self._btn_w, self._btn_h, self._btn_h // 2
        self.create_polygon(
            r, 0, w - r, 0, w, 0, w, r, w, h - r, w, h, w - r, h,
            r, h, 0, h, 0, h - r, 0, r, 0, 0,
            smooth=True, fill=fill, outline="",
        )
        self.create_text(w // 2, h // 2, text=self._text,
                         fill=self._fg, font=(FONT_FAMILY, self._font_size, "bold"))

    def _on_click(self, event=None) -> None:
        if self._command:
            self._command()

    def configure_text(self, text: str) -> None:
        self._text = text
        self._draw(self._bg)


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


PICKS_FILE = ROOT_DIR / "picks.json"


def _fetch_quick_picks() -> List[Dict[str, str]]:
    """Fetch quick picks from remote first (so all users stay in sync), fall back to local cache.

    Expected JSON format: [{"symbol": "AAPL"}, {"symbol": "ZNB", "note": "EV play"}, ...]
    """
    import json
    # Remote is authoritative — always try it first
    try:
        req = urllib.request.Request(QUICK_PICKS_URL, headers={"User-Agent": "gotEV/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if isinstance(data, list):
                # Cache locally for offline use
                try:
                    PICKS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
                except Exception:
                    pass
                return data
    except Exception:
        pass
    # Offline fallback — use local cache
    if PICKS_FILE.exists():
        try:
            data = json.loads(PICKS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("gotEV")
        self.geometry("1050x700")
        self.configure(bg=BG_PRIMARY)
        self.minsize(900, 600)

        self._log_lines: List[str] = []
        self._active_nav: Optional[tk.Frame] = None

        self._configure_styles()
        self._build_sidebar()
        self._build_content_area()
        self._build_notification_bar()
        self._build_frames()
        self._install_input_hook()
        self._show_frame("dashboard")
        # Auto-refresh non-browser brokers on startup (browser brokers need manual bootstrap)
        self.after(500, self._startup_refresh)

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
                answer = simpledialog.askstring(
                    "Broker Input Required",
                    prompt.strip(),
                    parent=app,
                )
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

        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=TEXT_PRIMARY,
                        insertcolor=TEXT_PRIMARY, padding=8)
        style.map("TEntry", fieldbackground=[("focus", BG_CARD_ALT)])

        style.configure("TCombobox", fieldbackground=BG_INPUT, foreground=TEXT_PRIMARY,
                        padding=8, arrowcolor=TEXT_SECONDARY)
        style.map("TCombobox", fieldbackground=[("readonly", BG_INPUT)])

        style.configure("Treeview", background=BG_CARD, foreground=TEXT_PRIMARY,
                        fieldbackground=BG_CARD, rowheight=34,
                        font=(FONT_MONO, 10), borderwidth=0)
        style.configure("Treeview.Heading", background=BG_CARD_ALT,
                        foreground=TEXT_SECONDARY,
                        font=(FONT_FAMILY, 9, "bold"), borderwidth=0,
                        relief="flat")
        style.map("Treeview",
                  background=[("selected", ACCENT + "30")],
                  foreground=[("selected", TEXT_PRIMARY)])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

        style.configure("Vertical.TScrollbar", background=BG_CARD,
                        troughcolor=BG_SECONDARY, arrowcolor=TEXT_MUTED,
                        borderwidth=0)

    # ---- Sidebar ----------------------------------------------------------

    def _build_sidebar(self) -> None:
        self._sidebar = tk.Frame(self, bg=SIDEBAR_BG, width=200)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)

        # logo area
        logo_frame = tk.Frame(self._sidebar, bg=SIDEBAR_BG)
        logo_frame.pack(fill="x", pady=(20, 30), padx=20)

        tk.Label(logo_frame, text="gEV", bg=ACCENT, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold"), padx=4, pady=2).pack(side="left")
        tk.Label(logo_frame, text="  gotEV", bg=SIDEBAR_BG, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 13, "bold")).pack(side="left")

        # nav items
        nav_items = [
            ("dashboard", "Dashboard", "\u25a3"),
            ("holdings", "Holdings", "\u25b6"),
            ("trade",    "Trade",     "\u21c4"),
            ("stats",    "Stats",     "\u2591"),
            ("settings", "Settings",  "\u2696"),
            ("accounts", "Accounts",  "\u2699"),
            ("logs",     "Logs",      "\u2630"),
        ]

        self._nav_items: Dict[str, tk.Frame] = {}
        for name, label, icon in nav_items:
            item = tk.Frame(self._sidebar, bg=SIDEBAR_BG, cursor="hand2")
            item.pack(fill="x", padx=10, pady=1)

            inner = tk.Frame(item, bg=SIDEBAR_BG, padx=14, pady=10)
            inner.pack(fill="x")

            icon_lbl = tk.Label(inner, text=icon, bg=SIDEBAR_BG, fg=TEXT_SECONDARY,
                                font=(FONT_FAMILY, 11))
            icon_lbl.pack(side="left")
            text_lbl = tk.Label(inner, text=f"  {label}", bg=SIDEBAR_BG, fg=TEXT_SECONDARY,
                                font=(FONT_FAMILY, 10))
            text_lbl.pack(side="left")

            self._nav_items[name] = item

            for widget in (item, inner, icon_lbl, text_lbl):
                widget.bind("<Enter>", lambda e, n=name: self._nav_hover(n, True))
                widget.bind("<Leave>", lambda e, n=name: self._nav_hover(n, False))
                widget.bind("<Button-1>", lambda e, n=name: self._show_frame(n))

        # spacer
        tk.Frame(self._sidebar, bg=SIDEBAR_BG).pack(fill="both", expand=True)

        # version label at bottom
        tk.Label(self._sidebar, text="v1.0.0", bg=SIDEBAR_BG, fg=TEXT_MUTED,
                 font=(FONT_FAMILY, 8)).pack(pady=(0, 16))

    def _nav_hover(self, name: str, entering: bool) -> None:
        item = self._nav_items[name]
        if self._active_nav and self._active_nav == name:
            return
        bg = SIDEBAR_HOVER if entering else SIDEBAR_BG
        fg = TEXT_PRIMARY if entering else TEXT_SECONDARY
        for widget in item.winfo_children():
            widget.configure(bg=bg)
            for child in widget.winfo_children():
                child.configure(bg=bg, fg=fg)
        item.configure(bg=bg)

    def _set_active_nav(self, name: str) -> None:
        # reset all
        for n, item in self._nav_items.items():
            bg = SIDEBAR_BG
            fg = TEXT_SECONDARY
            for widget in item.winfo_children():
                widget.configure(bg=bg)
                for child in widget.winfo_children():
                    child.configure(bg=bg, fg=fg)
            item.configure(bg=bg)
        # set active
        item = self._nav_items[name]
        bg = SIDEBAR_HOVER
        fg = TEXT_PRIMARY
        for widget in item.winfo_children():
            widget.configure(bg=bg)
            for child in widget.winfo_children():
                child.configure(bg=bg, fg=fg)
        item.configure(bg=bg)
        self._active_nav = name

    # ---- Content Area -----------------------------------------------------

    def _build_content_area(self) -> None:
        wrapper = tk.Frame(self, bg=BG_PRIMARY)
        wrapper.pack(side="left", fill="both", expand=True)

        # top bar with page title
        self._topbar = tk.Frame(wrapper, bg=BG_PRIMARY, height=56)
        self._topbar.pack(fill="x", padx=28, pady=(20, 0))
        self._topbar.pack_propagate(False)

        self._page_title = tk.Label(self._topbar, text="Dashboard", bg=BG_PRIMARY,
                                    fg=TEXT_PRIMARY, font=(FONT_FAMILY, 18, "bold"))
        self._page_title.pack(side="left", anchor="w")

        self._page_subtitle = tk.Label(self._topbar, text="Overview of all brokers",
                                       bg=BG_PRIMARY, fg=TEXT_SECONDARY,
                                       font=(FONT_FAMILY, 10))
        self._page_subtitle.pack(side="left", padx=(12, 0), anchor="w", pady=(4, 0))

        # separator
        tk.Frame(wrapper, bg=BORDER, height=1).pack(fill="x", padx=28, pady=(8, 0))

        # main content
        self._content = tk.Frame(wrapper, bg=BG_PRIMARY)
        self._content.pack(fill="both", expand=True, padx=28, pady=16)

    def _build_frames(self) -> None:
        self._frames: Dict[str, tk.Frame] = {}
        self._build_dashboard()
        self._build_holdings()
        self._build_trade()
        self._build_stats()
        self._build_settings()
        self._build_accounts()
        self._build_logs()

    _PAGE_META = {
        "dashboard": ("Dashboard", "Overview of all brokers"),
        "holdings":  ("Holdings", "Tool-bought positions with live P/L"),
        "trade":     ("Trade", "Execute orders across brokers"),
        "stats":     ("Stats", "Trading performance and analytics"),
        "settings":  ("Settings", "Mirror trading and preferences"),
        "accounts":  ("Accounts", "Manage credentials and connections"),
        "logs":      ("Logs", "Activity log for this session"),
    }

    def _show_frame(self, name: str) -> None:
        for f in self._frames.values():
            f.pack_forget()
        self._frames[name].pack(in_=self._content, fill="both", expand=True)
        title, subtitle = self._PAGE_META.get(name, (name.title(), ""))
        self._page_title.configure(text=title)
        self._page_subtitle.configure(text=subtitle)
        self._set_active_nav(name)
        if name == "stats":
            self.after(100, self._refresh_stats)

    # ---- Logging ----------------------------------------------------------

    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}]  {msg}"
        self._log_lines.append(line)
        if hasattr(self, "_log_text"):
            self._log_text.configure(state="normal")
            self._log_text.insert("end", line + "\n")
            self._log_text.see("end")
            self._log_text.configure(state="disabled")

    def _run_in_thread(self, target, *args) -> None:
        threading.Thread(target=target, args=args, daemon=True).start()

    # ---- Dashboard --------------------------------------------------------

    def _update_total_accounts(self, broker: str = None, count: int = None) -> None:
        """Update a broker's account count and refresh the total accounts card."""
        if broker and count is not None:
            self._broker_account_counts[broker] = count
        total = sum(self._broker_account_counts.values())
        self._dash_accounts.configure(text=str(total))

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

        # metric cards row
        cards_row = tk.Frame(frame, bg=BG_PRIMARY)
        cards_row.pack(fill="x", pady=(0, 20))
        cards_row.columnconfigure(0, weight=1)
        cards_row.columnconfigure(1, weight=1)
        cards_row.columnconfigure(2, weight=1)
        cards_row.columnconfigure(3, weight=1)

        self._dash_invested = self._make_metric_card(cards_row, "TOTAL INVESTED", "$0.00", 0)
        self._dash_value = self._make_metric_card(cards_row, "CURRENT VALUE", "$0.00", 1)
        self._dash_pl = self._make_metric_card(cards_row, "UNREALIZED P/L", "$0.00", 2)
        # Pre-calculate total from known counts for brokers with credentials
        startup_total = sum(
            _KNOWN_ACCOUNT_COUNTS.get(b, 1) if _broker_has_creds(b) else 0
            for b in BROKER_MODULES
        )
        self._dash_accounts = self._make_metric_card(cards_row, "TOTAL ACCOUNTS", str(startup_total), 3)
        # Track per-broker account counts so bootstrap/refresh can replace (not add)
        self._broker_account_counts: Dict[str, int] = {
            b: _KNOWN_ACCOUNT_COUNTS.get(b, 1) if _broker_has_creds(b) else 0
            for b in BROKER_MODULES
        }

        # broker status card
        status_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        status_card.pack(fill="x", pady=(0, 12))

        header = tk.Frame(status_card.inner, bg=BG_CARD)
        header.pack(fill="x", padx=20, pady=(16, 12))
        tk.Label(header, text="Broker Status", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(side="left")
        PillButton(header, text="Refresh All", command=self._dashboard_refresh,
                   width=110, height=28).pack(side="right")

        self._broker_status_labels: Dict[str, Dict[str, Any]] = {}

        list_frame = tk.Frame(status_card.inner, bg=BG_CARD)
        list_frame.pack(fill="x", padx=20, pady=(0, 16))

        for i, broker in enumerate(sorted(BROKER_MODULES)):
            if not _broker_has_creds(broker):
                continue
            row = tk.Frame(list_frame, bg=BG_CARD)
            row.pack(fill="x", pady=2)

            dot = StatusDot(row, color=GREEN, size=8)
            dot.pack(side="left", padx=(0, 10))

            name_lbl = tk.Label(row, text=broker.capitalize(), bg=BG_CARD, fg=TEXT_PRIMARY,
                                font=(FONT_FAMILY, 10), width=12, anchor="w")
            name_lbl.pack(side="left")

            n = _KNOWN_ACCOUNT_COUNTS.get(broker)
            status_text = f"{n} account(s)" if n else "credentials set"
            status_lbl = tk.Label(row, text=status_text, bg=BG_CARD, fg=GREEN,
                                  font=(FONT_FAMILY, 9))
            status_lbl.pack(side="left", padx=(8, 0))

            self._broker_status_labels[broker] = {"dot": dot, "status": status_lbl}

        # ---- Custom Accounts card ----
        custom_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        custom_card.pack(fill="x", pady=(0, 12))

        custom_header = tk.Frame(custom_card.inner, bg=BG_CARD)
        custom_header.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(custom_header, text="Custom Accounts", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(side="left")
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
        tk.Label(picks_header, text="Quick Picks", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(side="left")
        PillButton(picks_header, text="Reload", command=self._reload_quick_picks,
                   width=80, height=28).pack(side="right", padx=(4, 0))
        if os.environ.get("GOTEV_ADMIN") == "1":
            PillButton(picks_header, text="Manage Picks", command=self._manage_picks,
                       width=110, height=28).pack(side="right")

        picks_container = tk.Frame(picks_card.inner, bg=BG_CARD, height=400)
        picks_container.pack(fill="x", padx=20, pady=(0, 16))
        picks_container.pack_propagate(False)

        picks_canvas = tk.Canvas(picks_container, bg=BG_CARD, bd=0, highlightthickness=0)
        picks_canvas.pack(fill="both", expand=True)

        self._picks_grid = tk.Frame(picks_canvas, bg=BG_CARD)
        picks_cw = picks_canvas.create_window((0, 0), window=self._picks_grid, anchor="nw")
        self._picks_grid.bind("<Configure>",
            lambda e: picks_canvas.configure(scrollregion=picks_canvas.bbox("all")))
        picks_canvas.bind("<Configure>",
            lambda e: picks_canvas.itemconfigure(picks_cw, width=e.width))

        def _picks_mousewheel(e):
            picks_canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

        picks_container.bind("<Enter>",
            lambda e: picks_canvas.bind_all("<MouseWheel>", _picks_mousewheel))
        picks_container.bind("<Leave>",
            lambda e: picks_canvas.unbind_all("<MouseWheel>"))

        self._quick_picks: List[Dict[str, str]] = []
        # Fetch picks in background on startup
        self.after(300, self._reload_quick_picks)

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

    def _render_quick_picks(self, picks: List[Dict[str, str]]) -> None:
        """Render picks as a vertical scrollable list grouped by date."""
        for w in self._picks_grid.winfo_children():
            w.destroy()
        self._quick_picks = picks

        if not picks:
            tk.Label(self._picks_grid, text="No picks available (check gist URL)",
                     bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 9)).pack(anchor="w")
            return

        # Group by date, most recent first
        from collections import OrderedDict
        grouped: OrderedDict = OrderedDict()
        for pick in picks:
            date = pick.get("date", "Unknown")
            grouped.setdefault(date, []).append(pick)
        # Sort dates descending (most recent first)
        sorted_dates = sorted(grouped.keys(), reverse=True)

        for date_str in sorted_dates:
            # Date header
            try:
                from datetime import datetime as _dt
                dt = _dt.strptime(date_str, "%Y-%m-%d")
                display_date = dt.strftime("%B %d, %Y")
            except (ValueError, TypeError):
                display_date = date_str

            date_lbl = tk.Label(self._picks_grid, text=display_date, bg=BG_CARD,
                                fg=TEXT_SECONDARY, font=(FONT_FAMILY, 10, "bold"))
            date_lbl.pack(anchor="w", pady=(10, 4))

            tk.Frame(self._picks_grid, bg=BORDER, height=1).pack(fill="x", pady=(0, 6))

            for pick in grouped[date_str]:
                sym = pick.get("symbol", "???").upper()
                note = pick.get("note", "")

                row = tk.Frame(self._picks_grid, bg=BG_INPUT, cursor="hand2")
                row.pack(fill="x", pady=(0, 4))

                inner = tk.Frame(row, bg=BG_INPUT, padx=14, pady=8)
                inner.pack(fill="x")

                sym_lbl = tk.Label(inner, text=sym, bg=BG_INPUT, fg=ACCENT,
                                   font=(FONT_FAMILY, 11, "bold"), cursor="hand2")
                sym_lbl.pack(side="left")

                if note:
                    display_text = self._NOTE_DISPLAY.get(note.lower(), note)
                    note_lbl = tk.Label(inner, text=f"  {display_text}", bg=BG_INPUT,
                                        fg="#FFFFFF", font=(FONT_FAMILY, 8), cursor="hand2")
                    note_lbl.pack(side="left")
                    note_lbl.bind("<Button-1>", lambda e, s=sym: self._quick_pick_buy(s))

                buy_lbl = tk.Label(inner, text="Buy \u2192", bg=BG_INPUT, fg=GREEN,
                                   font=(FONT_FAMILY, 9, "bold"), cursor="hand2")
                buy_lbl.pack(side="right")

                for widget in (row, inner, sym_lbl, buy_lbl):
                    widget.bind("<Button-1>", lambda e, s=sym: self._quick_pick_buy(s))

    def _quick_pick_buy(self, symbol: str) -> None:
        """Jump to Trade tab with symbol and qty pre-filled."""
        self._show_frame("trade")
        # Set side to BUY (visual + variable)
        self._set_trade_side("buy")
        # Clear and set symbol
        self._trade_symbol.delete(0, "end")
        self._trade_symbol.insert(0, symbol)
        # Set qty to 1
        self._trade_qty.delete(0, "end")
        self._trade_qty.insert(0, "1")
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

                # Remote sync is best-effort
                try:
                    data = _json.dumps(all_picks).encode("utf-8")
                    req = urllib.request.Request(
                        QUICK_PICKS_URL, data=data, method="PUT",
                        headers={"Content-Type": "application/json",
                                 "User-Agent": "gotEV/1.0"})
                    with urllib.request.urlopen(req, timeout=10):
                        pass
                except Exception:
                    pass  # remote sync failed — local file is authoritative

                self.after(0, lambda: self._render_quick_picks(all_picks))
                self.after(0, lambda: status_lbl.configure(
                    text=f"Added {len(parsed)} pick(s) for {date_str}!", fg=GREEN))
                self.after(0, lambda: self._log(
                    f"Quick Picks: added {len(parsed)} tickers for {date_str}"))

            threading.Thread(target=_push, daemon=True).start()

        def _clear_all():
            if messagebox.askyesno("Clear All Picks",
                                   "Remove ALL picks for everyone?", parent=dlg):
                def _push_empty():
                    import json as _json
                    try:
                        PICKS_FILE.write_text("[]", encoding="utf-8")
                    except Exception as ex:
                        self.after(0, lambda: status_lbl.configure(
                            text=f"Failed: {ex}", fg=RED))
                        return
                    # Remote sync best-effort
                    try:
                        data = b"[]"
                        req = urllib.request.Request(
                            QUICK_PICKS_URL, data=data, method="PUT",
                            headers={"Content-Type": "application/json",
                                     "User-Agent": "gotEV/1.0"})
                        with urllib.request.urlopen(req, timeout=10):
                            pass
                    except Exception:
                        pass
                    self.after(0, lambda: self._render_quick_picks([]))
                    self.after(0, lambda: status_lbl.configure(
                        text="All picks cleared.", fg=TEXT_MUTED))
                threading.Thread(target=_push_empty, daemon=True).start()

        btn_row = tk.Frame(dlg, bg=BG_CARD)
        btn_row.pack(fill="x", padx=16, pady=(8, 16))
        PillButton(btn_row, text="Add Picks", command=_save,
                   width=120, height=36).pack(side="left", padx=(0, 8))
        PillButton(btn_row, text="Clear All", command=_clear_all,
                   width=100, height=36).pack(side="left")
        PillButton(btn_row, text="Cancel", command=dlg.destroy,
                   width=80, height=36).pack(side="right")

    def _make_metric_card(self, parent, title: str, value: str, col: int) -> tk.Label:
        card = RoundedFrame(parent, bg_color=BG_CARD, border_color=BORDER, radius=14,
                            height=100)
        card.grid(row=0, column=col, sticky="nsew", padx=(0, 12) if col < 2 else (0, 0))

        tk.Label(card.inner, text=title, bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(anchor="w", padx=20, pady=(16, 4))

        val_lbl = tk.Label(card.inner, text=value, bg=BG_CARD, fg=TEXT_PRIMARY,
                           font=(FONT_FAMILY, 22, "bold"))
        val_lbl.pack(anchor="w", padx=20, pady=(0, 16))
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

    def _update_custom_totals(self) -> None:
        """Re-calculate dashboard totals including custom accounts."""
        accounts = _load_custom_accounts()
        custom_invested = sum(a.get("invested", 0.0) for a in accounts)
        custom_value = sum(a.get("value", 0.0) for a in accounts)

        # Read current tracked totals from the labels and add custom
        try:
            cur_invested = float(self._dash_invested.cget("text").replace("$", "").replace(",", "").replace("+", ""))
        except (ValueError, AttributeError):
            cur_invested = 0.0
        try:
            cur_value = float(self._dash_value.cget("text").replace("$", "").replace(",", "").replace("+", ""))
        except (ValueError, AttributeError):
            cur_value = 0.0

        # Store the base (non-custom) amounts if not already stored
        if not hasattr(self, "_base_invested"):
            self._base_invested = cur_invested
            self._base_value = cur_value
        total_inv = self._base_invested + custom_invested
        total_val = self._base_value + custom_value
        pl = total_val - total_inv

        self._dash_invested.configure(text=f"${total_inv:,.2f}")
        self._dash_value.configure(text=f"${total_val:,.2f}")
        self._dash_pl.configure(text=f"${pl:+,.2f}", fg=GREEN if pl >= 0 else RED)

    def _startup_refresh(self) -> None:
        """Auto-refresh all brokers on startup, reusing saved sessions."""
        self._log("Dashboard: restoring broker sessions...")
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
                n = len(out.accounts)
                labels = self._broker_status_labels.get(broker)
                if labels and out.state == "success":
                    labels["dot"].set_color(GREEN)
                    labels["status"].configure(text=f"{n} account(s) connected", fg=GREEN)
            self._log("Dashboard: API brokers restored")
        self.after(0, update_api)

        # Browser brokers skip auto-refresh (require manual bootstrap/Refresh All)
        self.after(0, lambda: self._log("Dashboard: browser brokers skipped (use Bootstrap or Refresh All)"))

        # Final totals update
        portfolio = trade_journal.get_portfolio()
        total_invested = 0.0
        total_value = 0.0
        seen_keys: set = set()
        for broker, output in results.items():
            for acct in output.accounts:
                for h in acct.holdings:
                    key = (broker, h.symbol)
                    if key in portfolio and key not in seen_keys:
                        seen_keys.add(key)
                        pos = portfolio[key]
                        total_invested += pos["total_cost"]
                        if h.price is not None:
                            total_value += h.price * pos["qty"]
        custom_accounts = _load_custom_accounts()
        custom_invested = sum(a.get("invested", 0.0) for a in custom_accounts)
        custom_value = sum(a.get("value", 0.0) for a in custom_accounts)
        total_invested += custom_invested
        total_value += custom_value
        pl = total_value - total_invested

        def update_final() -> None:
            self._base_invested = total_invested - custom_invested
            self._base_value = total_value - custom_value
            self._dash_invested.configure(text=f"${total_invested:,.2f}")
            self._dash_value.configure(text=f"${total_value:,.2f}")
            self._dash_pl.configure(text=f"${pl:+,.2f}", fg=GREEN if pl >= 0 else RED)
            for broker, out in results.items():
                if out.state == "success":
                    self._update_total_accounts(broker, len(out.accounts))
            self._log("Dashboard: startup refresh complete")

        self.after(0, update_final)

    def _dashboard_refresh(self) -> None:
        self._log("Dashboard: refreshing all brokers...")
        self._run_in_thread(self._dashboard_refresh_worker)

    def _dashboard_refresh_worker(self) -> None:
        load_dotenv(ENV_FILE, override=True)
        portfolio = trade_journal.get_portfolio()
        total_invested = 0.0
        total_value = 0.0

        threads: List[threading.Thread] = []
        results: Dict[str, BrokerOutput] = {}
        lock = threading.Lock()

        def fetch(broker: str) -> None:
            use_block = broker in _BROWSER_BROKERS
            try:
                if use_block:
                    _browser_lock.acquire()
                mod = _load_broker(broker)
                out = mod.get_holdings()
                with lock:
                    results[broker] = out
            except Exception as e:
                self.after(0, lambda b=broker, err=e: self._log(f"  {b}: error - {err}"))
            finally:
                if use_block:
                    try:
                        _browser_lock.release()
                    except RuntimeError:
                        pass

        for broker in BROKER_MODULES:
            if _broker_has_creds(broker):
                t = threading.Thread(target=fetch, args=(broker,), daemon=True)
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        seen_keys: set = set()
        for broker, output in results.items():
            for acct in output.accounts:
                for h in acct.holdings:
                    key = (broker, h.symbol)
                    if key in portfolio and key not in seen_keys:
                        seen_keys.add(key)
                        pos = portfolio[key]
                        total_invested += pos["total_cost"]
                        if h.price is not None:
                            total_value += h.price * pos["qty"]

        # Include custom accounts in totals
        custom_accounts = _load_custom_accounts()
        custom_invested = sum(a.get("invested", 0.0) for a in custom_accounts)
        custom_value = sum(a.get("value", 0.0) for a in custom_accounts)
        total_invested += custom_invested
        total_value += custom_value
        pl = total_value - total_invested

        def update_ui() -> None:
            # Store base amounts so custom account edits can recalculate
            self._base_invested = total_invested - custom_invested
            self._base_value = total_value - custom_value
            self._dash_invested.configure(text=f"${total_invested:,.2f}")
            self._dash_value.configure(text=f"${total_value:,.2f}")
            self._dash_pl.configure(text=f"${pl:+,.2f}", fg=GREEN if pl >= 0 else RED)

            for broker in sorted(BROKER_MODULES):
                labels = self._broker_status_labels[broker]
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

        # refresh button top-right
        top = tk.Frame(frame, bg=BG_PRIMARY)
        top.pack(fill="x", pady=(0, 12))
        PillButton(top, text="Refresh", command=self._holdings_refresh,
                   width=100, height=32, font_size=9).pack(side="right")

        # table card
        table_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        table_card.pack(fill="both", expand=True)

        cols = ("broker", "symbol", "shares", "avg_cost", "price", "value", "pl", "pl_pct")
        self._holdings_tree = ttk.Treeview(table_card.inner, columns=cols,
                                           show="headings", height=18)
        for col, heading, w in [
            ("broker", "Broker", 100), ("symbol", "Symbol", 90),
            ("shares", "Shares", 80), ("avg_cost", "Avg Cost", 90),
            ("price", "Price", 90), ("value", "Value", 100),
            ("pl", "P/L", 100), ("pl_pct", "P/L %", 80),
        ]:
            self._holdings_tree.heading(col, text=heading)
            anchor = "w" if col in ("broker", "symbol") else "e"
            self._holdings_tree.column(col, width=w, anchor=anchor, minwidth=60)

        scrollbar = ttk.Scrollbar(table_card.inner, orient="vertical",
                                  command=self._holdings_tree.yview)
        self._holdings_tree.configure(yscrollcommand=scrollbar.set)
        self._holdings_tree.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        scrollbar.pack(side="right", fill="y", pady=4)

    def _holdings_refresh(self) -> None:
        self._log("Holdings: refreshing...")
        self._run_in_thread(self._holdings_refresh_worker)

    def _holdings_refresh_worker(self) -> None:
        portfolio = trade_journal.get_portfolio()
        if not portfolio:
            self.after(0, lambda: self._log("Holdings: no trades recorded yet"))
            return

        brokers_needed = {k[0] for k in portfolio}
        live_prices: Dict[tuple, Optional[float]] = {}
        threads: List[threading.Thread] = []
        lock = threading.Lock()

        def fetch(broker: str) -> None:
            try:
                mod = _load_broker(broker)
                out = mod.get_holdings()
                with lock:
                    for acct in out.accounts:
                        for h in acct.holdings:
                            live_prices[(broker, h.symbol)] = h.price
            except Exception as e:
                self.after(0, lambda b=broker, err=e: self._log(f"  Holdings {b}: {err}"))

        for broker in brokers_needed:
            if _broker_has_creds(broker):
                t = threading.Thread(target=fetch, args=(broker,), daemon=True)
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        rows = []
        for (broker, symbol), pos in sorted(portfolio.items()):
            price = live_prices.get((broker, symbol))
            qty = pos["qty"]
            avg = pos["avg_cost"]
            val = price * qty if price is not None else None
            pl = (price - avg) * qty if price is not None else None
            pl_pct = ((price - avg) / avg * 100) if (price is not None and avg > 0) else None
            rows.append((broker, symbol, qty, avg, price, val, pl, pl_pct))

        def update_ui() -> None:
            for item in self._holdings_tree.get_children():
                self._holdings_tree.delete(item)
            for broker, symbol, qty, avg, price, val, pl, pl_pct in rows:
                values = (
                    broker.capitalize(), symbol, f"{qty:.4f}",
                    f"${avg:.2f}" if avg else "\u2014",
                    f"${price:.2f}" if price is not None else "\u2014",
                    f"${val:.2f}" if val is not None else "\u2014",
                    f"${pl:+,.2f}" if pl is not None else "\u2014",
                    f"{pl_pct:+.1f}%" if pl_pct is not None else "\u2014",
                )
                tag = ""
                if pl is not None:
                    tag = "profit" if pl >= 0 else "loss"
                self._holdings_tree.insert("", "end", values=values, tags=(tag,))
            self._holdings_tree.tag_configure("profit", foreground=GREEN)
            self._holdings_tree.tag_configure("loss", foreground=RED)
            self._log("Holdings: refresh complete")

        self.after(0, update_ui)

    # ---- Trade ------------------------------------------------------------

    def _build_trade(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["trade"] = frame

        # form card
        form_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14,
                                 height=320)
        form_card.pack(fill="x", pady=(0, 16))

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
        select_all_chip = tk.Label(broker_frame, text="Select All", bg=BG_INPUT,
                                   fg=TEXT_SECONDARY, font=(FONT_FAMILY, 8, "bold"),
                                   cursor="hand2", padx=10, pady=4)
        select_all_chip.pack(side="left", padx=(0, 8), pady=2)

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
                chip_row_frame.pack(anchor="w", pady=(2, 0))

            chip = tk.Label(chip_row_frame, text=broker.capitalize(), bg=BG_INPUT,
                            fg=TEXT_SECONDARY, font=(FONT_FAMILY, 8, "bold"),
                            cursor="hand2", padx=10, pady=4)
            chip.pack(side="left", padx=(0, 4), pady=2)
            self._trade_broker_chips[broker] = {"label": chip, "selected": False}
            chip.bind("<Button-1>", lambda e, b=broker: self._toggle_broker_chip(b))

        def toggle_all(event=None):
            all_selected = len(self._trade_selected_brokers) == len(linked_brokers)
            for b in linked_brokers:
                if all_selected:
                    self._trade_selected_brokers.discard(b)
                    self._trade_broker_chips[b]["selected"] = False
                    self._trade_broker_chips[b]["label"].configure(bg=BG_INPUT, fg=TEXT_SECONDARY)
                else:
                    self._trade_selected_brokers.add(b)
                    self._trade_broker_chips[b]["selected"] = True
                    self._trade_broker_chips[b]["label"].configure(bg=ACCENT, fg=TEXT_PRIMARY)
            if all_selected:
                select_all_chip.configure(bg=BG_INPUT, fg=TEXT_SECONDARY)
            else:
                select_all_chip.configure(bg=ACCENT, fg=TEXT_PRIMARY)

        select_all_chip.bind("<Button-1>", toggle_all)
        self._select_all_chip = select_all_chip
        self._linked_brokers = linked_brokers

        # side
        row += 1
        add_label("SIDE", row)
        side_frame = tk.Frame(form, bg=BG_CARD)
        side_frame.grid(row=row, column=1, sticky="w", pady=(0, 12))
        self._trade_side = tk.StringVar(value="buy")

        buy_btn = tk.Label(side_frame, text="  BUY  ", bg=GREEN, fg=BG_PRIMARY,
                           font=(FONT_FAMILY, 9, "bold"), cursor="hand2", padx=12, pady=4)
        buy_btn.pack(side="left", padx=(0, 6))
        sell_btn = tk.Label(side_frame, text="  SELL  ", bg=BG_INPUT, fg=RED,
                            font=(FONT_FAMILY, 9, "bold"), cursor="hand2", padx=12, pady=4)
        sell_btn.pack(side="left")

        self._buy_btn = buy_btn
        self._sell_btn = sell_btn

        def set_side(s):
            self._trade_side.set(s)
            if s == "buy":
                self._buy_btn.configure(bg=GREEN, fg=BG_PRIMARY)
                self._sell_btn.configure(bg=BG_INPUT, fg=RED)
            else:
                self._buy_btn.configure(bg=BG_INPUT, fg=GREEN)
                self._sell_btn.configure(bg=RED, fg=BG_PRIMARY)

        self._set_trade_side = set_side
        buy_btn.bind("<Button-1>", lambda e: set_side("buy"))
        sell_btn.bind("<Button-1>", lambda e: set_side("sell"))

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

        PillButton(action_frame, text="Execute Trade", command=self._trade_execute,
                   width=140, height=36, font_size=10).pack(side="left")

        # result area
        result_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        result_card.pack(fill="both", expand=True)

        tk.Label(result_card.inner, text="OUTPUT", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(anchor="w", padx=16, pady=(12, 4))

        self._trade_result = tk.Text(result_card.inner, bg=BG_CARD, fg=TEXT_PRIMARY,
                                     font=(FONT_MONO, 10), bd=0, wrap="word",
                                     state="disabled", insertbackground=TEXT_PRIMARY,
                                     highlightthickness=0)
        self._trade_result.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def _toggle_broker_chip(self, broker: str) -> None:
        chip = self._trade_broker_chips[broker]
        if chip["selected"]:
            chip["selected"] = False
            chip["label"].configure(bg=BG_INPUT, fg=TEXT_SECONDARY)
            self._trade_selected_brokers.discard(broker)
        else:
            chip["selected"] = True
            chip["label"].configure(bg=ACCENT, fg=TEXT_PRIMARY)
            self._trade_selected_brokers.add(broker)
        # update select all chip
        if len(self._trade_selected_brokers) == len(self._linked_brokers):
            self._select_all_chip.configure(bg=ACCENT, fg=TEXT_PRIMARY)
        else:
            self._select_all_chip.configure(bg=BG_INPUT, fg=TEXT_SECONDARY)

    def _trade_execute(self) -> None:
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

        brokers_str = ", ".join(sorted(selected))
        label = f"{side.upper()} {qty_str} {symbol} on [{brokers_str}]" + (" [DRY RUN]" if dry_run else "")
        self._log(f"Trade: {label}")
        self._trade_result_write(f"Executing: {label}\n")

        # launch one thread per broker in parallel
        for broker in sorted(selected):
            self._run_in_thread(self._trade_worker, broker, side, symbol, qty_str, dry_run)

    def _trade_result_write(self, text: str) -> None:
        self._trade_result.configure(state="normal")
        self._trade_result.insert("end", text)
        self._trade_result.see("end")
        self._trade_result.configure(state="disabled")

    def _fetch_fill_price(self, broker: str, symbol: str) -> Optional[float]:
        """Try to get current price from broker holdings after a trade."""
        try:
            mod = _load_broker(broker)
            output = mod.get_holdings()
            for acct in output.accounts:
                for h in acct.holdings:
                    if h.symbol and h.symbol.upper() == symbol.upper() and h.price is not None:
                        return h.price
        except Exception:
            pass
        return None

    def _trade_worker(self, broker: str, side: str, symbol: str, qty: str, dry_run: bool) -> None:
        use_block = broker in _BROWSER_BROKERS
        try:
            if use_block:
                self.after(0, lambda b=broker: self._log(
                    f"  {b}: waiting for browser..." if _browser_lock.locked() else f"  {b}: starting trade..."))
                _browser_lock.acquire()

            load_dotenv(ENV_FILE, override=True)
            mod = _load_broker(broker)

            # Live progress: tail the broker's nav log for real-time updates
            done = threading.Event()
            log_file = Path("sessions") / broker / f"{broker}_nav.log"
            last_size = [log_file.stat().st_size if log_file.exists() else 0]

            def progress_ticker():
                while not done.is_set():
                    done.wait(3)
                    if done.is_set():
                        break
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
                                    self.after(0, lambda b=broker, m=msg: self._log(f"  {b}: {m}"))
                    except Exception:
                        pass

            ticker = threading.Thread(target=progress_ticker, daemon=True)
            ticker.start()

            try:
                output: BrokerOutput = mod.execute_trade(
                    side=side, qty=qty, symbol=symbol, dry_run=dry_run,
                )
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
                fill_price = self._fetch_fill_price(broker, symbol)

            for acct in output.accounts:
                status = "OK" if acct.ok else "FAIL"
                lines.append(f"  [{status}] {acct.account_id}: {acct.message}")
                if acct.ok and not dry_run:
                    trade_journal.record_trade(
                        broker=broker, account_id=acct.account_id,
                        side=side, symbol=symbol, qty=float(qty),
                        fill_price=fill_price,
                    )

            if fill_price is not None:
                lines.append(f"  Fill price: ${fill_price:.2f}")

            result_text = "\n".join(lines) + "\n\n"
            self.after(0, lambda t=result_text: self._trade_result_write(t))
            self.after(0, lambda b=broker, s=output.state: self._log(f"Trade: {b} -> {s}"))
        except Exception as e:
            self.after(0, lambda b=broker, err=e: self._trade_result_write(f"[{b.capitalize()}] Error: {err}\n\n"))
            self.after(0, lambda b=broker, err=e: self._log(f"Trade error ({b}): {err}"))
        finally:
            if use_block:
                try:
                    _browser_lock.release()
                except RuntimeError:
                    pass

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

        # Filter bar + refresh
        top_bar = tk.Frame(scroll_frame, bg=BG_PRIMARY)
        top_bar.pack(fill="x", pady=(0, 16), padx=(0, 4))
        PillButton(top_bar, text="Refresh Stats", command=self._refresh_stats,
                   width=140, height=36).pack(side="right")

        # Period filter chips
        tk.Label(top_bar, text="PERIOD", bg=BG_PRIMARY, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 9, "bold")).pack(side="left", padx=(0, 8))
        self._stats_period = tk.StringVar(value="all")
        self._stats_period_chips: Dict[str, tk.Label] = {}
        for period_val, period_label in [
            ("month", "This Month"), ("last_month", "Last Month"),
            ("year", "This Year"), ("all", "All Time"),
        ]:
            chip = tk.Label(top_bar, text=period_label,
                            bg=ACCENT if period_val == "all" else BG_INPUT,
                            fg=TEXT_PRIMARY if period_val == "all" else TEXT_SECONDARY,
                            font=(FONT_FAMILY, 8, "bold"), cursor="hand2", padx=10, pady=4)
            chip.pack(side="left", padx=(0, 6))
            self._stats_period_chips[period_val] = chip
            chip.bind("<Button-1>", lambda e, pv=period_val: self._set_stats_period(pv))

        # ---- Key Metrics Row ----
        metrics_row = tk.Frame(scroll_frame, bg=BG_PRIMARY)
        metrics_row.pack(fill="x", pady=(0, 16))
        for i in range(5):
            metrics_row.columnconfigure(i, weight=1)

        self._stat_total_trades = self._make_stat_card(metrics_row, "TOTAL TRADES", "0", 0)
        self._stat_win_rate = self._make_stat_card(metrics_row, "WIN RATE", "—", 1)
        self._stat_total_pl = self._make_stat_card(metrics_row, "REALIZED P/L", "$0.00", 2)
        self._stat_best_trade = self._make_stat_card(metrics_row, "BEST TRADE", "—", 3)
        self._stat_worst_trade = self._make_stat_card(metrics_row, "WORST TRADE", "—", 4)

        # ---- Trade Summary Card ----
        summary_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        summary_card.pack(fill="x", pady=(0, 16))

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

        # ---- Per-Broker Breakdown ----
        broker_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        broker_card.pack(fill="x", pady=(0, 16))

        tk.Label(broker_card.inner, text="Per-Broker Performance", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 12))

        cols = ("broker", "trades", "buys", "sells", "volume", "avg_size")
        self._broker_stats_tree = ttk.Treeview(
            broker_card.inner, columns=cols, show="headings", height=10,
            selectmode="none")
        for col, heading, w in [
            ("broker", "Broker", 140),
            ("trades", "Trades", 80),
            ("buys", "Buys", 80),
            ("sells", "Sells", 80),
            ("volume", "Volume", 120),
            ("avg_size", "Avg Size", 100),
        ]:
            self._broker_stats_tree.heading(col, text=heading)
            self._broker_stats_tree.column(col, width=w, anchor="center" if col != "broker" else "w")
        self._broker_stats_tree.pack(fill="x", padx=20, pady=(0, 16))

        # ---- Symbol Performance ----
        symbol_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        symbol_card.pack(fill="x", pady=(0, 16))

        tk.Label(symbol_card.inner, text="Symbol Performance", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 12))

        sym_cols = ("symbol", "trades", "shares_bought", "shares_sold", "avg_buy", "avg_sell", "net_position", "pl")
        self._symbol_stats_tree = ttk.Treeview(
            symbol_card.inner, columns=sym_cols, show="headings", height=10,
            selectmode="none")
        for col, heading, w in [
            ("symbol", "Symbol", 100),
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

        # ---- Recent Trades ----
        recent_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        recent_card.pack(fill="x", pady=(0, 16))

        tk.Label(recent_card.inner, text="Recent Trades", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 12))

        recent_cols = ("time", "broker", "account", "side", "symbol", "qty", "price", "total")
        recent_tree_frame = tk.Frame(recent_card.inner, bg=BG_CARD)
        recent_tree_frame.pack(fill="x", padx=20, pady=(0, 16))
        self._recent_trades_tree = ttk.Treeview(
            recent_tree_frame, columns=recent_cols, show="headings", height=25,
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

        # ---- Trade Simulator ----
        sim_card = RoundedFrame(scroll_frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        sim_card.pack(fill="x", pady=(0, 16))

        tk.Label(sim_card.inner, text="Trade Simulator", bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 8))
        tk.Label(sim_card.inner, text="Estimate profit from a round-trip trade across multiple accounts",
                 bg=BG_CARD, fg=TEXT_MUTED, font=(FONT_FAMILY, 8)).pack(anchor="w", padx=20, pady=(0, 12))

        sim_form = tk.Frame(sim_card.inner, bg=BG_CARD)
        sim_form.pack(fill="x", padx=20, pady=(0, 12))

        # Ticker
        tk.Label(sim_form, text="TICKER", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_ticker = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        self._sim_ticker.grid(row=0, column=1, sticky="w", padx=(0, 16), pady=(0, 6))

        # Fetch Price button
        PillButton(sim_form, text="Fetch Price", command=self._sim_fetch_price,
                   width=100, height=28).grid(row=0, column=2, sticky="w", padx=(0, 16), pady=(0, 6))

        # Current price (auto-filled)
        tk.Label(sim_form, text="BUY PRICE", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_buy_price = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        self._sim_buy_price.grid(row=1, column=1, sticky="w", padx=(0, 16), pady=(0, 6))

        # Sell / round-up price
        tk.Label(sim_form, text="SELL PRICE", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_sell_price = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        self._sim_sell_price.grid(row=1, column=3, sticky="w", padx=(0, 16), pady=(0, 6))

        # Shares per account
        tk.Label(sim_form, text="SHARES / ACCT", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=2, column=0, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_qty = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        self._sim_qty.insert(0, "1")
        self._sim_qty.grid(row=2, column=1, sticky="w", padx=(0, 16), pady=(0, 6))

        # Number of accounts
        tk.Label(sim_form, text="ACCOUNTS", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=(FONT_FAMILY, 8, "bold")).grid(row=2, column=2, sticky="w", padx=(0, 10), pady=(0, 6))
        self._sim_accounts = ttk.Entry(sim_form, width=10, font=(FONT_MONO, 10))
        # Pre-fill with total linked accounts
        total_accts = sum(
            _KNOWN_ACCOUNT_COUNTS.get(b, 1) if _broker_has_creds(b) else 0
            for b in BROKER_MODULES
        )
        self._sim_accounts.insert(0, str(total_accts))
        self._sim_accounts.grid(row=2, column=3, sticky="w", padx=(0, 16), pady=(0, 6))

        # Calculate button
        calc_row = tk.Frame(sim_card.inner, bg=BG_CARD)
        calc_row.pack(fill="x", padx=20, pady=(0, 8))
        PillButton(calc_row, text="Calculate", command=self._sim_calculate,
                   width=110, height=32).pack(side="left")

        # Result display
        self._sim_result = tk.Label(sim_card.inner, text="", bg=BG_CARD, fg=TEXT_PRIMARY,
                                    font=(FONT_MONO, 10), justify="left", anchor="w")
        self._sim_result.pack(fill="x", padx=20, pady=(0, 16))

        # Initial load
        self.after(200, self._refresh_stats)

    def _set_stats_period(self, period: str) -> None:
        self._stats_period.set(period)
        for pv, chip in self._stats_period_chips.items():
            if pv == period:
                chip.configure(bg=ACCENT, fg=TEXT_PRIMARY)
            else:
                chip.configure(bg=BG_INPUT, fg=TEXT_SECONDARY)
        self._refresh_stats()

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

    def _refresh_stats(self) -> None:
        all_trades = trade_journal.get_trades()

        # Filter by selected period
        period = self._stats_period.get() if hasattr(self, "_stats_period") else "all"
        now = datetime.now()
        if period == "month":
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

        # ---- Key metrics ----
        total = len(trades)
        buys = [t for t in trades if t["side"] == "buy"]
        sells = [t for t in trades if t["side"] == "sell"]
        symbols = set(t["symbol"] for t in trades)
        brokers_used = set(t["broker"] for t in trades)
        accounts_used = set((t["broker"], t["account_id"]) for t in trades)

        self._stat_total_trades.configure(text=str(total))
        self._stat_buys.configure(text=str(len(buys)))
        self._stat_sells.configure(text=str(len(sells)))
        self._stat_symbols.configure(text=str(len(symbols)))
        self._stat_brokers_used.configure(text=str(len(brokers_used)))
        self._stat_accounts_used.configure(text=str(len(accounts_used)))

        total_shares = sum(t["qty"] for t in trades)
        self._stat_shares.configure(text=f"{total_shares:,.0f}")

        total_volume = sum((t["fill_price"] or 0) * t["qty"] for t in trades)
        self._stat_volume.configure(text=f"${total_volume:,.2f}")

        avg_trade = total_volume / total if total else 0
        self._stat_avg_trade.configure(text=f"${avg_trade:,.2f}")

        # ---- Win/loss analysis per symbol ----
        # Track realized P/L: for each symbol, match buys to sells
        sym_buys: Dict[str, List] = {}
        sym_sells: Dict[str, List] = {}
        for t in trades:
            bucket = sym_buys if t["side"] == "buy" else sym_sells
            bucket.setdefault(t["symbol"], []).append(t)

        realized_pl = 0.0
        wins = 0
        losses = 0
        best = 0.0
        worst = 0.0

        for sym in symbols:
            b_list = sym_buys.get(sym, [])
            s_list = sym_sells.get(sym, [])
            if not b_list or not s_list:
                continue
            avg_buy = sum((t["fill_price"] or 0) * t["qty"] for t in b_list) / max(sum(t["qty"] for t in b_list), 1)
            avg_sell = sum((t["fill_price"] or 0) * t["qty"] for t in s_list) / max(sum(t["qty"] for t in s_list), 1)
            sold_qty = sum(t["qty"] for t in s_list)
            pl = (avg_sell - avg_buy) * sold_qty
            realized_pl += pl
            if pl > 0:
                wins += 1
                best = max(best, pl)
            elif pl < 0:
                losses += 1
                worst = min(worst, pl)

        closed = wins + losses
        win_rate = (wins / closed * 100) if closed > 0 else 0
        self._stat_win_rate.configure(
            text=f"{win_rate:.0f}%",
            fg=GREEN if win_rate >= 50 else RED if closed > 0 else TEXT_PRIMARY)
        self._stat_total_pl.configure(
            text=f"${realized_pl:+,.2f}",
            fg=GREEN if realized_pl >= 0 else RED)
        self._stat_best_trade.configure(
            text=f"${best:+,.2f}" if best != 0 else "—",
            fg=GREEN if best > 0 else TEXT_PRIMARY)
        self._stat_worst_trade.configure(
            text=f"${worst:+,.2f}" if worst != 0 else "—",
            fg=RED if worst < 0 else TEXT_PRIMARY)

        # ---- Per-broker table ----
        self._broker_stats_tree.delete(*self._broker_stats_tree.get_children())
        broker_data: Dict[str, Dict] = {}
        for t in trades:
            b = t["broker"]
            d = broker_data.setdefault(b, {"trades": 0, "buys": 0, "sells": 0, "volume": 0.0})
            d["trades"] += 1
            if t["side"] == "buy":
                d["buys"] += 1
            else:
                d["sells"] += 1
            d["volume"] += (t["fill_price"] or 0) * t["qty"]

        for b in sorted(broker_data):
            d = broker_data[b]
            avg = d["volume"] / d["trades"] if d["trades"] else 0
            self._broker_stats_tree.insert("", "end", values=(
                b.capitalize(), d["trades"], d["buys"], d["sells"],
                f"${d['volume']:,.2f}", f"${avg:,.2f}"))

        # ---- Symbol performance table ----
        self._symbol_stats_tree.delete(*self._symbol_stats_tree.get_children())
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
            else:
                d["sold"] += t["qty"]
                d["sell_rev"] += price * t["qty"]

        for s in sorted(sym_data):
            d = sym_data[s]
            avg_b = d["buy_cost"] / d["bought"] if d["bought"] else 0
            avg_s = d["sell_rev"] / d["sold"] if d["sold"] else 0
            net = d["bought"] - d["sold"]
            pl = d["sell_rev"] - (avg_b * d["sold"]) if d["sold"] and d["bought"] else 0
            pl_str = f"${pl:+,.2f}" if d["sold"] and d["bought"] else "—"
            self._symbol_stats_tree.insert("", "end", values=(
                s, d["trades"],
                f"{d['bought']:,.0f}", f"{d['sold']:,.0f}",
                f"${avg_b:,.4f}" if avg_b else "—",
                f"${avg_s:,.4f}" if avg_s else "—",
                f"{net:,.0f}",
                pl_str))

        # ---- Recent trades table ----
        self._recent_trades_tree.delete(*self._recent_trades_tree.get_children())
        for t in reversed(trades[-100:]):
            ts = t.get("timestamp", "")[:19].replace("T", " ")
            price = t["fill_price"]
            total_val = (price or 0) * t["qty"]
            side_tag = t["side"].upper()
            self._recent_trades_tree.insert("", "end", values=(
                ts,
                t["broker"].capitalize(),
                t.get("account_id", ""),
                side_tag,
                t["symbol"],
                f"{t['qty']:,.0f}",
                f"${price:,.4f}" if price else "\u2014",
                f"${total_val:,.2f}"),
                tags=(t["side"],))

        # Color the side column
        self._recent_trades_tree.tag_configure("buy", foreground=GREEN)
        self._recent_trades_tree.tag_configure("sell", foreground=RED)

        self._log("Stats: refreshed")

    # ---- Simulator --------------------------------------------------------

    def _sim_fetch_price(self) -> None:
        """Fetch current price for the ticker using Yahoo Finance CSV endpoint."""
        ticker = self._sim_ticker.get().strip().upper()
        if not ticker:
            return

        def _worker():
            try:
                url = f"https://query1.finance.yahoo.com/v8/finance/chart/{ticker}?range=1d&interval=1d"
                req = urllib.request.Request(url, headers={"User-Agent": "gotEV/1.0"})
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
        return {"enabled": False, "brokers": [], "executed": []}

    def _save_mirror_state(self) -> None:
        """Persist mirror trading state to disk."""
        import json
        state = {
            "enabled": self._mirror_enabled.get(),
            "brokers": list(self._mirror_selected_brokers),
            "executed": list(self._mirror_executed),
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
            chip = tk.Label(chip_row, text=broker.capitalize(),
                            bg=ACCENT if is_selected else BG_INPUT,
                            fg=TEXT_PRIMARY if is_selected else TEXT_SECONDARY,
                            font=(FONT_FAMILY, 8, "bold"),
                            cursor="hand2", padx=10, pady=4)
            chip.pack(side="left", padx=(0, 4), pady=2)
            self._mirror_broker_chips[broker] = {"label": chip, "selected": is_selected}
            chip.bind("<Button-1>", lambda e, b=broker: self._toggle_mirror_broker(b))

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

    def _toggle_mirror_broker(self, broker: str) -> None:
        chip = self._mirror_broker_chips[broker]
        if chip["selected"]:
            chip["selected"] = False
            chip["label"].configure(bg=BG_INPUT, fg=TEXT_SECONDARY)
            self._mirror_selected_brokers.discard(broker)
        else:
            chip["selected"] = True
            chip["label"].configure(bg=ACCENT, fg=TEXT_PRIMARY)
            self._mirror_selected_brokers.add(broker)
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
        confirm = messagebox.askyesno(
            "Enable Mirror Trading",
            f"Are you sure you want to enable Mirror Trading?\n\n"
            f"This will automatically BUY 1 share of any new Reg Alert pick "
            f"on the following brokers:\n\n"
            f"  {brokers_str}\n\n"
            f"Only new picks added AFTER this moment will be executed.\n"
            f"You can disable it at any time.",
            parent=self)
        if not confirm:
            return

        # Snapshot current picks so we don't execute existing ones
        for pick in self._quick_picks:
            note = pick.get("note", "").lower()
            if note in ("reg alert", "alert", "early access"):
                key = (pick.get("date", ""), pick.get("symbol", ""))
                self._mirror_executed.add(key)

        self._mirror_enabled.set(True)
        self._mirror_status_dot.itemconfig("all", fill=GREEN, outline=GREEN)
        self._mirror_status_lbl.configure(text="ACTIVE", fg=GREEN)
        self._mirror_toggle_btn.configure_text("Disable Mirror Trading")
        self._mirror_log_msg(f"Mirror trading ENABLED on: {brokers_str}")
        self._mirror_log_msg(f"Monitoring for new Reg Alert picks every 60s...")
        self._save_mirror_state()

        # Start polling
        self._mirror_poll()

    def _mirror_poll(self) -> None:
        """Poll for new picks and auto-execute eligible ones."""
        if not self._mirror_enabled.get():
            return

        def _worker():
            picks = _fetch_quick_picks()
            new_picks = []
            for pick in picks:
                note = pick.get("note", "").lower()
                # Only Reg Alert / alert / early access
                if note not in ("reg alert", "alert", "early access"):
                    continue
                key = (pick.get("date", ""), pick.get("symbol", ""))
                if key not in self._mirror_executed:
                    new_picks.append(pick)

            if new_picks:
                self.after(0, lambda: self._mirror_execute(new_picks))
            else:
                self.after(0, lambda: self._mirror_log_msg("Poll: no new picks"))

            # Schedule next poll
            if self._mirror_enabled.get():
                self._mirror_poll_id = self.after(60000, self._mirror_poll)

        threading.Thread(target=_worker, daemon=True).start()

    def _mirror_execute(self, picks: List[Dict[str, str]]) -> None:
        """Execute BUY 1 share for each new pick on selected brokers."""
        if not self._mirror_selected_brokers:
            self._mirror_log_msg("No brokers selected — skipping")
            return

        for pick in picks:
            symbol = pick.get("symbol", "").upper()
            date = pick.get("date", "")
            key = (date, symbol)

            # Double-check not already executed
            if key in self._mirror_executed:
                continue

            self._mirror_executed.add(key)
            self._mirror_log_msg(f"NEW PICK: {symbol} — executing BUY 1 share")
            self._mirror_exec_count.configure(
                text=f"{len(self._mirror_executed)} pick(s) already executed")

            # Execute on each selected broker (reuse trade worker)
            for broker in sorted(self._mirror_selected_brokers):
                self._mirror_log_msg(f"  {broker}: sending BUY 1 {symbol}...")
                self._run_in_thread(self._trade_worker, broker, "buy", symbol, "1", False)

            # Play notification sound
            try:
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass

        self._save_mirror_state()

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

        # Bootstrap All button
        top_bar = tk.Frame(scroll_frame, bg=BG_PRIMARY)
        top_bar.pack(fill="x", pady=(0, 12), padx=(0, 4))
        PillButton(top_bar, text="Bootstrap All", command=self._bootstrap_all,
                   width=140, height=36).pack(side="left")

        self._account_widgets: Dict[str, Dict[str, Any]] = {}

        for broker in sorted(BROKER_MODULES.keys()):
            # plain frame card with border effect
            card_outer = tk.Frame(scroll_frame, bg=BORDER, padx=1, pady=1)
            card_outer.pack(fill="x", pady=(0, 10), padx=(0, 4))
            card = tk.Frame(card_outer, bg=BG_CARD)
            card.pack(fill="both", expand=True)

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
            PillButton(save_frame, text="Save", bg_color="#2a2a40", hover_color=ACCENT,
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
            # Serialize browser-based brokers to prevent Chrome conflicts
            use_lock = broker in _BROWSER_BROKERS
            if use_lock:
                self.after(0, lambda: widgets["status"].configure(
                    text="waiting for browser..." if _browser_lock.locked() else "bootstrapping...", fg=YELLOW))
                _browser_lock.acquire()
                self.after(0, lambda: widgets["status"].configure(text="bootstrapping...", fg=YELLOW))
            try:
                load_dotenv(ENV_FILE, override=True)
                mod = _load_broker(broker)
                output: BrokerOutput = mod.bootstrap()
            finally:
                if use_lock:
                    _browser_lock.release()
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
                    # Update total accounts card (replace, not add)
                    self._update_total_accounts(broker, n_accounts)
                else:
                    widgets["dot"].set_color(RED)
                    widgets["status"].configure(text=output.message or "failed", fg=RED)
                    if broker in self._broker_status_labels:
                        self._broker_status_labels[broker]["dot"].set_color(RED)
                        self._broker_status_labels[broker]["status"].configure(
                            text="failed", fg=RED)
                self._log(f"Accounts: {broker} bootstrap -> {output.state}")

            self.after(0, update)
        except Exception as e:
            self.after(0, lambda: widgets["status"].configure(text=str(e)[:40], fg=RED))
            self.after(0, lambda err=e: self._log(f"Accounts: {broker} error - {err}"))

    # ---- Logs -------------------------------------------------------------

    def _build_logs(self) -> None:
        frame = tk.Frame(self._content, bg=BG_PRIMARY)
        self._frames["logs"] = frame

        log_card = RoundedFrame(frame, bg_color=BG_CARD, border_color=BORDER, radius=14)
        log_card.pack(fill="both", expand=True)

        self._log_text = tk.Text(log_card.inner, bg=BG_CARD, fg=TEXT_PRIMARY,
                                 font=(FONT_MONO, 10), bd=0, wrap="word",
                                 state="disabled", insertbackground=TEXT_PRIMARY,
                                 highlightthickness=0, padx=16, pady=12)
        scrollbar = ttk.Scrollbar(log_card.inner, orient="vertical",
                                  command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=scrollbar.set)
        self._log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y", pady=4)

        # tag for timestamps
        self._log_text.tag_configure("ts", foreground=TEXT_MUTED)

        if self._log_lines:
            self._log_text.configure(state="normal")
            for line in self._log_lines:
                self._log_text.insert("end", line + "\n")
            self._log_text.see("end")
            self._log_text.configure(state="disabled")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = App()
    app.mainloop()

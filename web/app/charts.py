"""Charts as inline SVG, generated server-side.

No chart library and no CDN: the dashboard is meant to open fast on a phone
over cell data, and these shapes are simple enough that a few dozen lines of
path math beats a 300 KB dependency.

Every function returns a complete <svg> string with a viewBox and no fixed
width, so CSS controls the size and the chart scales on any screen.
"""
from __future__ import annotations

from datetime import datetime
from html import escape

ACCENT = "#7c78ff"
GREEN = "#34d39e"
RED = "#fb6f84"
GRID = "#1f2330"
MUTED = "#565b6b"

# Donut slice colors: accent-led, then desaturated steps. Semantic green/red
# are deliberately excluded here so they keep meaning profit/loss elsewhere.
SLICES = ["#7c78ff", "#9d9aff", "#5f7fd6", "#6fb2c9", "#8b90a0", "#565b6b",
          "#a97fd0", "#c9a2e0", "#4f5566", "#7a8296"]


def _money(v: float) -> str:
    return f"${v:,.0f}"


def empty(message: str = "No data yet") -> str:
    return (
        f'<svg viewBox="0 0 400 160" role="img" aria-label="{escape(message)}">'
        f'<text x="200" y="84" text-anchor="middle" fill="{MUTED}" '
        f'font-size="13" font-family="inherit">{escape(message)}</text></svg>'
    )


def equity_line(points: list[tuple[datetime, float]]) -> str:
    """Cumulative realized P/L. Filled area under a single accent stroke."""
    if len(points) < 2:
        return empty("Not enough closed trades yet")

    w, h = 700.0, 240.0
    pad_l, pad_r, pad_t, pad_b = 8.0, 8.0, 16.0, 20.0
    xs = [p[0].timestamp() for p in points]
    ys = [p[1] for p in points]
    x0, x1 = min(xs), max(xs)
    y0, y1 = min(0.0, min(ys)), max(ys)
    if x1 == x0:
        x1 = x0 + 1
    if y1 == y0:
        y1 = y0 + 1

    def sx(x: float) -> float:
        return pad_l + (x - x0) / (x1 - x0) * (w - pad_l - pad_r)

    def sy(y: float) -> float:
        return h - pad_b - (y - y0) / (y1 - y0) * (h - pad_t - pad_b)

    coords = [(sx(x), sy(y)) for x, y in zip(xs, ys)]
    line = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    area = f"{line} L{coords[-1][0]:.1f},{h - pad_b:.1f} L{coords[0][0]:.1f},{h - pad_b:.1f} Z"
    base = sy(0.0)

    return f"""<svg viewBox="0 0 {w:.0f} {h:.0f}" preserveAspectRatio="none" class="chart-eq" role="img" aria-label="Cumulative realized profit over time">
  <defs><linearGradient id="eqfill" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="{ACCENT}" stop-opacity="0.35"/>
    <stop offset="100%" stop-color="{ACCENT}" stop-opacity="0"/>
  </linearGradient></defs>
  <line x1="0" y1="{base:.1f}" x2="{w:.0f}" y2="{base:.1f}" stroke="{GRID}" stroke-width="1"/>
  <path d="{area}" fill="url(#eqfill)"/>
  <path d="{line}" fill="none" stroke="{ACCENT}" stroke-width="2"
        stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
  <circle cx="{coords[-1][0]:.1f}" cy="{coords[-1][1]:.1f}" r="3.5" fill="{ACCENT}"/>
</svg>"""


def month_bars(data: list[tuple[str, float]]) -> str:
    """Realized P/L per month. Green above the zero line, red below."""
    if not data:
        return empty("No closed trades yet")

    w, h = 700.0, 220.0
    pad_b, pad_t = 30.0, 14.0
    n = len(data)
    slot = w / n
    bw = min(slot * 0.55, 56.0)

    vals = [v for _k, v in data]
    top = max(vals + [0.0])
    bot = min(vals + [0.0])
    span = (top - bot) or 1.0

    def sy(v: float) -> float:
        return h - pad_b - (v - bot) / span * (h - pad_t - pad_b)

    zero = sy(0.0)
    parts = [
        f'<line x1="0" y1="{zero:.1f}" x2="{w:.0f}" y2="{zero:.1f}" stroke="{GRID}" stroke-width="1"/>'
    ]
    for i, (label, v) in enumerate(data):
        cx = slot * i + slot / 2
        y = sy(v)
        color = GREEN if v >= 0 else RED
        top_y, bar_h = (y, zero - y) if v >= 0 else (zero, y - zero)
        bar_h = max(bar_h, 1.0)
        short = label[5:] if len(label) == 7 else label  # "2026-03" -> "03"
        parts.append(
            f'<rect x="{cx - bw / 2:.1f}" y="{top_y:.1f}" width="{bw:.1f}" height="{bar_h:.1f}" '
            f'rx="3" fill="{color}" opacity="0.85"><title>{escape(label)}: {_money(v)}</title></rect>'
            f'<text x="{cx:.1f}" y="{h - pad_b + 15:.0f}" text-anchor="middle" fill="{MUTED}" '
            f'font-size="11" font-family="inherit">{escape(short)}</text>'
        )
    return (
        f'<svg viewBox="0 0 {w:.0f} {h:.0f}" class="chart-bars" role="img" '
        f'aria-label="Realized profit by month">{"".join(parts)}</svg>'
    )


def broker_bars(data: list[tuple[str, float]]) -> str:
    """Horizontal ranked bars, one per broker."""
    if not data:
        return empty("No closed trades yet")

    row_h, gap = 30.0, 10.0
    w = 700.0
    label_w = 110.0
    h = len(data) * (row_h + gap) + gap
    peak = max((abs(v) for _k, v in data), default=1.0) or 1.0
    track = w - label_w - 90.0

    parts = []
    for i, (name, v) in enumerate(data):
        y = gap + i * (row_h + gap)
        bar = abs(v) / peak * track
        color = GREEN if v >= 0 else RED
        parts.append(
            f'<text x="0" y="{y + row_h * 0.68:.1f}" fill="#8b90a0" font-size="13" '
            f'font-family="inherit">{escape(name.title())}</text>'
            f'<rect x="{label_w}" y="{y:.1f}" width="{track:.1f}" height="{row_h:.1f}" rx="5" fill="{GRID}"/>'
            f'<rect x="{label_w}" y="{y:.1f}" width="{max(bar, 2):.1f}" height="{row_h:.1f}" rx="5" '
            f'fill="{color}" opacity="0.85"/>'
            f'<text x="{label_w + track + 10:.1f}" y="{y + row_h * 0.68:.1f}" fill="#f3f4f8" '
            f'font-size="13" font-family="inherit">{_money(v)}</text>'
        )
    return (
        f'<svg viewBox="0 0 {w:.0f} {h:.0f}" class="chart-hbars" role="img" '
        f'aria-label="Realized profit by broker">{"".join(parts)}</svg>'
    )


def allocation_donut(rows: list[tuple[str, float, float]]) -> str:
    """Share-count allocation of open positions. `rows` is (symbol, qty, pct)."""
    if not rows:
        return empty("No open positions")

    size, r_out, r_in = 220.0, 100.0, 62.0
    cx = cy = size / 2
    import math

    parts = []
    angle = -math.pi / 2  # start at 12 o'clock
    shown = rows[:len(SLICES)]
    rest = rows[len(SLICES):]
    if rest:
        shown = shown + [("Other", sum(r[1] for r in rest), sum(r[2] for r in rest))]

    for i, (sym, qty, pct) in enumerate(shown):
        sweep = pct / 100.0 * 2 * math.pi
        if sweep <= 0:
            continue
        end = angle + sweep
        large = 1 if sweep > math.pi else 0
        x1, y1 = cx + r_out * math.cos(angle), cy + r_out * math.sin(angle)
        x2, y2 = cx + r_out * math.cos(end), cy + r_out * math.sin(end)
        x3, y3 = cx + r_in * math.cos(end), cy + r_in * math.sin(end)
        x4, y4 = cx + r_in * math.cos(angle), cy + r_in * math.sin(angle)
        color = SLICES[i % len(SLICES)]
        # A single full-circle slice can't be drawn as an arc (start == end).
        if abs(sweep - 2 * math.pi) < 1e-9:
            parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.1f}" fill="none" '
                f'stroke="{color}" stroke-width="{r_out - r_in:.1f}">'
                f'<title>{escape(sym)}: {qty:g} sh (100%)</title></circle>'
            )
        else:
            parts.append(
                f'<path d="M{x1:.2f},{y1:.2f} A{r_out},{r_out} 0 {large} 1 {x2:.2f},{y2:.2f} '
                f'L{x3:.2f},{y3:.2f} A{r_in},{r_in} 0 {large} 0 {x4:.2f},{y4:.2f} Z" '
                f'fill="{color}"><title>{escape(sym)}: {qty:g} sh ({pct:.1f}%)</title></path>'
            )
        angle = end

    total = sum(r[1] for r in rows)
    parts.append(
        f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" fill="#f3f4f8" font-size="26" '
        f'font-weight="600" font-family="inherit">{total:g}</text>'
        f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" fill="{MUTED}" font-size="11" '
        f'letter-spacing="1" font-family="inherit">SHARES</text>'
    )
    return (
        f'<svg viewBox="0 0 {size:.0f} {size:.0f}" class="chart-donut" role="img" '
        f'aria-label="Open position allocation">{"".join(parts)}</svg>'
    )


def donut_legend(rows: list[tuple[str, float, float]]) -> list[tuple[str, float, float, str]]:
    shown = rows[:len(SLICES)]
    rest = rows[len(SLICES):]
    out = [(s, q, p, SLICES[i % len(SLICES)]) for i, (s, q, p) in enumerate(shown)]
    if rest:
        out.append(("Other", sum(r[1] for r in rest), sum(r[2] for r in rest), SLICES[-1]))
    return out

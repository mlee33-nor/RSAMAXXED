"""The RSAMAXXED mark.

A heavy geometric "R", sliced clean through on a rising diagonal, with its
upper half kicked up and to the right. That is the whole product in one glyph:
the brand's initial, SPLIT (a reverse split), and the piece above the cut
lifted -- the fraction rounded up. White on the brand's violet tile (the same
150deg accent -> #4d49d6 gradient the website's nav mark uses), so the desktop,
taskbar and site all read as one thing.

Three outputs, because they have different constraints:

  draw_mark()  vector, on a tk.Canvas, for the in-app wordmark. Scales to
               whatever the shell asks for and costs nothing at import.
  ico_path()   a real .ico on disk, because Windows' titlebar, taskbar and
               desktop shortcut will not take anything else. Cached.
  write_svg()  the master vector (assets/rsamaxxed.svg) for anything else.

All three draw the same polygons (_glyph_parts), so they cannot drift apart.

Legibility at 16px drove the choices. A single bold letterform survives a
taskbar where a pictogram turns to mush; the cut is wide enough to still show
as a pixel of tile at 16px; and below 48px every vertical and horizontal edge
is snapped to whole pixels (_params) so the stem and baseline stay crisp
instead of landing on half pixels and going soft.

Regenerate every asset with:  py -3.13 logo.py
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parent
ASSET_DIR = ROOT / "assets"
ICO_FILE = ASSET_DIR / "rsamaxxed.ico"
PNG_FILE = ASSET_DIR / "rsamaxxed.png"
SVG_FILE = ASSET_DIR / "rsamaxxed.svg"

# The shell's accent, repeated here so this module has no import cycle back
# into app.py. Keep in step with ACCENT there.
ACCENT = "#7c78ff"
INK = "#0a0a12"
GLYPH = "#ffffff"
# Tile gradient, top-left -> bottom-right. Matches the website's .brand .mark
# (linear-gradient(150deg, var(--accent), #4d49d6)), nudged a touch lighter at
# the top so the tile still separates from a dark taskbar.
TILE_TOP = "#8e8aff"
TILE_BOTTOM = "#4d49d6"

# Windows renders the icon at all of these; supplying each avoids the ugly
# nearest-neighbour downscale it does when it has to invent one.
_ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)

# --------------------------------------------------------------------------
# Geometry, as fractions of the tile's side.
# --------------------------------------------------------------------------
RADIUS = 0.225            # tile corner radius

_UNIT = dict(
    x0=0.20, x1=0.38,     # stem, left and right edge
    top=0.16, base=0.84,  # cap height and baseline
    bowl_r=0.70,          # outer right edge of the bowl
    bowl_b=0.54,          # bottom of the bowl
    cx1=0.48, cy0=0.30, cy1=0.40,   # the counter (a D, flat on the stem side)
    leg=((0.45, 0.58), (0.64, 0.58), (0.80, 0.84), (0.61, 0.84)),
    cut_y=0.71,           # where the cut crosses x=0 ...
    cut_slope=-0.24,      # ... rising to the right
    gap=0.05,             # width of the cut
    lift=(0.025, -0.03),  # how far the upper half is kicked up and right
)

SMALL_CUT_BELOW = 32      # sizes under this get the level, pixel-row cut
SMALL_CUT_ROW = 0
SMALL_LIFT = (1.0, 0.0)

Pt = Tuple[float, float]
Poly = List[Pt]


def _params(size: float) -> Dict[str, Any]:
    """_UNIT scaled to a `size`-px tile; snapped to whole pixels when small."""
    s = size
    u = _UNIT
    p: Dict[str, Any] = {k: u[k] * s for k in
                         ("x0", "x1", "top", "base", "bowl_r", "bowl_b",
                          "cx1", "cy0", "cy1", "cut_y", "gap")}
    p["leg"] = [(x * s, y * s) for x, y in u["leg"]]
    p["cut_slope"] = u["cut_slope"]
    p["lift"] = (u["lift"][0] * s, u["lift"][1] * s)
    p["radius"] = RADIUS * s
    if s < 48:
        for k in ("x0", "x1", "top", "base", "bowl_r", "bowl_b",
                  "cx1", "cy0", "cy1"):
            p[k] = float(round(p[k]))
        p["leg"] = [(round(x), round(y)) for x, y in p["leg"]]
        p["leg"][0] = (p["leg"][0][0], p["bowl_b"] - 1)
        p["leg"][1] = (p["leg"][1][0], p["bowl_b"] - 1)
        p["leg"][2] = (p["leg"][2][0], p["base"])
        p["leg"][3] = (p["leg"][3][0], p["base"])
        # The cut must survive as at least a pixel of tile, and the lift as at
        # least a pixel of movement, or the idea vanishes at taskbar size.
        p["gap"] = max(p["gap"], 1.4)
        p["lift"] = (float(round(p["lift"][0])), float(min(-1, round(p["lift"][1]))))
        p["radius"] = {16: 3.5, 20: 4.5, 24: 5.5, 32: 7, 40: 9}.get(int(s), p["radius"])
        if s < SMALL_CUT_BELOW:
            # A diagonal cut at this size is a staircase of half-lit pixels
            # that chews the letter apart. Cut level instead, on a whole pixel
            # row just under the bowl, and kick the top half right by one:
            # still visibly split-and-lifted, and every edge stays crisp.
            p["cut_slope"] = 0.0
            p["cut_y"] = p["bowl_b"] + SMALL_CUT_ROW + 0.5
            p["gap"] = 1.0
            p["lift"] = SMALL_LIFT
    return p


def _arc(cx: float, cy: float, r: float, a0: float, a1: float, n: int = 24) -> Poly:
    return [(cx + r * math.cos(math.radians(a0 + (a1 - a0) * i / n)),
             cy + r * math.sin(math.radians(a0 + (a1 - a0) * i / n)))
            for i in range(n + 1)]


def _clip(poly: Poly, c: float, b: float, keep_above: bool) -> Poly:
    """Sutherland-Hodgman against the half-plane y <= c + b*x (or >=)."""
    def f(pt: Pt) -> float:
        v = pt[1] - (c + b * pt[0])
        return v if keep_above else -v

    out: Poly = []
    n = len(poly)
    for i in range(n):
        a, z = poly[i], poly[(i + 1) % n]
        fa, fz = f(a), f(z)
        if fa <= 0:
            out.append(a)
        if (fa <= 0) != (fz <= 0):
            t = fa / (fa - fz)
            out.append((a[0] + (z[0] - a[0]) * t, a[1] + (z[1] - a[1]) * t))
    return out


def _glyph_parts(size: float) -> List[Tuple[Poly, bool]]:
    """The glyph as ordered (polygon, ink) pairs in pixels; ink=False knocks out.

    Paint them in order: the upper half (lifted), its counter knocked out of
    it, then the lower half.
    """
    p = _params(size)
    x0, x1, top, base = p["x0"], p["x1"], p["top"], p["base"]
    bb, br = p["bowl_b"], p["bowl_r"]
    r = (bb - top) / 2
    stem: Poly = [(x0, top), (x1, top), (x1, base), (x0, base)]
    bowl: Poly = [(x0, top), (br - r, top)] + _arc(br - r, top + r, r, -90, 90) \
        + [(br - r, bb), (x0, bb)]
    cr = (p["cy1"] - p["cy0"]) / 2
    counter: Poly = [(x1, p["cy0"]), (p["cx1"] - cr, p["cy0"])] \
        + _arc(p["cx1"] - cr, p["cy0"] + cr, cr, -90, 90) + [(x1, p["cy1"])]
    leg: Poly = list(p["leg"])

    # The cut: a band of width `gap` (measured square to the line) around
    # y = cut_y + slope*x.
    b = p["cut_slope"]
    h = p["gap"] / 2 * math.sqrt(1 + b * b)
    c_up, c_lo = p["cut_y"] - h, p["cut_y"] + h
    dx, dy = p["lift"]

    def lifted(poly: Poly) -> Poly:
        return [(x + dx, y + dy) for x, y in poly]

    parts: List[Tuple[Poly, bool]] = []
    for shape in (stem, bowl, leg):
        up = _clip(shape, c_up, b, keep_above=True)
        if len(up) >= 3:
            parts.append((lifted(up), True))
    parts.append((lifted(counter), False))
    for shape in (stem, leg):
        lo = _clip(shape, c_lo, b, keep_above=False)
        if len(lo) >= 3:
            parts.append((lo, True))
    return parts


# --------------------------------------------------------------------------
# In-app canvas mark
# --------------------------------------------------------------------------
def draw_mark(canvas: Any, size: int, *, bg: str, fg: str = ACCENT,
              ink: str = GLYPH) -> None:
    """Paint the mark into `canvas`, filling a `size`x`size` box.

    Uses the same hand-drawn approach as the app's charts: no image files, no
    scaling artefacts, and it recolours with the theme for free.
    """
    canvas.delete("all")
    canvas.configure(bg=bg, highlightthickness=0, bd=0)

    s = size
    r = max(2, int(s * RADIUS))

    # Rounded tile. Tk has no rounded rect, so it is two rects plus four arcs --
    # the same trick RoundedFrame uses.
    canvas.create_rectangle(r, 0, s - r, s, fill=fg, outline=fg)
    canvas.create_rectangle(0, r, s, s - r, fill=fg, outline=fg)
    for x, y, start in ((0, 0, 90), (s - 2 * r, 0, 0),
                        (0, s - 2 * r, 180), (s - 2 * r, s - 2 * r, 270)):
        canvas.create_arc(x, y, x + 2 * r, y + 2 * r, start=start, extent=90,
                          fill=fg, outline=fg)

    for poly, is_ink in _glyph_parts(s):
        colour = ink if is_ink else fg
        canvas.create_polygon(*[c for pt in poly for c in pt],
                              fill=colour, outline="")


# --------------------------------------------------------------------------
# Raster
# --------------------------------------------------------------------------
def _hex(h: str) -> Tuple[int, int, int]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]


def _gradient(s: int):
    """The tile's diagonal violet gradient, s x s."""
    from PIL import Image

    # Build it along one axis and rotate -- a per-pixel loop at 4096px is slow.
    a, b = _hex(TILE_TOP), _hex(TILE_BOTTOM)
    n = int(s * 1.5)
    ramp = Image.new("RGB", (n, 1))
    ramp.putdata([tuple(int(a[i] + (b[i] - a[i]) * t / (n - 1)) for i in range(3))
                  for t in range(n)])
    ramp = ramp.resize((n, n))
    # 150deg CSS == top-left light, bottom-right dark, steeper than 45.
    ramp = ramp.rotate(-60, resample=Image.BICUBIC, expand=False)
    off = (n - s) // 2
    return ramp.crop((off, off, off + s, off + s))


def _glyph_mask(size: int, scale: int):
    from PIL import Image, ImageDraw

    s = size * scale
    m = Image.new("L", (s, s), 0)
    d = ImageDraw.Draw(m)
    for poly, is_ink in _glyph_parts(size):
        d.polygon([(x * scale, y * scale) for x, y in poly],
                  fill=255 if is_ink else 0)
    return m


def _render_png(size: int):
    """One square of the mark as a PIL image, transparent outside the tile."""
    from PIL import Image, ImageChops, ImageDraw, ImageFilter

    # Draw oversized and downsample: PIL has no anti-aliased primitives, and at
    # 16px the difference between this and a jagged tile is the whole icon.
    scale = 8 if size <= 64 else max(2, 4096 // size)
    s = size * scale
    small = size < 48          # no shadow/sheen/rim: at 16-40px they are mud

    tile = Image.new("L", (s, s), 0)
    radius = _params(size)["radius"] * scale
    ImageDraw.Draw(tile).rounded_rectangle([0, 0, s - 1, s - 1], radius=radius,
                                           fill=255)
    img = _gradient(s).convert("RGBA")
    glyph = _glyph_mask(size, scale)

    if not small:
        # A soft top-left light, so the tile has a little volume.
        light = Image.new("L", (s, s), 0)
        ImageDraw.Draw(light).ellipse([-s * .55, -s * .85, s * .95, s * .55], fill=26)
        light = light.filter(ImageFilter.GaussianBlur(s * .12))
        white = Image.new("RGBA", (s, s), (255, 255, 255, 0))
        white.putalpha(light)
        img = Image.alpha_composite(img, white)

        # A deep-violet drop shadow under the glyph lifts it off the tile.
        blur = glyph.filter(ImageFilter.GaussianBlur(s * .028))
        shadow = Image.new("RGBA", (s, s), (22, 14, 90, 0))
        shadow.putalpha(blur.point(lambda v: int(v * .55)))
        shadow = ImageChops.offset(shadow, 0, int(s * .014))
        img = Image.alpha_composite(img, shadow)

    fg = Image.new("RGBA", (s, s), _hex(GLYPH) + (0,))
    fg.putalpha(glyph)
    img = Image.alpha_composite(img, fg)

    if not small:
        # The 1px white rim the website's mark has (border: rgba(255,255,255,.18)).
        rim = Image.new("L", (s, s), 0)
        ImageDraw.Draw(rim).rounded_rectangle(
            [0, 0, s - 1, s - 1], radius=radius, outline=58,
            width=max(scale, int(s * .008)))
        wr = Image.new("RGBA", (s, s), (255, 255, 255, 0))
        wr.putalpha(rim)
        img = Image.alpha_composite(img, wr)

    img.putalpha(ImageChops.multiply(img.getchannel("A"), tile))
    return img.resize((size, size), Image.LANCZOS)


def _write_ico(path: Path) -> None:
    """A multi-size .ico where every size is its own rendering, not a rescale."""
    frames = [_render_png(n) for n in _ICO_SIZES]
    # Pillow's ICO writer takes the largest image plus `append_images` and
    # keeps any appended frame whose size matches a requested size exactly.
    frames[-1].save(path, format="ICO", sizes=[(n, n) for n in _ICO_SIZES],
                    append_images=frames[:-1])


def ico_path(force: bool = False) -> str:
    """Path to the .ico, generating it on first use. '' if it can't be made.

    Never raises: a missing icon must not stop the terminal from opening.
    """
    try:
        if ICO_FILE.exists() and not force:
            return str(ICO_FILE)
        ASSET_DIR.mkdir(parents=True, exist_ok=True)
        _write_ico(ICO_FILE)
        return str(ICO_FILE)
    except Exception:
        return ""


def save_png(path: str | Path = PNG_FILE, size: int = 1024) -> str:
    """Write a standalone PNG -- for a README, a store listing, the web."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    _render_png(size).save(p, format="PNG")
    return str(p)


# --------------------------------------------------------------------------
# Vector master
# --------------------------------------------------------------------------
def svg_markup(size: int = 1024) -> str:
    s = size
    f = lambda v: f"{v:.1f}".rstrip("0").rstrip(".")  # noqa: E731

    def pts(poly: Sequence[Pt]) -> str:
        return " ".join(f"{f(x)},{f(y)}" for x, y in poly)

    shapes = "\n      ".join(
        f'<polygon points="{pts(poly)}" fill="{"#fff" if ink else "#000"}"/>'
        for poly, ink in _glyph_parts(s))
    r = RADIUS * s
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {s} {s}" width="{s}" height="{s}">
  <title>RSAMAXXED</title>
  <defs>
    <linearGradient id="tile" x1="0.2" y1="0" x2="0.8" y2="1">
      <stop offset="0" stop-color="{TILE_TOP}"/>
      <stop offset="1" stop-color="{TILE_BOTTOM}"/>
    </linearGradient>
    <radialGradient id="light" cx="0.2" cy="0" r="0.8">
      <stop offset="0" stop-color="#fff" stop-opacity="0.12"/>
      <stop offset="1" stop-color="#fff" stop-opacity="0"/>
    </radialGradient>
    <mask id="glyph" maskUnits="userSpaceOnUse" x="0" y="0" width="{s}" height="{s}">
      {shapes}
    </mask>
    <filter id="lift" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="{f(0.014 * s)}" stdDeviation="{f(0.028 * s)}" flood-color="#160e5a" flood-opacity="0.55"/>
    </filter>
  </defs>
  <rect width="{s}" height="{s}" rx="{f(r)}" fill="url(#tile)"/>
  <rect width="{s}" height="{s}" rx="{f(r)}" fill="url(#light)"/>
  <g filter="url(#lift)">
    <rect width="{s}" height="{s}" fill="{GLYPH}" mask="url(#glyph)"/>
  </g>
  <rect x="{f(0.004 * s)}" y="{f(0.004 * s)}" width="{f(0.992 * s)}" height="{f(0.992 * s)}" rx="{f(r - 0.004 * s)}" fill="none" stroke="#fff" stroke-opacity="0.23" stroke-width="{f(0.008 * s)}"/>
</svg>
"""


def write_svg(path: str | Path = SVG_FILE) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(svg_markup(), encoding="utf-8")
    return str(p)


if __name__ == "__main__":  # pragma: no cover - manual generation
    print("svg:", write_svg())
    print("png:", save_png())
    print("png:", save_png(ASSET_DIR / "rsamaxxed-512.png", 512))
    print("ico:", ico_path(force=True))

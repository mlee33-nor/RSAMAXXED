"""The RSAMAXXED mark.

One idea, drawn two ways: a fraction being rounded up to a whole share. That is
the entire product, so it is what the mark says — an arrow rising out of a
split floor, the gap being the fraction a reverse split leaves behind.

Two renderers, because they have different constraints:

  draw_mark()  vector, on a tk.Canvas, for the in-app wordmark. Scales to
               whatever the shell asks for and costs nothing at import.
  ico_path()   a real .ico on disk, because Windows' titlebar and taskbar will
               not take anything else. Generated once and cached.

Legibility at 16px drove every choice here. The arrowhead is a filled triangle
because a stroked chevron turns to grey mush in a taskbar; the floor is split
rather than solid because a solid bar makes the whole thing read as the generic
"upload" glyph; and there are four shapes total because five stopped resolving.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
ASSET_DIR = ROOT / "assets"
ICO_FILE = ASSET_DIR / "rsamaxxed.ico"

# The shell's accent, repeated here so this module has no import cycle back
# into app.py. Keep in step with ACCENT there.
ACCENT = "#7c78ff"
INK = "#0a0a12"

# Windows renders the icon at all of these; supplying each avoids the ugly
# nearest-neighbour downscale it does when it has to invent one.
_ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)


def draw_mark(canvas: Any, size: int, *, bg: str, fg: str = ACCENT,
              ink: str = INK) -> None:
    """Paint the mark into `canvas`, filling a `size`×`size` box.

    Uses the same hand-drawn approach as the app's charts: no image files, no
    scaling artefacts, and it recolours with the theme for free.
    """
    canvas.delete("all")
    canvas.configure(bg=bg, highlightthickness=0, bd=0)

    s = size
    r = max(2, int(s * 0.22))          # corner radius of the tile

    # Rounded tile. Tk has no rounded rect, so it is two rects plus four arcs —
    # the same trick RoundedFrame uses.
    canvas.create_rectangle(r, 0, s - r, s, fill=fg, outline=fg)
    canvas.create_rectangle(0, r, s, s - r, fill=fg, outline=fg)
    for x, y, start in ((0, 0, 90), (s - 2 * r, 0, 0),
                        (0, s - 2 * r, 180), (s - 2 * r, s - 2 * r, 270)):
        canvas.create_arc(x, y, x + 2 * r, y + 2 * r, start=start, extent=90,
                          fill=fg, outline=fg)

    # The floor a fraction sits on, and the arrow lifting it to a whole share.
    # An arrow rather than a second bar: two bars read as a chart, and a chart
    # is what this product is emphatically not about.
    # A SPLIT floor, not a solid one: the gap is the fraction a reverse split
    # leaves behind, and the arrow is it being rounded up. It also stops the
    # mark reading as the generic "upload" glyph, which a solid bar does.
    base_y = s * 0.78
    bar_h = s * 0.10
    canvas.create_rectangle(s * 0.20, base_y, s * 0.44, base_y + bar_h,
                            fill=ink, outline=ink)
    canvas.create_rectangle(s * 0.56, base_y, s * 0.80, base_y + bar_h,
                            fill=ink, outline=ink)

    stem_w = s * 0.16
    canvas.create_rectangle(s * 0.50 - stem_w / 2, s * 0.36,
                            s * 0.50 + stem_w / 2, base_y - s * 0.04,
                            fill=ink, outline=ink)

    # Arrowhead — a filled triangle, which survives 16px where a stroked
    # chevron turns to grey mush.
    canvas.create_polygon(s * 0.50, s * 0.17,
                          s * 0.76, s * 0.44,
                          s * 0.24, s * 0.44,
                          fill=ink, outline=ink)


def _render_png(size: int):
    """One square of the mark as a PIL image, transparent outside the tile."""
    from PIL import Image, ImageDraw

    # Draw at 4x and downsample: PIL has no anti-aliased primitives, and at
    # 16px the difference between this and a jagged tile is the whole icon.
    scale = 4
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.22), fill=ACCENT)

    base_y = s * 0.78
    bar_h = s * 0.10
    d.rectangle([s * 0.20, base_y, s * 0.44, base_y + bar_h], fill=INK)
    d.rectangle([s * 0.56, base_y, s * 0.80, base_y + bar_h], fill=INK)

    stem_w = s * 0.16
    d.rectangle([s * 0.50 - stem_w / 2, s * 0.36,
                 s * 0.50 + stem_w / 2, base_y - s * 0.04], fill=INK)

    d.polygon([(s * 0.50, s * 0.17), (s * 0.76, s * 0.44), (s * 0.24, s * 0.44)],
              fill=INK)

    return img.resize((size, size), Image.LANCZOS)


def ico_path(force: bool = False) -> str:
    """Path to the .ico, generating it on first use. '' if it can't be made.

    Never raises: a missing icon must not stop the terminal from opening.
    """
    try:
        if ICO_FILE.exists() and not force:
            return str(ICO_FILE)
        ASSET_DIR.mkdir(parents=True, exist_ok=True)
        base = _render_png(max(_ICO_SIZES))
        base.save(ICO_FILE, format="ICO",
                  sizes=[(n, n) for n in _ICO_SIZES])
        return str(ICO_FILE)
    except Exception:
        return ""


def save_png(path: str | Path, size: int = 512) -> str:
    """Write a standalone PNG — for the web favicon, a README, a store listing."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    _render_png(size).save(p, format="PNG")
    return str(p)


if __name__ == "__main__":  # pragma: no cover - manual generation
    print("ico:", ico_path(force=True))
    print("png:", save_png(ASSET_DIR / "rsamaxxed-512.png"))

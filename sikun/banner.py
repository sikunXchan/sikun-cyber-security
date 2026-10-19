"""Startup banner: renders the Sikun mascot as colored half-block art in the terminal."""

from __future__ import annotations

from pathlib import Path

import numpy as np
from PIL import Image
from rich.console import Console, Group
from rich.segment import Segment
from rich.style import Style
from rich.text import Text

MASCOT_PATH = Path(__file__).parent / "assets" / "mascot.png"

TITLE = "SIKUN"                       # drawn big, as block letters
SUBTITLE_MAIN = "CYBER SECURITY"      # drawn in colored caps under the big title
SUBTITLE = "authorized attack-exercise agent"

# ---------------------------------------------------------------------------
# Big block-letter font (dependency-free; avoids pulling in pyfiglet just for
# the title). Each glyph is 5 rows of '█'/space, padded to a common width when
# assembled. Covers exactly the letters used by TITLE / SUBTITLE_MAIN so the
# header can be rendered large like a classic CLI splash.
# ---------------------------------------------------------------------------
_BLOCK_FONT: dict[str, list[str]] = {
    "S": ["█████", "█    ", "█████", "    █", "█████"],
    "I": ["███", " █ ", " █ ", " █ ", "███"],
    "K": ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"],
    "U": ["█   █", "█   █", "█   █", "█   █", "█████"],
    "N": ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    "C": ["█████", "█    ", "█    ", "█    ", "█████"],
    "Y": ["█   █", " █ █ ", "  █  ", "  █  ", "  █  "],
    "B": ["████ ", "█   █", "████ ", "█   █", "████ "],
    "E": ["█████", "█    ", "███  ", "█    ", "█████"],
    "R": ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    "T": ["█████", "  █  ", "  █  ", "  █  ", "  █  "],
    " ": ["   ", "   ", "   ", "   ", "   "],
}
_BLOCK_ROWS = 5

# Vertical cyan->blue shading per row, echoing the reference splash art.
_BLOCK_ROW_COLORS = ["#8ad4ff", "#4fb8ff", "#2f9fff", "#1f82e6", "#1566c8"]


def _big_text_lines(text: str) -> list[str]:
    """Assemble `text` into 5 plain rows of block letters (one space between
    glyphs). Unknown characters are skipped so this never raises."""
    glyphs = [_BLOCK_FONT[c] for c in text.upper() if c in _BLOCK_FONT]
    if not glyphs:
        return [""] * _BLOCK_ROWS
    rows: list[str] = []
    for r in range(_BLOCK_ROWS):
        rows.append("  ".join(g[r] for g in glyphs))
    return rows


def big_title() -> Text:
    """Rich Text of the big block title, each row shaded top->bottom."""
    out = Text()
    for row, color in zip(_big_text_lines(TITLE), _BLOCK_ROW_COLORS):
        out.append(row + "\n", style=color)
    return out


def _binarize_bw(img: Image.Image, threshold: int = 128) -> Image.Image:
    """Snap every opaque pixel to pure black or pure white.

    mascot.png is a 2-tone (black outline / white fill) source, but it still
    carries a thin anti-aliased gray gradient at every edge. At 128px source
    -> ~36 char target that gradient is wide relative to the target
    resolution, so plain resizing (any filter) samples/blends into visible
    gray speckle instead of a clean outline. Thresholding first removes every
    gray value before resizing ever sees it — there is nothing left to leak.
    """
    arr = np.asarray(img.convert("RGBA")).astype(np.float32)
    rgb, alpha = arr[..., :3], arr[..., 3]
    luminance = rgb.mean(axis=-1)
    bw = np.where(luminance < threshold, 0, 255).astype(np.uint8)
    out = np.dstack([bw, bw, bw, alpha.astype(np.uint8)])
    return Image.fromarray(out, mode="RGBA")


def _premultiplied_resize(img: Image.Image, size: tuple[int, int]) -> Image.Image:
    """Resize an RGBA image without bleeding the (often garbage) RGB color of
    fully-transparent pixels into the opaque edges.

    Plain Image.resize() blends RGB and alpha independently. If transparent
    pixels happen to store black (very common — e.g. this mascot's transparent
    area is (0,0,0,0)), every edge/outline in the downsampled result picks up
    a dark, muddy fringe. Premultiplying by alpha before resizing — then
    dividing it back out — makes transparent pixels contribute nothing to the
    blended color, regardless of what RGB they happen to store.

    Uses NEAREST rather than LANCZOS: at this downsampling ratio (source is
    often 1000px+, target ~36px) LANCZOS's negative lobes ring around hard
    black-outline/cream-fill edges and leave stray gray speckle. NEAREST
    avoids blending entirely, which also reads as a crisper pixel-art look.
    """
    arr = np.asarray(img).astype(np.float32)
    rgb, alpha = arr[..., :3], arr[..., 3]

    premult = (rgb * (alpha[..., None] / 255.0)).astype(np.uint8)
    premult_resized = np.asarray(
        Image.fromarray(premult, mode="RGB").resize(size, Image.NEAREST)
    ).astype(np.float32)
    alpha_resized = np.asarray(
        Image.fromarray(alpha.astype(np.uint8), mode="L").resize(size, Image.NEAREST)
    ).astype(np.float32)

    safe_alpha = np.where(alpha_resized < 1, 1, alpha_resized)
    rgb_result = np.clip(premult_resized / (safe_alpha[..., None] / 255.0), 0, 255)

    out = np.dstack([rgb_result.astype(np.uint8), alpha_resized.astype(np.uint8)])
    return Image.fromarray(out, mode="RGBA")


def _mascot_segments(width: int = 36) -> list[Segment]:
    """Render mascot.png as half-block (▀) art: two image rows per text row.

    Transparent pixels become plain spaces so the terminal's own background
    shows through instead of a black box.
    """
    img = _binarize_bw(Image.open(MASCOT_PATH).convert("RGBA"))
    aspect = img.height / img.width
    # each text row covers 2 image rows, so double the vertical sample count
    target_h = max(2, int(width * aspect))
    if target_h % 2:
        target_h += 1
    img = _premultiplied_resize(img, (width, target_h))

    segments: list[Segment] = []
    px = img.load()
    for y in range(0, target_h, 2):
        for x in range(width):
            top = px[x, y]
            bottom = px[x, y + 1]
            top_visible = top[3] > 40
            bottom_visible = bottom[3] > 40
            if not top_visible and not bottom_visible:
                segments.append(Segment(" "))
                continue
            if top_visible and bottom_visible:
                fg = f"rgb({top[0]},{top[1]},{top[2]})"
                bg = f"rgb({bottom[0]},{bottom[1]},{bottom[2]})"
                segments.append(Segment("▀", Style(color=fg, bgcolor=bg)))
            else:
                # Only one half has real pixel data. Leaving the other side's
                # color unset makes Rich fall back to the terminal's ambient
                # default (which is often not pure black), producing a faint
                # gray fringe exactly along the silhouette edge. Filling the
                # whole cell with the one real color avoids depending on that
                # default at all — costs a little edge precision, not correctness.
                color = top if top_visible else bottom
                fg = f"rgb({color[0]},{color[1]},{color[2]})"
                segments.append(Segment("█", Style(color=fg)))
        segments.append(Segment("\n"))
    return segments


def banner_renderable(width: int = 36) -> Group:
    """Rich renderable combining mascot art + the big block title — usable in
    plain console output or embedded inside a Textual widget."""
    subtitle_main = Text(SUBTITLE_MAIN, style="bold #ff2bd6")
    subtitle = Text(SUBTITLE + "\n", style="dim #6a7a99")
    return Group(_MascotRenderable(width), big_title(), subtitle_main, subtitle)


class _MascotRenderable:
    def __init__(self, width: int = 36) -> None:
        self.width = width

    def __rich_console__(self, console: Console, options):
        yield from _mascot_segments(self.width)


def print_banner(width: int = 36) -> None:
    console = Console()
    console.print(_MascotRenderable(width))
    console.print(big_title())
    console.print(SUBTITLE_MAIN, style="bold #ff2bd6")
    console.print(SUBTITLE, style="dim")


if __name__ == "__main__":
    print_banner()

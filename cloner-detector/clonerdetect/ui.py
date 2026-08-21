"""Terminal styling, banner, tables and progress rendering (stdlib only)."""

from __future__ import annotations

import os
import shutil
import sys
from typing import Iterable, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Colour handling
# ---------------------------------------------------------------------------

class C:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    RED = "\x1b[91m"
    GREEN = "\x1b[92m"
    YELLOW = "\x1b[93m"
    BLUE = "\x1b[94m"
    MAGENTA = "\x1b[95m"
    CYAN = "\x1b[96m"
    WHITE = "\x1b[97m"
    GREY = "\x1b[90m"
    BGRED = "\x1b[101m"
    BGGREEN = "\x1b[42m"


def _tty_supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Best-effort enable of VT sequences on modern Windows consoles.
        try:
            import ctypes

            k32 = ctypes.windll.kernel32
            return bool(k32.SetConsoleMode(k32.GetStdHandle(-11), 7))
        except Exception:
            return False
    return os.environ.get("TERM", "") != "dumb"


COLOR_ENABLED = _tty_supports_color()


def enable_color(enabled: bool) -> None:
    global COLOR_ENABLED
    COLOR_ENABLED = enabled


def paint(text: str, *styles: str) -> str:
    if not COLOR_ENABLED or not styles:
        return text
    return "".join(styles) + text + C.RESET


def red(text: str, bold: bool = False) -> str:
    return paint(text, C.RED, C.BOLD if bold else "")


def green(text: str, bold: bool = False) -> str:
    return paint(text, C.GREEN, C.BOLD if bold else "")


def yellow(text: str, bold: bool = False) -> str:
    return paint(text, C.YELLOW, C.BOLD if bold else "")


def cyan(text: str, bold: bool = False) -> str:
    return paint(text, C.CYAN, C.BOLD if bold else "")


def grey(text: str) -> str:
    return paint(text, C.GREY)


def bold(text: str) -> str:
    return paint(text, C.BOLD)


SEVERITY_STYLE = {
    "critical": lambda t: paint(t, C.BGRED, C.BOLD, C.WHITE),
    "high": lambda t: red(t, bold=True),
    "medium": lambda t: yellow(t),
    "low": lambda t: cyan(t),
    "info": lambda t: grey(t),
}

VERDICT_STYLE = {
    "DEFINITIVE": lambda t: paint(t, C.BGRED, C.BOLD, C.WHITE),
    "LIKELY": lambda t: red(t, bold=True),
    "SUSPICIOUS": lambda t: yellow(t, bold=True),
    "CLEAN": lambda t: green(t, bold=True),
}


def style_severity(severity: str) -> str:
    fn = SEVERITY_STYLE.get(severity.lower(), grey)
    return fn(severity.upper())


def style_verdict(verdict: str) -> str:
    fn = VERDICT_STYLE.get(verdict.upper(), bold)
    return fn(verdict.upper())


# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------

def terminal_width(default: int = 100) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default


def _clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    text = str(text).replace("\n", " ")
    if len(text) <= width:
        return text
    if width <= 1:
        return "…"
    return text[: width - 1] + "…"


def _pad(text: str, width: int) -> str:
    text = _clip(text, width)
    return text + " " * max(0, width - len(text))


class Table:
    """Minimal auto-width table renderer with box-drawing borders."""

    def __init__(self, headers: Sequence[str], rows: Iterable[Sequence[object]],
                 max_col: int = 48) -> None:
        self.headers = [str(h) for h in headers]
        self.rows = [[str(c) for c in row] for row in rows]
        self.max_col = max_col

    def _widths(self) -> List[int]:
        cols = len(self.headers)
        widths = [len(h) for h in self.headers]
        for row in self.rows:
            for i in range(cols):
                if i >= len(row):
                    continue
                widths[i] = max(widths[i], len(_clip(row[i], self.max_col)))
        # Cap total table width to terminal (leave room for borders).
        avail = max(30, terminal_width() - 2)
        total = sum(widths) + 3 * cols + 1
        if total > avail:
            overflow = total - avail
            # Shrink from the widest column down.
            order = sorted(range(cols), key=lambda i: -widths[i])
            for i in order:
                if overflow <= 0:
                    break
                cut = min(overflow, max(0, widths[i] - 8))
                widths[i] -= cut
                overflow -= cut
        return widths

    def render(self) -> str:
        if not self.rows:
            return grey("  (no rows)")
        widths = self._widths()
        cols = len(self.headers)

        def row_line(cells: Sequence[str]) -> str:
            return "│ " + " │ ".join(
                _pad(_clip(c, widths[i]), widths[i]) for i, c in enumerate(cells)
            ) + " │"

        def border(left: str, mid: str, right: str, fill: str) -> str:
            return left + mid.join(fill * (w + 2) for w in widths) + right

        lines = [border("┌", "┬", "┐", "─")]
        lines.append(row_line(self.headers))
        lines.append(border("├", "┼", "┤", "─"))
        for row in self.rows:
            padded = row + [""] * (cols - len(row))
            lines.append(row_line(padded[:cols]))
        lines.append(border("└", "┴", "┘", "─"))
        return "\n".join(lines)


def box(lines: Sequence[str], border_color: str = C.CYAN,
        width: Optional[int] = None) -> str:
    """Wrap lines in a single-cell box, padded to a common width."""
    if not lines:
        return ""
    if width is None:
        width = max(len(_visible(l)) for l in lines) + 2
    top = "╔" + "═" * (width - 2) + "╗"
    bottom = "╚" + "═" * (width - 2) + "╝"
    body = []
    for line in lines:
        vis = _visible(line)
        pad = max(0, width - 2 - vis)
        body.append("║ " + line + " " * pad + " ║")
    out = "\n".join([top] + body + [bottom])
    if COLOR_ENABLED and border_color:
        out = paint(out, border_color)
    return out


def _visible(text: str) -> int:
    # Strip ANSI escapes for length calculations.
    out = []
    i = 0
    while i < len(text):
        if text[i] == "\x1b":
            j = text.find("m", i)
            i = (j + 1) if j != -1 else len(text)
            continue
        out.append(text[i])
        i += 1
    return len("".join(out))


def progressbar(done: int, total: int, width: int = 26, label: str = "") -> str:
    total = max(1, total)
    frac = min(1.0, done / total)
    filled = int(round(frac * width))
    bar = "█" * filled + "░" * (width - filled)
    pct = int(frac * 100)
    text = f"[{bar}] {pct:3d}%  ({done}/{total})"
    if label:
        text = f"{label} {text}"
    return text


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = (
    "{r} ██████╗{x} {c}██╗  ██╗{x}       {r}██████╗ ██╗      ██████╗ ███╗   ██╗{x}\n"
    "{r}██╔════╝{x} {c}██║  ██║{x}       {r}██╔══██╗██║     ██╔═══██╗████╗  ██║{x}\n"
    "{r}██║     {x} {c}███████║{x}       {r}██████╔╝██║     ██║   ██║██╔██╗ ██║{x}\n"
    "{r}██║     {x} {c}██╔══██║{x}       {r}██╔══██╗██║     ██║   ██║██║╚██╗██║{x}\n"
    "{r}╚██████╗{x} {c}██║  ██║{x}       {r}██║  ██║███████╗╚██████╔╝██║ ╚████║{x}\n"
    "{r} ╚═════╝{x} {c}╚═╝  ╚═╝{x}       {r}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝{x}\n"
    "{y}██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗{x}\n"
    "{y}██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗{x}\n"
    "{y}███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝{x}\n"
    "{y}██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗{x}\n"
    "{y}██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║{x}\n"
    "{y}╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{x}\n"
)


def banner(version: str = "", tagline: str = "") -> str:
    if not COLOR_ENABLED:
        r = c = y = x = ""
    else:
        r, c, y = C.RED, C.CYAN, C.YELLOW
        x = C.RESET
    art = BANNER.format(r=r, c=c, y=y, x=x)
    if version:
        art += f"\n  {grey('version')} {bold(version)}"
    if tagline:
        art += f"\n  {cyan(tagline)}"
    return art


def divider(char: str = "─", color: str = C.GREY) -> str:
    line = char * min(terminal_width(), 100)
    return paint(line, color) if COLOR_ENABLED else line

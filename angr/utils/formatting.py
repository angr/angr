from __future__ import annotations
import sys
from collections.abc import Sequence, Callable


if sys.platform == "win32":
    import colorama  # pylint:disable=import-error


ansi_color_enabled: bool = False


def setup_terminal():
    """
    Check if we are running in a TTY. If so, make sure the terminal supports ANSI escape sequences. If not, disable
    colorized output. Sets global `ansi_color_enabled` to True if colorized output should be enabled by default.
    """
    isatty = (
        hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
    )
    if sys.platform == "win32" and isatty:
        if not isinstance(sys.stdout, colorama.ansitowin32.StreamWrapper):
            colorama.init()

    global ansi_color_enabled  # pylint:disable=global-statement
    ansi_color_enabled = isatty


def ansi_color(s: str, color: str | None) -> str:
    """
    Colorize string `s` by wrapping in ANSI escape sequence for given `color`.

    This function does not consider whether escape sequences are functional or not; it is up to the caller to determine
    if its appropriate. Check global `ansi_color_enabled` value in this module.
    """
    if color is None:
        return s

    codes = {
        "black": "30m",
        "bright_black": "90m",
        "gray": "90m",  # alias 'bright black'
        "blue": "34m",
        "bright_blue": "94m",
        "cyan": "36m",
        "bright_cyan": "96m",
        "green": "32m",
        "bright_green": "92m",
        "magenta": "35m",
        "bright_magenta": "95m",
        "red": "31m",
        "bright_red": "91m",
        "white": "37m",
        "bright_white": "97m",
        "yellow": "33m",
        "bright_yellow": "93m",
    }
    return "\u001b[" + codes[color] + s + "\u001b[0m"


def add_edge_to_buffer(
    buf: Sequence[str],
    ref: Sequence[str],
    start: int,
    end: int,
    formatter: Callable[[str], str] | None = None,
    dashed: bool = False,
    ascii_only: bool | None = None,
):
    """
    Draw an edge by adding Unicode box and arrow glyphs to beginning of each line in a list of lines.

    :param buf: Output buffer, used to render formatted edges.
    :param ref: Reference buffer, used to calculate edge depth.
    :param start: Start line.
    :param end: End line, where arrow points.
    :param formatter: Optional callback function used to format the edge before writing it to output buffer.
    :param dashed: Render edge line dashed instead of solid.
    :param ascii_only: Render edge using ASCII characters only. If unspecified, guess by stdout encoding.
    :return:
    """
    abs_start = min(start, end)
    abs_end = max(start, end)
    max_depth = max(map(len, ref[abs_start : abs_end + 1]))
    descending = start < end

    if ascii_only is None:
        # Guess whether we should only use ASCII characters based on stdout encoding
        ascii_only = getattr(sys.stdout, "encoding", None) != "utf-8"

    if ascii_only:
        chars = {
            "start_cap": "-",
            "start_corner": "+",
            "end_cap": ">",
            "end_corner": "+",
            "horizontal": "+" if dashed else "-",
            "vertical": "+" if dashed else "|",
            "spin": "@ ",
        }
    else:
        chars = {
            "start_cap": "╴",
            "start_corner": "╭" if descending else "╰",
            "end_cap": "▸",
            "end_corner": "╰" if descending else "╭",
            "horizontal": "╌" if dashed else "─",
            "vertical": "╎" if dashed else "│",
            "spin": "⟳ ",
        }

    def handle_line(i, edge_str):
        if formatter is not None:
            edge_str = formatter(edge_str)
        buf[i] = edge_str + buf[i]

    if start == end:
        handle_line(start, chars["spin"])
    else:
        handle_line(
            start, (chars["start_corner"] + chars["horizontal"] * (max_depth - len(ref[start])) + chars["start_cap"])
        )
        handle_line(end, (chars["end_corner"] + chars["horizontal"] * (max_depth - len(ref[end])) + chars["end_cap"]))
        for i in range(abs_start + 1, abs_end):
            handle_line(i, chars["vertical"] + " " * (1 + max_depth - len(ref[i])))

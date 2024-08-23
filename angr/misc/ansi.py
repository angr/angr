from __future__ import annotations
from enum import Enum, unique


_ansi_prefix = "\x1b["


#
# Ansi colors
#


clear: str = f"{_ansi_prefix}0m"


@unique
class Color(Enum):
    """
    The basic ansi colors
    """

    black = 30
    red = 31
    green = 32
    yellow = 33
    blue = 34
    magenta = 35
    cyan = 36
    white = 37


BackgroundColor = unique(Enum("BackgroundColor", {i.name: (i.value + 10) for i in Color}))


#
# Functions
#


def color(c: Color | BackgroundColor, bright: bool):
    """
    Return the ansi prefix using the given code
    Bright may not be used with a BackgroundColor
    """
    if bright and isinstance(c, BackgroundColor):
        raise ValueError("Backgrounds should not be bright")
    return f"{_ansi_prefix}{c.value};1m" if bright else f"{_ansi_prefix}{c.value}m"

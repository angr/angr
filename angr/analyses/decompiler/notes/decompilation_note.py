from __future__ import annotations
from typing import Any

from enum import Enum


class DecompilationNoteLevel(Enum):
    """
    Enum class describing the level of each decompilation note.
    """

    DEBUG = 0
    INFO = 1
    WARNING = 2
    CRITICAL = 3


class DecompilationNote:
    """
    Describes a note that is generated during decompilation.

    Key is a unique string for the decompilation note. It is used as an index in the decompilation notes dictionary in
    the Decompiler class.
    Name is string for display by default.
    Content is the actual content of the note. It can be of any time, but for custom types, you must override `__str__`
    so that it can be displayed.
    Level is the level of the note. The following values are available: DecompilationNoteLevel.DEBUG,
    DecompilationNoteLevel.INFO, DecompilationNoteLevel.WARNING, and DecompilationNoteLevel.CRITICAL.
    """

    __slots__ = (
        "content",
        "key",
        "level",
        "name",
    )

    def __init__(self, key: str, name: str, content: Any, *, level=DecompilationNoteLevel.INFO):
        self.key = key
        self.name = name
        self.content = content
        self.level = level

    def __repr__(self):
        return f"<DecompilationNote: {self.name}>"

    def __str__(self):
        return f"{self.name}: {self.content}"

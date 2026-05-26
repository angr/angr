from __future__ import annotations

import json
from enum import Enum
from typing import Any

from angr.protos import decompilation_cache_pb2
from angr.serializable import Serializable


class DecompilationNoteLevel(Enum):
    """
    Enum class describing the level of each decompilation note.
    """

    DEBUG = 0
    INFO = 1
    WARNING = 2
    CRITICAL = 3


class DecompilationNote(Serializable):
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

    @classmethod
    def _get_cmsg(cls):
        return decompilation_cache_pb2.DecompilationNote()

    def serialize_to_cmessage(self):
        # content is constrained at serialize time to values that round-trip through json.dumps / json.loads.
        try:
            content_json = json.dumps(self.content)
        except (TypeError, ValueError):
            content_json = json.dumps(None)
        return decompilation_cache_pb2.DecompilationNote(
            key=self.key,
            name=self.name,
            content_json=content_json,
            level=int(self.level.value),
        )

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        return cls(
            key=cmsg.key,
            name=cmsg.name,
            content=json.loads(cmsg.content_json) if cmsg.content_json else None,
            level=DecompilationNoteLevel(cmsg.level),
        )

from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Any

l = logging.getLogger(name=__name__)


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

    _subclasses: dict[str, type[DecompilationNote]] = {}

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

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        DecompilationNote._subclasses[cls.__name__] = cls

    def __repr__(self):
        return f"<DecompilationNote: {self.name}>"

    def __str__(self):
        return f"{self.name}: {self.content}"

    #
    # JSON serialization
    #

    def to_jsonable(self) -> dict[str, Any]:
        try:
            content = json.loads(json.dumps(self.content))
        except (TypeError, ValueError):
            l.warning("Failed to serialize content of decompilation note %s to JSON", self.key)
            content = None
        return {
            "class": type(self).__name__,
            "key": self.key,
            "name": self.name,
            "content": content,
            "level": int(self.level.value),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_jsonable())

    @classmethod
    def from_jsonable(cls, d: dict[str, Any]) -> DecompilationNote:
        klass = cls._subclasses.get(d.get("class", ""), DecompilationNote)
        return klass._from_jsonable_impl(d)  # pylint:disable=protected-access

    @classmethod
    def _from_jsonable_impl(cls, d: dict[str, Any]) -> DecompilationNote:
        return cls(
            key=d["key"],
            name=d["name"],
            content=d.get("content"),
            level=DecompilationNoteLevel(d.get("level", DecompilationNoteLevel.INFO.value)),
        )

    @classmethod
    def from_json(cls, s: str) -> DecompilationNote:
        return cls.from_jsonable(json.loads(s))

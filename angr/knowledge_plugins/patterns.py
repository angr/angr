"""User-authored fuzzy patterns, kept with the knowledge base so they outlive a session.

A stored pattern is a :class:`~angr.analyses.decompiler.known_patterns.KnownPattern`
plus how it is to be applied: whether it is switched on, and the similarity an
occurrence must reach before it is outlined. Patterns are keyed by name; call
names are unique too, since an outlined call is looked up by its target.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from .plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from angr.analyses.decompiler.known_patterns import KnownPattern
    from angr.knowledge_base import KnowledgeBase


@dataclass
class PatternStats:
    """What the outliner pass saw of one pattern in one function when it last ran there."""

    #: verified occurrences found before anything was outlined
    matches: int = 0
    #: occurrences outlined into calls
    outlined: int = 0
    #: the instruction address each outlined call carries, which is where it renders
    call_addrs: list[int] = field(default_factory=list)
    #: for each verified occurrence, the instruction addresses its statements carry
    match_addrs: list[frozenset[int]] = field(default_factory=list)


@dataclass
class StoredPattern:
    """One fuzzy pattern and its application settings."""

    pattern: KnownPattern
    enabled: bool = True
    #: an occurrence is outlined only at this similarity or above (see search.TemplateMatch)
    min_similarity: float = 0.8
    #: address of the function the pattern was lifted from, if any
    origin_func: int | None = None
    #: outline only occurrences that pass the pattern's structural match (constants,
    #: captures); off, similarity alone decides, as it does for discovered patterns
    require_verified: bool = True
    created_at: float = field(default_factory=time.time)

    @property
    def name(self) -> str:
        return self.pattern.name

    def to_dict(self) -> dict[str, Any]:
        # imported here: the knowledge base loads before the decompiler package does
        from angr.analyses.decompiler.known_patterns.serialize import (  # pylint:disable=import-outside-toplevel
            known_pattern_to_dict,
        )

        return {
            "pattern": known_pattern_to_dict(self.pattern),
            "enabled": self.enabled,
            "min_similarity": self.min_similarity,
            "origin_func": self.origin_func,
            "require_verified": self.require_verified,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StoredPattern:
        from angr.analyses.decompiler.known_patterns.serialize import (  # pylint:disable=import-outside-toplevel
            known_pattern_from_dict,
        )

        return cls(
            pattern=known_pattern_from_dict(data["pattern"]),
            enabled=bool(data.get("enabled", True)),
            min_similarity=float(data.get("min_similarity", 0.8)),
            origin_func=data.get("origin_func"),
            require_verified=bool(data.get("require_verified", True)),
            created_at=float(data.get("created_at", 0.0)),
        )


class Patterns(KnowledgeBasePlugin):
    """The fuzzy patterns of a knowledge base, by pattern name."""

    def __init__(self, kb: KnowledgeBase):
        super().__init__(kb)
        self._patterns: dict[str, StoredPattern] = {}
        # function address -> pattern name -> stats; runtime only, never persisted
        self._stats: dict[int, dict[str, PatternStats]] = {}

    def copy(self) -> Patterns:
        o = Patterns(self._kb)
        o._patterns = dict(self._patterns)
        o._stats = {
            addr: {
                name: replace(st, call_addrs=list(st.call_addrs), match_addrs=list(st.match_addrs))
                for name, st in per.items()
            }
            for addr, per in self._stats.items()
        }
        return o

    def record_stats(self, func_addr: int, stats: dict[str, PatternStats]) -> None:
        """Replace what is known about ``func_addr``: the outliner pass saw exactly these patterns."""
        self._stats[func_addr] = dict(stats)

    def stats(self, func_addr: int, name: str) -> PatternStats | None:
        """The outliner pass's numbers for a pattern in a function, or None if it did not
        search for that pattern there when it last ran."""
        return self._stats.get(func_addr, {}).get(name)

    def __len__(self) -> int:
        return len(self._patterns)

    def __iter__(self) -> Iterator[StoredPattern]:
        return iter(self._patterns.values())

    def __contains__(self, name: str) -> bool:
        return name in self._patterns

    def get(self, name: str) -> StoredPattern | None:
        return self._patterns.get(name)

    def add(
        self,
        pattern: KnownPattern,
        *,
        enabled: bool = True,
        min_similarity: float = 0.8,
        origin_func: int | None = None,
        require_verified: bool = True,
        replace: bool = False,
    ) -> StoredPattern:
        """Store ``pattern``. Refuses a name or call name already taken unless ``replace``."""
        if not replace:
            if pattern.name in self._patterns:
                raise ValueError(f"a fuzzy pattern named {pattern.name!r} already exists")
            clash = self.by_call_name(pattern.call_name)
            if clash is not None:
                raise ValueError(f"call name {pattern.call_name!r} is already used by pattern {clash.name!r}")
        stored = StoredPattern(
            pattern,
            enabled=enabled,
            min_similarity=min_similarity,
            origin_func=origin_func,
            require_verified=require_verified,
        )
        self._patterns[pattern.name] = stored
        return stored

    def store(self, stored: StoredPattern) -> None:
        """Put a StoredPattern back, keeping its settings (a loader's entry point)."""
        self._patterns[stored.name] = stored

    def remove(self, name: str) -> bool:
        for per in self._stats.values():
            per.pop(name, None)
        return self._patterns.pop(name, None) is not None

    def set_enabled(self, name: str, enabled: bool) -> None:
        self._patterns[name].enabled = enabled

    def enabled_patterns(self) -> list[StoredPattern]:
        return [p for p in self._patterns.values() if p.enabled]

    def by_call_name(self, call_name: str) -> StoredPattern | None:
        for stored in self._patterns.values():
            if stored.pattern.call_name == call_name:
                return stored
        return None

    def to_records(self) -> list[dict[str, Any]]:
        return [stored.to_dict() for stored in self._patterns.values()]

    def load_records(self, records: list[dict[str, Any]]) -> None:
        for record in records:
            self.store(StoredPattern.from_dict(record))


KnowledgeBasePlugin.register_default("patterns", Patterns)

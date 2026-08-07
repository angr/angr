from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Refresh:
    """
    What a caller has to redo after an edit.

    Lets a UI pick between re-rendering text, rebuilding the codegen AST, and a full
    re-decompilation instead of guessing. ``text_stale_all`` means every cached decompilation's
    rendered text is stale (a function rename changes call sites everywhere), but the caller should
    re-render lazily: eagerly re-rendering the whole cache would thrash its LRU.
    """

    text_stale: frozenset[int] = frozenset()
    text_stale_all: bool = False
    reanalyze: frozenset[int] = frozenset()
    redecompile: frozenset[int] = frozenset()
    function_list_dirty: bool = False
    disassembly_dirty: bool = False

    def merge(self, other: Refresh) -> Refresh:
        return Refresh(
            text_stale=self.text_stale | other.text_stale,
            text_stale_all=self.text_stale_all or other.text_stale_all,
            reanalyze=self.reanalyze | other.reanalyze,
            redecompile=self.redecompile | other.redecompile,
            function_list_dirty=self.function_list_dirty or other.function_list_dirty,
            disassembly_dirty=self.disassembly_dirty or other.disassembly_dirty,
        )


@dataclass
class EditResult:
    """The outcome of a single edit. ``changed`` is False when the edit was a no-op."""

    changed: bool
    kind: str
    func_addr: int | None = None
    old: Any = None
    new: Any = None
    refresh: Refresh = field(default_factory=Refresh)
    detail: dict[str, Any] = field(default_factory=dict)

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING

from .plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class CommentKind(IntEnum):
    """
    How a comment is displayed.

    ``PLAIN`` shows only at its own address. ``FUNCTION`` renders as a header block above the
    function, which is also what the decompiler does with a comment on a function entry.
    ``REPEATABLE`` additionally shows at every location referencing the commented address.
    """

    PLAIN = 0
    FUNCTION = 1
    REPEATABLE = 2

    @property
    def display_name(self) -> str:
        return _KIND_NAMES[self]


_KIND_NAMES = {
    CommentKind.PLAIN: "Plain",
    CommentKind.FUNCTION: "Function",
    CommentKind.REPEATABLE: "Repeatable",
}


class Comment:
    """
    A comment together with its display metadata. Rebuilt on demand from the knowledge base.
    """

    __slots__ = ("addr", "func_addr", "func_name", "kind", "text")

    def __init__(
        self, addr: int, text: str, kind: CommentKind, func_addr: int | None = None, func_name: str | None = None
    ) -> None:
        self.addr = addr
        self.text = text
        self.kind = kind
        self.func_addr = func_addr
        self.func_name = func_name

    @property
    def first_line(self) -> str:
        return self.text.split("\n", 1)[0]

    def __repr__(self) -> str:
        return f"<Comment {self.addr:#x} {self.kind.display_name}: {self.first_line!r}>"


class Comments(KnowledgeBasePlugin, dict):
    """
    Tracks comments via a Dict of Address -> Text, along with a per-address :class:`CommentKind`.
    """

    def __init__(self, kb) -> None:
        super().__init__(kb)
        self._kinds: dict[int, CommentKind] = {}
        self._repeatable_map: dict[int, list[tuple[int, str]]] | None = None

    def copy(self):
        o = Comments(self._kb)
        o.update(self)
        o._kinds = dict(self._kinds)
        return o

    #
    # Mutations. Any change invalidates the cached repeatable-comment map; removing a comment also
    # drops its kind.
    #

    def __setitem__(self, addr, text) -> None:
        dict.__setitem__(self, addr, text)
        self.invalidate()

    def __delitem__(self, addr) -> None:
        dict.__delitem__(self, addr)
        self._kinds.pop(addr, None)
        self.invalidate()

    def pop(self, addr, *default):
        result = dict.pop(self, addr, *default)
        self._kinds.pop(addr, None)
        self.invalidate()
        return result

    def update(self, *args, **kwargs) -> None:
        dict.update(self, *args, **kwargs)
        self.invalidate()

    def clear(self) -> None:
        dict.clear(self)
        self._kinds.clear()
        self.invalidate()

    #
    # Comment kinds
    #

    @property
    def kinds(self) -> dict[int, CommentKind]:
        """Explicitly-set comment kinds. Addresses not present here use :meth:`kind_of` defaults."""
        return self._kinds

    def kind_of(self, addr: int) -> CommentKind:
        kind = self._kinds.get(addr)
        if kind is not None:
            return kind
        return CommentKind.FUNCTION if self.is_function_entry(addr) else CommentKind.PLAIN

    def set_kind(self, addr: int, kind: CommentKind | None) -> None:
        """
        Set the display kind for the comment at ``addr``, or reset it to the default with None.
        """
        if kind is None or (kind == CommentKind.PLAIN and not self.is_function_entry(addr)):
            self._kinds.pop(addr, None)
        else:
            self._kinds[addr] = CommentKind(kind)
        self.invalidate()

    def is_function_entry(self, addr: int) -> bool:
        return self._kb is not None and addr in self._kb.functions

    def function_comment(self, func_addr: int) -> str | None:
        """The comment rendered as a function's header block, if any."""
        text = self.get(func_addr)
        if not text:
            return None
        return text if self.kind_of(func_addr) != CommentKind.PLAIN else None

    def inline_comment(self, addr: int) -> str | None:
        """
        The comment rendered next to the instruction at ``addr``. A comment that already renders as
        a function header block is not repeated inline.
        """
        text = self.get(addr)
        if not text:
            return None
        if self.kind_of(addr) != CommentKind.PLAIN and self.is_function_entry(addr):
            return None
        return text

    def iter_comments(self) -> Iterator[Comment]:
        """All comments in address order, with their kinds and owning functions."""
        kb = self._kb
        for addr in sorted(self):
            text = self[addr]
            if not text:
                continue
            func = kb.functions.floor_func(addr) if kb is not None else None
            if func is not None and not (func.addr <= addr < func.addr + max(func.size, 1)):
                func = None
            yield Comment(
                addr,
                text,
                self.kind_of(addr),
                func_addr=None if func is None else func.addr,
                func_name=None if func is None else func.name,
            )

    #
    # Repeatable comments
    #

    def repeatable_comments_at(self, ins_addr: int) -> list[tuple[int, str]]:
        """
        Repeatable comments that should show at ``ins_addr`` because it references their address.
        """
        if self._repeatable_map is None:
            self._repeatable_map = self._build_repeatable_map()
        return self._repeatable_map.get(ins_addr, [])

    def invalidate(self) -> None:
        """Drop the cached repeatable-comment map, e.g. after xrefs or functions change."""
        self._repeatable_map = None

    def _build_repeatable_map(self) -> dict[int, list[tuple[int, str]]]:
        if self._kb is None:
            return {}
        mapping: dict[int, list[tuple[int, str]]] = {}
        for addr, kind in self._kinds.items():
            if kind != CommentKind.REPEATABLE:
                continue
            text = self.get(addr)
            if not text:
                continue
            for ins_addr in self._referencing_insns(addr):
                if ins_addr != addr:
                    mapping.setdefault(ins_addr, []).append((addr, text))
        return mapping

    def _referencing_insns(self, addr: int) -> set[int]:
        """Instruction addresses that reference ``addr``: data xrefs plus call sites."""
        kb = self._kb
        out: set[int] = set()
        for xref in kb.xrefs.get_xrefs_by_dst(addr):
            if xref.ins_addr is not None:
                out.add(xref.ins_addr)

        if addr not in kb.functions:
            return out

        callgraph = kb.functions.callgraph
        if addr not in callgraph:
            return out
        cfg = kb.cfgs.get_most_accurate()
        for caller_addr in callgraph.predecessors(addr):
            caller = kb.functions.get_by_addr(caller_addr)
            if caller is None:
                continue
            for site in caller.get_call_sites():
                if caller.get_call_target(site) != addr:
                    continue
                node = cfg.get_any_node(site) if cfg is not None else None
                if node is not None and node.instruction_addrs:
                    out.add(node.instruction_addrs[-1])
                else:
                    out.add(site)
        return out


KnowledgeBasePlugin.register_default("comments", Comments)

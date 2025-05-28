from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .statement import Statement


class Block:
    """
    Describes an AIL block.
    """

    __slots__ = (
        "_hash",
        "addr",
        "idx",
        "original_size",
        "statements",
    )

    def __init__(self, addr: int, original_size, statements=None, idx=None):
        self.addr = addr
        self.original_size = original_size
        self.statements: list[Statement] = [] if statements is None else statements
        self.idx = idx
        self._hash = None  # cached hash value

    def copy(self, statements=None):
        return Block(
            addr=self.addr,
            original_size=self.original_size,
            statements=self.statements[::] if statements is None else statements,
            idx=self.idx,
        )

    def __repr__(self):
        if self.idx is None:
            return f"<AILBlock {self.addr:#x} of {len(self.statements)} statements>"
        return f"<AILBlock {self.addr:#x}.{self.idx} of {len(self.statements)} statements>"

    def dbg_repr(self, indent=0):
        indent_str = " " * indent
        if self.idx is None:
            block_str = f"{indent_str}## Block {self.addr:x}\n"
        else:
            block_str = f"{indent_str}## Block {self.addr:x}.{self.idx}\n"
        stmts_str = "\n".join(
            [
                (f"{indent_str}{i:02d} | {getattr(stmt, 'ins_addr', 0):#x} | {stmt}")
                for i, stmt in enumerate(self.statements)
            ]
        )
        block_str += stmts_str + "\n"
        return block_str

    def __str__(self):
        return self.dbg_repr()

    def __eq__(self, other):
        return (
            type(other) is Block
            and self.addr == other.addr
            and self.statements == other.statements
            and self.idx == other.idx
        )

    def likes(self, other):
        return (
            type(other) is Block
            and len(self.statements) == len(other.statements)
            and all(s1.likes(s2) for s1, s2 in zip(self.statements, other.statements))
        )

    def clear_hash(self):
        self._hash = None

    def __hash__(self):
        # Changing statements does not change the hash of a block, which allows in-place statement editing
        if self._hash is None:
            self._hash = hash((Block, self.addr, self.idx))
        return self._hash

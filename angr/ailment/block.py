from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from .statement import Statement


class Block:
    """
    Describes an AIL block.
    """

    __slots__ = (
        "addr",
        "original_size",
        "statements",
        "idx",
    )

    def __init__(self, addr, original_size, statements=None, idx=None):
        self.addr = addr
        self.original_size = original_size
        self.statements: List["Statement"] = [] if statements is None else statements
        self.idx = idx

    def copy(self, statements=None):
        return Block(
            addr=self.addr,
            original_size=self.original_size,
            statements=self.statements[::] if statements is None else statements,
            idx=self.idx,
        )

    def __repr__(self):
        if self.idx is None:
            return "<AILBlock %#x of %d statements>" % (self.addr, len(self.statements))
        else:
            return "<AILBlock %#x.%d of %d statements>" % (self.addr, self.idx, len(self.statements))

    def __str__(self):
        if self.idx is None:
            block_str = "## Block %x\n" % self.addr
        else:
            block_str = "## Block %x.%d\n" % (self.addr, self.idx)
        stmts_str = "\n".join(
            [
                ("%02d | %s | " % (i, hex(getattr(stmt, "ins_addr", 0)))) + str(stmt)
                for i, stmt in enumerate(self.statements)
            ]
        )
        block_str += stmts_str
        return block_str

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

    def __hash__(self):
        # Changing statements does not change the hash of a block, which allows in-place statement editing
        return hash((Block, self.addr, self.idx))

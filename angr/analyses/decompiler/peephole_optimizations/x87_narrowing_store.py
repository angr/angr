from __future__ import annotations

from angr.ailment.block import Block
from angr.ailment.expression import Convert
from angr.ailment.statement import Store

from .base import PeepholeOptimizationStmtBase


class X87NarrowingStore(PeepholeOptimizationStmtBase):
    """
    Store(addr, x<80>, size=8) ==> Store(addr, Conv(80F->64F, x), size=8)

    VEX models the x87 registers as F64, so a long double loaded with ``fld m80`` stays 80 bits wide when it is
    propagated into an ``fstp m64``. The store narrows it to double (which may raise overflow/underflow).
    """

    __slots__ = ()

    NAME = "x87: narrow long double stored as double"
    stmt_classes = (Store,)

    def optimize(self, stmt: Store, stmt_idx: int, block: Block, **kwargs):
        data = stmt.data
        if data.bits != 80 or stmt.size != 8:
            return None
        narrowed = Convert(
            self.manager.next_atom(),
            80,
            64,
            False,
            data,
            from_type=Convert.TYPE_FP,
            to_type=Convert.TYPE_FP,
            **data.tags,
        )
        return Store(stmt.idx, stmt.addr, narrowed, stmt.size, stmt.endness, guard=stmt.guard, **stmt.tags)

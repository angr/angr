from __future__ import annotations

from angr.ailment.block import Block
from angr.ailment.expression import Reinterpret
from angr.ailment.statement import Store

from .base import PeepholeOptimizationStmtBase


class RemoveReinterpretsAtStores(PeepholeOptimizationStmtBase):
    """
    Drop the integer view that VEX puts between a floating-point register and memory: ``Store(Reinterpret(F->I, x))``
    stores the float itself (memory is untyped).
    """

    __slots__ = ()

    NAME = "Remove Reinterprets at stores"
    stmt_classes = (Store,)

    def optimize(self, stmt: Store, stmt_idx: int, block: Block, **kwargs):
        data = stmt.data
        if (
            isinstance(data, Reinterpret)
            and data.from_type == "F"
            and data.to_type == "I"
            and data.operand.bits == data.bits
        ):
            return Store(stmt.idx, stmt.addr, data.operand, stmt.size, stmt.endness, guard=stmt.guard, **stmt.tags)
        return None

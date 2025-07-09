# pylint:disable=arguments-differ
from __future__ import annotations

from angr.ailment.expression import Const, StackBaseOffset, VirtualVariable, Load, UnaryOp
from angr.ailment.statement import Call, Assignment, Store
from angr import SIM_LIBRARIES
from .base import PeepholeOptimizationStmtBase


class InlinedMemcpy(PeepholeOptimizationStmtBase):
    """
    Simplifies inlined data copying logic into calls to memcpy.
    """

    __slots__ = ()

    NAME = "Simplifying inlined strcpy"
    stmt_classes = (Assignment, Store)

    def optimize(self, stmt: Assignment | Store, stmt_idx: int | None = None, block=None, **kwargs):
        should_replace = False
        dst_offset, src_offset, store_size = None, None, None
        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and stmt.dst.size == 16
            and isinstance(stmt.src, Load)
        ):
            dst_offset = stmt.dst.stack_offset
            store_size = stmt.dst.size
            if (
                isinstance(stmt.src.addr, UnaryOp)
                and stmt.src.addr.op == "Reference"
                and isinstance(stmt.src.addr.operand, VirtualVariable)
            ):
                should_replace = True
                src_offset = stmt.src.addr.operand.stack_offset
            elif isinstance(stmt.src.addr, StackBaseOffset):
                should_replace = True
                src_offset = stmt.src.addr.offset

        if (
            isinstance(stmt, Store)
            and isinstance(stmt.addr, StackBaseOffset)
            and stmt.size == 16
            and isinstance(stmt.data, Load)
        ):
            dst_offset = stmt.addr.offset
            store_size = stmt.size
            if (
                isinstance(stmt.data.addr, UnaryOp)
                and stmt.data.addr.op == "Reference"
                and isinstance(stmt.data.addr.operand, VirtualVariable)
            ):
                should_replace = True
                src_offset = stmt.data.addr.operand.stack_offset
            elif isinstance(stmt.data.addr, StackBaseOffset):
                should_replace = True
                src_offset = stmt.data.addr.offset

        if should_replace:
            assert dst_offset is not None and src_offset is not None and store_size is not None
            # replace it with a call to memcpy
            assert self.project is not None
            return Call(
                stmt.idx,
                "memcpy",
                args=[
                    StackBaseOffset(None, self.project.arch.bits, dst_offset),
                    StackBaseOffset(None, self.project.arch.bits, src_offset),
                    Const(None, None, store_size, self.project.arch.bits),
                ],
                prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("memcpy"),
                **stmt.tags,
            )

        return None

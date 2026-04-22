# pylint:disable=no-self-use
from __future__ import annotations

from angr.ailment.expression import Call, Const, StackBaseOffset, VirtualVariable, Load, UnaryOp
from angr.ailment.statement import Assignment, Store, SideEffectStatement
from angr import SIM_LIBRARIES
from .optimization_pass import OptimizationPass, OptimizationPassStage


class InlinedMemcpySimplifier(OptimizationPass):
    """
    Simplifies inlined data copying logic into calls to memcpy.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined memcpy"
    DESCRIPTION = "Simplify inlined memcpy patterns into memcpy calls"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            new_statements = []
            changed = False
            for stmt in block.statements:
                replacement = self._optimize_stmt(stmt)
                if replacement is not None:
                    new_statements.append(replacement)
                    changed = True
                else:
                    new_statements.append(stmt)
            if changed:
                new_block = block.copy(statements=new_statements)
                self._update_block(block, new_block)

    def _optimize_stmt(self, stmt):
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
                and stmt.src.addr.operand.was_stack
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
            return SideEffectStatement(
                stmt.idx,
                Call(
                    stmt.idx,
                    "memcpy",
                    calling_convention=None,
                    args=[
                        StackBaseOffset(self.manager.next_atom(), self.project.arch.bits, dst_offset),
                        StackBaseOffset(self.manager.next_atom(), self.project.arch.bits, src_offset),
                        Const(self.manager.next_atom(), None, store_size, self.project.arch.bits),
                    ],
                    prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("memcpy", arch=self.project.arch),
                    bits=None,
                    **stmt.tags,
                ),
                ret_expr=None,
                fp_ret_expr=None,
                **stmt.tags,
            )

        return None


class InlinedMemcpySimplifierLate(InlinedMemcpySimplifier):
    """
    Same as InlinedMemcpySimplifier but runs after SSA level 1 transformation.
    """

    STAGE = OptimizationPassStage.AFTER_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined memcpy (late)"

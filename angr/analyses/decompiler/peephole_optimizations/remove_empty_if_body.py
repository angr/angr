from __future__ import annotations

from angr.ailment.expression import ITE, UnaryOp
from angr.ailment.statement import ConditionalJump

from .base import PeepholeOptimizationStmtBase


class RemoveEmptyIfBody(PeepholeOptimizationStmtBase):
    __slots__ = ()

    NAME = "Remove empty If bodies"
    stmt_classes = (ConditionalJump,)

    def optimize(self, stmt: ConditionalJump, stmt_idx: int | None = None, block=None, **kwargs):
        cond_in = stmt.condition
        true_target_in = stmt.true_target
        false_target_in = stmt.false_target
        cond = cond_in

        # if (!cond) {} else { ITE(cond, true_branch, false_branch } ==> if (cond) { ITE(...) } else {}
        if isinstance(false_target_in, ITE) and isinstance(cond, UnaryOp) and cond.op == "Not":
            new_true_target = false_target_in
            new_true_idx = stmt.false_target_idx
            new_false_target = true_target_in
            new_false_idx = stmt.true_target_idx
            cond = cond.operand
        else:
            new_true_target = true_target_in
            new_true_idx = stmt.true_target_idx
            new_false_target = false_target_in
            new_false_idx = stmt.false_target_idx

        if cond != cond_in or new_true_target != true_target_in or new_false_target != false_target_in:
            # it's updated
            return ConditionalJump(
                stmt.idx,
                cond,
                new_true_target,
                new_false_target,
                true_target_idx=new_true_idx,
                false_target_idx=new_false_idx,
                **stmt.tags,
            )

        return None

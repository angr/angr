from __future__ import annotations
from ailment.statement import ConditionalJump
from ailment.expression import ITE, UnaryOp

from .base import PeepholeOptimizationStmtBase


class RemoveEmptyIfBody(PeepholeOptimizationStmtBase):
    __slots__ = ()

    NAME = "Remove empty If bodies"
    stmt_classes = (ConditionalJump,)

    def optimize(self, stmt: ConditionalJump, stmt_idx: int | None = None, block=None, **kwargs):
        cond = stmt.condition

        # if (!cond) {} else { ITE(cond, true_branch, false_branch } ==> if (cond) { ITE(...) } else {}
        if isinstance(stmt.false_target, ITE) and isinstance(cond, UnaryOp) and cond.op == "Not":
            new_true_target = stmt.false_target
            new_true_idx = stmt.false_target_idx
            new_false_target = stmt.true_target
            new_false_idx = stmt.true_target_idx
            cond = cond.operand
        else:
            new_true_target = stmt.true_target
            new_true_idx = stmt.true_target_idx
            new_false_target = stmt.false_target
            new_false_idx = stmt.false_target_idx

        if (
            cond is not stmt.condition
            or new_true_target is not stmt.true_target
            or new_false_target is not stmt.false_target
        ):
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

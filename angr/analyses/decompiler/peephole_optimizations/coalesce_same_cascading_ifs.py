from __future__ import annotations

from angr.ailment.expression import ITE
from angr.ailment.statement import ConditionalJump

from .base import PeepholeOptimizationStmtBase


class CoalesceSameCascadingIfs(PeepholeOptimizationStmtBase):
    __slots__ = ()

    NAME = "Coalescing cascading If constructs"
    stmt_classes = (ConditionalJump,)

    def optimize(self, stmt: ConditionalJump, stmt_idx: int | None = None, block=None, **kwargs):
        cond = stmt.condition
        true_target_in = stmt.true_target

        # if (cond) {ITE(cond, true_branch, false_branch)} else {} ==> if (cond) {true_branch} else {}
        if isinstance(true_target_in, ITE) and cond == true_target_in.cond:
            new_true_target = true_target_in.iftrue
        else:
            new_true_target = true_target_in

        if new_true_target != true_target_in:
            # it's updated
            return ConditionalJump(
                stmt.idx, cond, new_true_target, stmt.false_target, false_target_idx=stmt.false_target_idx, **stmt.tags
            )
        return None

from ailment.statement import ConditionalJump
from ailment.expression import ITE

from .base import PeepholeOptimizationStmtBase


class CoalesceSameCascadingIfs(PeepholeOptimizationStmtBase):
    __slots__ = ()

    NAME = "Coalescing cascading If constructs"
    stmt_classes = (ConditionalJump,)

    def optimize(self, stmt: ConditionalJump):
        cond = stmt.condition

        # if (cond) {ITE(cond, true_branch, false_branch)} else {} ==> if (cond) {true_branch} else {}
        if isinstance(stmt.true_target, ITE) and cond == stmt.true_target.cond:
            new_true_target = stmt.true_target.iftrue
        else:
            new_true_target = stmt.true_target

        if cond is not stmt.condition or new_true_target is not stmt.true_target:
            # it's updated
            return ConditionalJump(stmt.idx, cond, new_true_target, stmt.false_target, **stmt.tags)
        return None

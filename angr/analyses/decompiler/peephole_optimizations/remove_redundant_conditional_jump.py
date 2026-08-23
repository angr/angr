from angr.ailment.statement import ConditionalJump, Jump

from .base import PeepholeOptimizationStmtBase


class RemoveRedunCondJump(PeepholeOptimizationStmtBase):
    __slots__ = ()

    NAME = "Convert conditional jump with same targets to normal jump"
    stmt_classes = (ConditionalJump,)

    def optimize(self, stmt: ConditionalJump, stmt_idx: int = None, block=None, **kwargs):

        if stmt.false_target is None or stmt.true_target is None:
            return None

        if stmt.false_target.likes(stmt.true_target):
            return Jump(None, stmt.true_target, stmt.true_target_idx, **stmt.tags)

        return None

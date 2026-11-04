from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.statement import ConditionalJump, Jump, SideEffectStatement
from angr.utils.ail import has_call

from .base import PeepholeOptimizationMultiStmtBase, PeepholeOptimizationStmtBase


def _same_targets(stmt: ConditionalJump) -> bool:
    # two copies of one block (e.g. duplicated returns) share an address and differ in idx
    return (
        stmt.false_target is not None
        and stmt.true_target is not None
        and stmt.false_target.likes(stmt.true_target)
        and (stmt.true_target_idx or None) == (stmt.false_target_idx or None)
    )


class _OuterCalls(AILBlockViewer):
    """The calls in an expression that are not arguments of another call, in walk order."""

    def __init__(self):
        super().__init__()
        self.calls = []

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.calls.append(expr)


class RemoveRedunCondJump(PeepholeOptimizationStmtBase):
    __slots__ = ()

    NAME = "Convert conditional jump with same targets to normal jump"
    stmt_classes = (ConditionalJump,)

    def optimize(self, stmt: ConditionalJump, stmt_idx: int = None, block=None, **kwargs):
        # a condition that calls is handled by RemoveRedunCondJumpKeepCalls
        if _same_targets(stmt) and not has_call(stmt.condition):
            return Jump(None, stmt.true_target, stmt.true_target_idx, **stmt.tags)

        return None


class RemoveRedunCondJumpKeepCalls(PeepholeOptimizationMultiStmtBase):
    """
    if (f() == 0) goto X; else goto X;  =>  f(); goto X;
    """

    __slots__ = ()

    NAME = "Convert conditional jump with same targets and a call in its condition to calls and a jump"
    stmt_classes = ((ConditionalJump,),)

    def optimize(self, stmts, stmt_idx: int | None = None, block=None, **kwargs):
        stmt = stmts[0]
        if not _same_targets(stmt) or not has_call(stmt.condition):
            return None
        finder = _OuterCalls()
        finder.walk_expression(stmt.condition)
        if not finder.calls:
            return None
        new_stmts = [SideEffectStatement(self.manager.next_atom(), call, **call.tags) for call in finder.calls]
        return [*new_stmts, Jump(None, stmt.true_target, stmt.true_target_idx, **stmt.tags)]

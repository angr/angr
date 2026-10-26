from __future__ import annotations

from angr.ailment import AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.block_walker import AILBlockRewriter, _ExprHandled
from angr.ailment.expression import BinaryOp, Convert, Expression, Extract, UnaryOp, VEXCCallExpression
from angr.ailment.manager import Manager
from angr.ailment.statement import Statement
from angr.analyses.decompiler.x87_fsw import lower_cmpf_value

from .optimization_pass import OptimizationPassStage, SequenceOptimizationPass
from .peephole_simplifier import ExpressionSequenceWalker


class _CmpFFound(Exception):
    pass


class _CmpFFinder(AILBlockViewer):
    def _enter_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr, BinaryOp) and expr.op == "CmpF":
            raise _CmpFFound
        return super()._enter_expr(expr_idx, expr, stmt_idx, stmt, block)


_FINDER = _CmpFFinder()


def _has_cmpf_block(block: Block) -> bool:
    try:
        _FINDER.walk(block)
    except _CmpFFound:
        return True
    return False


def _has_cmpf_expr(expr: Expression) -> bool:
    try:
        _FINDER.walk_expression(expr)
    except _CmpFFound:
        return True
    return False


class _CmpFValueRewriter(AILBlockRewriter):
    """Replaces each maximal CmpF-valued integer expression with its exact IEEE C form."""

    def __init__(self, manager: Manager):
        super().__init__()
        self._manager = manager

    def _enter_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if isinstance(expr, VEXCCallExpression):
            # flag thunks are left to the ccall rewriters
            return _ExprHandled(expr)
        if (isinstance(expr, BinaryOp) and not (expr.floating_point and expr.op != "CmpF")) or isinstance(
            expr, (Convert, Extract, UnaryOp)
        ):
            lowered = lower_cmpf_value(expr, self._manager)
            if lowered is not None:
                return _ExprHandled(lowered)
        return super()._enter_expr(expr_idx, expr, stmt_idx, stmt, block)


class CmpFValueLowering(SequenceOptimizationPass):
    """
    Lowers CmpF results that survive as values (e.g., an x87 status word stored by fnstsw) into exact IEEE C. Runs after
    all predicate folding, so it only sees CmpF values that no flag test consumed.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Lower CmpF values"
    DESCRIPTION = (__doc__ or "").strip()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        walker = ExpressionSequenceWalker(handlers={Expression: self._lower_expr, Block: self._lower_block})
        walker.walk(self.seq)
        self.out_seq = self.seq

    def _lower_expr(self, expr: Expression, **_) -> Expression | None:
        if not _has_cmpf_expr(expr):
            return None
        new_expr = _CmpFValueRewriter(self.manager).walk_expression(expr)
        return new_expr if new_expr is not expr else None

    def _lower_block(self, block: Block, **_) -> Block | None:
        if not _has_cmpf_block(block):
            return None
        _CmpFValueRewriter(self.manager).walk(block)
        return None

from __future__ import annotations

from angr import ailment
from angr.analyses.decompiler.utils import (
    peephole_optimize_expr,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.peephole_optimizations import (
    PeepholeOptimizationExprBase,
    EXPR_OPTS,
)
from .optimization_pass import OptimizationPassStage, SequenceOptimizationPass


class ExpressionSequenceWalker(SequenceWalker):
    """
    Walks sequences with generic expression handling.
    """

    def _handle(self, node, **kwargs):
        if isinstance(node, ailment.Expr.Expression):
            handler = self._handlers.get(ailment.Expr.Expression, None)
            if handler:
                return handler(node, **kwargs)
        return super()._handle(node, **kwargs)


class PostStructuringPeepholeOptimizationPass(SequenceOptimizationPass):
    """
    Perform a post-structuring peephole optimization pass to simplify node statements and expressions.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Post-Structuring Peephole Optimization"
    DESCRIPTION = (__doc__ or "").strip()

    def __init__(self, func, peephole_optimizations=None, **kwargs):
        super().__init__(func, **kwargs)
        self._peephole_optimizations = peephole_optimizations
        self._expr_peephole_opts = [
            cls(self.project, self.kb, self._func.addr)
            for cls in (self._peephole_optimizations or EXPR_OPTS)
            if issubclass(cls, PeepholeOptimizationExprBase)
        ]
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        walker = ExpressionSequenceWalker(
            handlers={ailment.Expr.Expression: self._optimize_expr, ailment.Block: self._optimize_block}
        )
        walker.walk(self.seq)
        self.out_seq = self.seq

    def _optimize_expr(self, expr, **_):
        new_expr = peephole_optimize_expr(expr, self._expr_peephole_opts)
        return new_expr if expr != new_expr else None

    def _optimize_block(self, block, **_):
        old_block, new_block = None, block
        while old_block != new_block:
            old_block = new_block
            # Note: AILBlockSimplifier updates expressions in place
            simp = self.project.analyses.AILBlockSimplifier(
                new_block,
                func_addr=self._func.addr,
                peephole_optimizations=self._peephole_optimizations,
            )
            assert simp.result_block is not None
            new_block = simp.result_block
        return new_block if block != new_block else None

from __future__ import annotations

from angr import ailment
from angr.analyses.decompiler.peephole_optimizations import (
    EXPR_OPTS,
    LowerInsert,
    PeepholeOptimizationExprBase,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.utils import (
    peephole_optimize_expr,
    peephole_optimize_exprs,
    peephole_optimize_stmt_exprs,
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


class StatementExpressionSequenceWalker(ExpressionSequenceWalker):
    """
    Walks sequences with generic expression handling, also visiting bare statements - the loop initializers and
    iterators that SequenceWalker hands over as statements rather than blocks or expressions.
    """

    def _handle(self, node, **kwargs):
        if isinstance(node, ailment.Stmt.Statement):
            handler = self._handlers.get(ailment.Stmt.Statement, None)
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

    def __init__(self, *args, peephole_optimizations=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._peephole_optimizations = peephole_optimizations
        self._expr_peephole_opts = [
            cls(self.project, self.kb, ail_manager=self.manager, func_addr=self._func.addr)
            for cls in (self._peephole_optimizations or EXPR_OPTS)
            if issubclass(cls, PeepholeOptimizationExprBase)
        ]
        # lowering rules are not part of the regular rotation; see _lower_residual_inserts()
        self._lowering_opts = [LowerInsert(self.project, self.kb, ail_manager=self.manager, func_addr=self._func.addr)]
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        walker = ExpressionSequenceWalker(
            handlers={ailment.Expr.Expression: self._optimize_expr, ailment.Block: self._optimize_block}
        )
        walker.walk(self.seq)
        self._lower_residual_inserts()
        self.out_seq = self.seq

    def _lower_residual_inserts(self):
        """
        Lower whatever Inserts the optimizers above left behind into mask-and-or arithmetic.

        This runs as a separate final round on purpose. The optimizers in the regular rotation rewrite specific Insert
        shapes into much more readable expressions, and a general lowering rule would pre-empt all of them if it ran
        alongside. Anything still shaped as an Insert at this point has no such rewrite and would otherwise be emitted
        by the C backend as a call to the non-existent function `_INSERT`.
        """
        walker = StatementExpressionSequenceWalker(
            handlers={
                ailment.Expr.Expression: self._lower_expr,
                ailment.Stmt.Statement: self._lower_stmt,
                ailment.Block: self._lower_block,
            }
        )
        walker.walk(self.seq)

    def _lower_expr(self, expr, **_):
        new_expr = peephole_optimize_expr(expr, self._lowering_opts)
        return new_expr if expr is not new_expr else None

    def _lower_stmt(self, stmt, **_):
        new_stmt = peephole_optimize_stmt_exprs(stmt, self._lowering_opts)
        return new_stmt if stmt is not new_stmt else None

    def _lower_block(self, block, **_):
        # expressions are updated in place
        peephole_optimize_exprs(block, self._lowering_opts)
        return None

    def _optimize_expr(self, expr, **_):
        new_expr = peephole_optimize_expr(expr, self._expr_peephole_opts)
        return new_expr if expr is not new_expr else None

    def _optimize_block(self, block, **_):
        old_block, new_block = None, block
        while old_block != new_block:
            old_block = new_block
            # Note: AILBlockSimplifier updates expressions in place
            simp = self.project.analyses.AILBlockSimplifier(
                new_block,
                func_addr=self._func.addr,
                peephole_optimizations=self._peephole_optimizations,
                ail_manager=self.manager,
            )
            assert simp.result_block is not None
            new_block = simp.result_block
        return new_block if block != new_block else None

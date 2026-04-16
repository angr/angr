from __future__ import annotations
import logging

from angr.ailment.statement import SideEffectStatement, Assignment

from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class CallStatementRewriter(OptimizationPass):
    """
    Rewrite call statements to assignments if needed.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_MAKING_CALLSITES
    NAME = "Unify call statements on demand."
    DESCRIPTION = __doc__.strip()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        changed = False

        for block in self._graph.nodes:
            for idx in range(len(block.statements)):  # pylint:disable=consider-using-enumerate
                stmt = block.statements[idx]
                if isinstance(stmt, SideEffectStatement) and stmt.ret_expr is not None and stmt.fp_ret_expr is None:
                    src = stmt.expr.copy()
                    new_stmt = Assignment(stmt.idx, stmt.ret_expr, src, **stmt.tags)
                    block.statements[idx] = new_stmt
                    changed = True

        if changed:
            self.out_graph = self._graph

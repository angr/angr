from __future__ import annotations
import logging

from angr import ailment
from angr.ailment.block_walker import AILBlockViewer

from .engine_base import SimplifierAILEngine, SimplifierAILState
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class ITESimplifierAILEngine(SimplifierAILEngine):
    def _handle_expr_ITE(self, expr):
        if isinstance(expr.cond, ailment.expression.Const):
            return self._expr(expr.iftrue) if expr.cond.value else self._expr(expr.iffalse)

        return super()._handle_expr_ITE(expr)


class ITESimplifier(OptimizationPass):
    """
    Simplify ITE expressions with constant condition.
    """

    ARCHES = [
        "X86",
        "AMD64",
        "ARMCortexM",
        "ARMHF",
        "ARMEL",
    ]
    PLATFORMS = ["linux", "windows"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify optimized ite forms"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, *args, **kwargs):
        super().__init__(func, *args, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self.engine = ITESimplifierAILEngine(self.project)

        self.analyze()

    def _check(self):
        if self._graph is not None:
            for block in self._graph.nodes():
                viewer = AILBlockViewer()
                found = [False]
                orig_handler = viewer._handle_ITE

                def check_ite(expr_idx, expr, *args, _orig=orig_handler, _found=found, **kwargs):
                    if isinstance(expr.cond, ailment.expression.Const):
                        _found[0] = True
                    return _orig(expr_idx, expr, *args, **kwargs)

                viewer.expr_handlers[ailment.expression.ITE] = check_ite
                viewer.walk(block)
                if found[0]:
                    return True, None
        return False, None

    def _analyze(self, cache=None):
        assert self._graph is not None
        for block in list(self._graph.nodes()):
            new_block = block
            old_block = None

            while new_block != old_block:
                old_block = new_block
                new_block = self.engine.process(state=self.state.copy(), block=old_block.copy())
                _l.debug("new block: %s", new_block.statements)

            self._update_block(block, new_block)

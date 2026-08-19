from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.ailment import AILBlockRewriter
from angr.ailment.constant import UNDETERMINED_SIZE
from angr.ailment.expression import Const, Expression, Load

from .optimization_pass import OptimizationPass, OptimizationPassStage

if TYPE_CHECKING:
    from angr.ailment import Block
    from angr.ailment.statement import Statement
    from angr.project import Project

_l = logging.getLogger(name=__name__)


class LoadSizeRewriter(AILBlockRewriter):
    """
    Rewrite Load expressions whose sizes are undetermined into loads of the strings they point to.
    """

    def __init__(self, project: Project):
        super().__init__()
        self._project = project
        self.changed = False

    def _handle_Load(  # pylint:disable=arguments-differ
        self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        if expr.size == UNDETERMINED_SIZE and isinstance(expr.addr, Const) and isinstance(expr.addr.value, int):
            # probably a string!
            bs = self._project.loader.memory.load_null_terminated_bytes(expr.addr.value, max_size=4096)
            if bs:
                self.changed = True
                return Load(expr.idx, expr.addr, len(bs), expr.endness, guard=expr.guard, alt=expr.alt, **expr.tags)
        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)


class DetermineLoadSizes(OptimizationPass):
    """
    Determine the sizes of Load expressions whose sizes are undetermined.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Determine sizes of loads whose sizes are undetermined"
    DESCRIPTION = __doc__.strip()  # type: ignore

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        rewriter = LoadSizeRewriter(self.project)
        for block in self._graph.nodes:
            rewriter.walk(block)

        if rewriter.changed:
            self.out_graph = self._graph

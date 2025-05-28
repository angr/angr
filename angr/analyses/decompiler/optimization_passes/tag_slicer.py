# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
import logging

from angr.ailment.statement import ConditionalJump, Jump, Label
from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


class TagSlicer(OptimizationPass):
    """
    Removes unmarked statements from the graph.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Remove unmarked statements from the graph."
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return True, {}

    def _analyze(self, cache=None):
        for n in self._graph.nodes():
            for i, s in enumerate(n.statements):
                if isinstance(s, (ConditionalJump, Jump, Label)):
                    continue
                if not s.tags.get("keep_in_slice", False):
                    n.statements[i] = None

        for n in self._graph.nodes():
            n.statements = [s for s in n.statements if s is not None]

        self.out_graph = self._graph

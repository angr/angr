from __future__ import annotations
import logging

from ailment.constant import UNDETERMINED_SIZE
from ailment.expression import BinaryOp, Load, Const
from ailment.statement import Assignment

from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


class DetermineLoadSizes(OptimizationPass):
    """
    TODO:
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_MAKING_CALLSITES
    NAME = "Determine sizes of loads whose sizes are undetermined"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):

        changed = False

        for block in self._graph.nodes:
            for idx in range(len(block.statements)):  # pylint:disable=consider-using-enumerate
                stmt = block.statements[idx]
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.src, BinaryOp)
                    and stmt.src.op == "Add"
                    and stmt.src.operands
                ):
                    for operand in stmt.src.operands:
                        if (
                            isinstance(operand, Load)
                            and isinstance(operand.addr, Const)
                            and operand.size == UNDETERMINED_SIZE
                        ):
                            # probably a string!
                            bs = self.project.loader.memory.load_null_terminated_bytes(
                                operand.addr.value, max_size=4096
                            )
                            if bs is not None:
                                operand.size = len(bs)
                                operand.bits = len(bs) * 8
                    changed = True

        if changed:
            self.out_graph = self._graph

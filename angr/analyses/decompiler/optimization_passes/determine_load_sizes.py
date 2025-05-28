from __future__ import annotations
import logging

from angr.ailment.constant import UNDETERMINED_SIZE
from angr.ailment.expression import BinaryOp, Load, Const
from angr.ailment.statement import Assignment, WeakAssignment

from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


class DetermineLoadSizes(OptimizationPass):
    """
    Determine the sizes of Load expressions whose sizes are undetermined.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Determine sizes of loads whose sizes are undetermined"
    DESCRIPTION = __doc__.strip()  # type: ignore

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
                if isinstance(stmt, (Assignment, WeakAssignment)):
                    if isinstance(stmt.src, BinaryOp) and stmt.src.op == "Add" and stmt.src.operands:
                        operands = stmt.src.operands
                    elif isinstance(stmt.src, Load):
                        operands = [stmt.src]
                    else:
                        continue

                    for operand in operands:
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

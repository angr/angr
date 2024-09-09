from __future__ import annotations
import claripy

from . import SimConcretizationStrategy


class SimConcretizationStrategySignedAdd(SimConcretizationStrategy):
    """
    Concretization strategy that changes additions of big offsets to subtractions of small offsets.
    """

    def __init__(self, subtraction_limit=0x10000):
        super().__init__()
        self._subtraction_limit = subtraction_limit

    def _concretize(self, memory, addr, **kwargs):
        if addr.depth == 2 and addr.op == "__add__":
            if addr.args[0].singlevalued and addr.args[1].symbolic:
                # Swap variable and immediate
                addr.args = (addr.args[1], addr.args[0])
            if (
                addr.args[0].symbolic
                and addr.args[1].singlevalued
                # Check if negative argument
                and memory.state.solver.is_true(addr.args[1] >= 1 << (addr.args[1].size() - 1))
            ):
                new_arg = (1 << addr.args[1].size()) - memory.state.solver.eval(addr.args[1])
                if new_arg < self._subtraction_limit:
                    addr.op = "__sub__"
                    addr.args = (addr.args[0], claripy.BVV(new_arg, addr.args[1].size()))

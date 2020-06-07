from typing import Optional

from ..errors import SimSolverError
from . import SimConcretizationStrategy


class SimConcretizationStrategyMax(SimConcretizationStrategy):
    """
    Concretization strategy that returns the maximum address.
    """

    def __init__(self, max_addr: Optional[int]=None):
        super().__init__()
        self._max_addr = max_addr

    def _concretize(self, memory, addr):
        if self._max_addr is None:
            return [ self._max(memory, addr) ]
        else:
            try:
                return [ self._max(memory, addr, extra_constraints=(addr <= self._max_addr,)) ]
            except SimSolverError:
                return [ self._max(memory, addr) ]

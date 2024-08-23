from __future__ import annotations
from . import SimConcretizationStrategy


class SimConcretizationStrategySolutions(SimConcretizationStrategy):
    """
    Concretization strategy that resolves an address into some
    limited number of solutions.
    """

    def __init__(self, limit, **kwargs):
        super().__init__(**kwargs)
        self._limit = limit

    def _concretize(self, memory, addr, **kwargs):
        addrs = self._eval(memory, addr, self._limit + 1, **kwargs)
        if len(addrs) <= self._limit:
            return addrs
        return None

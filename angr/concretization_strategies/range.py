from __future__ import annotations
from . import SimConcretizationStrategy


class SimConcretizationStrategyRange(SimConcretizationStrategy):
    """
    Concretization strategy that resolves addresses to a range.
    """

    def __init__(self, limit, **kwargs):  # pylint:disable=redefined-builtin
        super().__init__(**kwargs)
        self._limit = limit

    def _concretize(self, memory, addr, **kwargs):
        mn, mx = self._range(memory, addr, **kwargs)
        if mx - mn <= self._limit:
            return self._eval(memory, addr, self._limit, **kwargs)
        return None

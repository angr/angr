from __future__ import annotations
from . import SimConcretizationStrategy


class SimConcretizationStrategyUnlimitedRange(SimConcretizationStrategy):
    """
    Concretization strategy that resolves addresses to a range without checking if the number of possible addresses is
    within the limit.
    """

    def __init__(self, limit, **kwargs):  # pylint:disable=redefined-builtin
        super().__init__(**kwargs)
        self._limit = limit

    def _concretize(self, memory, addr, **kwargs):
        return self._eval(memory, addr, self._limit, **kwargs)

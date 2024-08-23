from __future__ import annotations
from . import SimConcretizationStrategy
from ..errors import SimMergeError


class SimConcretizationStrategyNorepeatsRange(SimConcretizationStrategy):
    """
    Concretization strategy that resolves a range, with no repeats.
    """

    def __init__(self, repeat_expr, min=None, granularity=None, **kwargs):  # pylint:disable=redefined-builtin
        super().__init__(**kwargs)
        self._repeat_expr = repeat_expr
        self._repeat_min = min
        self._repeat_granularity = granularity

    def _concretize(self, memory, addr, **kwargs):
        child_constraints = (addr >= self._repeat_min, addr < self._repeat_min + self._repeat_granularity)
        extra_constraints = kwargs.pop("extra_constraints", None)
        if extra_constraints is not None:
            child_constraints += tuple(extra_constraints)
        c = self._any(memory, addr, extra_constraints=child_constraints)
        self._repeat_min = c + self._repeat_granularity
        return [c]

    def copy(self):
        return SimConcretizationStrategyNorepeatsRange(
            repeat_expr=self._repeat_expr, min=self._repeat_min, granularity=self._repeat_granularity, exact=self._exact
        )

    def merge(self, others):
        if not all(self._repeat_expr is o._repeat_expr for o in others):
            raise SimMergeError("Unable to merge two different repeat expressions.")

        self._repeat_min = max(self._repeat_min, max(o._repeat_min for o in others))
        self._repeat_granularity = max(self._repeat_granularity, max(o._repeat_granularity for o in others))

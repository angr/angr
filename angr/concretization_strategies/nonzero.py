from __future__ import annotations
from . import SimConcretizationStrategy


class SimConcretizationStrategyNonzero(SimConcretizationStrategy):
    """
    Concretization strategy that returns any non-zero solution.
    """

    def _concretize(self, memory, addr, **kwargs):
        child_constraints = (addr != 0,)
        extra_constraints = kwargs.pop("extra_constraints", None)
        if extra_constraints is not None:
            child_constraints += tuple(extra_constraints)
        return [self._any(memory, addr, extra_constraints=child_constraints, **kwargs)]

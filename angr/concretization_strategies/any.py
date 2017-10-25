from . import SimConcretizationStrategy

class SimConcretizationStrategyAny(SimConcretizationStrategy):
    """
    Concretization strategy that returns any single solution.
    """

    def _concretize(self, memory, addr, extra_constraints=()):
        if self._exact:
            return [ self._any(memory, addr, extra_constraints=extra_constraints) ]
        else:
            mn,mx = self._range(memory, addr, extra_constraints=extra_constraints)
            if mn == mx:
                return [ mn ]

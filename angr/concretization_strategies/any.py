from . import SimConcretizationStrategy


class SimConcretizationStrategyAny(SimConcretizationStrategy):
    """
    Concretization strategy that returns any single solution.
    """

    def _concretize(self, memory, addr, **kwargs):
        if self._exact:
            return [self._any(memory, addr, **kwargs)]
        else:
            mn, mx = self._range(memory, addr, **kwargs)
            if mn == mx:
                return [mn]

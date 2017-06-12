from . import SimConcretizationStrategy

class SimConcretizationStrategyAny(SimConcretizationStrategy):
    """
    Concretization strategy that returns any single solution.
    """

    def _concretize(self, memory, addr):
        if self._exact:
            return [ self._any(memory, addr) ]
        else:
            mn,mx = self._range(memory, addr)
            if mn == mx:
                return [ mn ]

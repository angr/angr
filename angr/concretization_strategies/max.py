from . import SimConcretizationStrategy

class SimConcretizationStrategyMax(SimConcretizationStrategy):
    """
    Concretization strategy that returns the maximum address.
    """

    def _concretize(self, memory, addr):
        return [ self._max(memory, addr) ]

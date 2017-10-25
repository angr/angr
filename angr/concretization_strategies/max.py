from . import SimConcretizationStrategy

class SimConcretizationStrategyMax(SimConcretizationStrategy):
    """
    Concretization strategy that returns the maximum address.
    """

    def _concretize(self, memory, addr, extra_constraints=()):
        return [ self._max(memory, addr, extra_constraints=extra_constraints) ]

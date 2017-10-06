from . import SimConcretizationStrategy

class SimConcretizationStrategyNonzero(SimConcretizationStrategy):
    """
    Concretization strategy that returns any non-zero solution.
    """

    def _concretize(self, memory, addr, extra_constraints=()):
        if not extra_constraints:
            extra_constraints = [ ]
        return [ self._any(memory, addr, extra_constraints=[addr != 0] + extra_constraints) ]

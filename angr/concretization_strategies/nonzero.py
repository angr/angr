from . import SimConcretizationStrategy

class SimConcretizationStrategyNonzero(SimConcretizationStrategy):
    """
    Concretization strategy that returns any non-zero solution.
    """

    def _concretize(self, memory, addr, extra_constraints=None, **kwargs):
        child_constraints = (addr != 0,)
        if extra_constraints is not None:
            child_constraints += tuple(extra_constraints)
        return [ self._any(memory, addr, extra_constraints=child_constraints, **kwargs) ]

from . import SimConcretizationStrategy

class SimConcretizationStrategyNonzeroRange(SimConcretizationStrategy):
    """
    Concretization strategy that resolves a range in a non-zero location.
    """

    def __init__(self, limit, **kwargs):
        super(SimConcretizationStrategyNonzeroRange, self).__init__(**kwargs)
        self._limit = limit

    def _concretize(self, memory, addr, extra_constraints=None, **kwargs):
        mn,mx = self._range(memory, addr, extra_constraints=extra_constraints, **kwargs)
        if mx - mn <= self._limit:
            child_constaints = (addr != 0,)
            if extra_constraints is not None:
                child_constaints += tuple(extra_constraints)
            return self._eval(memory, addr, self._limit, extra_constraints=child_constaints, **kwargs)
        return None

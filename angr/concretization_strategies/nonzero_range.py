from . import SimConcretizationStrategy

class SimConcretizationStrategyNonzeroRange(SimConcretizationStrategy):
    """
    Concretization strategy that resolves a range in a non-zero location.
    """

    def __init__(self, limit, **kwargs):
        super(SimConcretizationStrategyNonzeroRange, self).__init__(**kwargs)
        self._limit = limit

    def _concretize(self, memory, addr, extra_constraints=None):
        if extra_constraints is None:
            extra_constraints = [ ]
        mn,mx = self._range(memory, addr, extra_constraints=extra_constraints)
        if mx - mn <= self._limit:
            return self._eval(memory, addr, self._limit, extra_constraints=[addr != 0] + extra_constraints)

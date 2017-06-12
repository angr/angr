import itertools

from . import SimConcretizationStrategy

class SimConcretizationStrategyNorepeats(SimConcretizationStrategy):
    """
    Concretization strategy that resolves addresses, without repeating.
    """

    def __init__(self, repeat_expr, repeat_constraints=None, **kwargs):
        super(SimConcretizationStrategyNorepeats, self).__init__(**kwargs)
        self._repeat_constraints = [ ] if repeat_constraints is None else repeat_constraints
        self._repeat_expr = repeat_expr

    def _concretize(self, memory, addr):
        c = self._any(
            memory, addr,
            extra_constraints = self._repeat_constraints + [ addr == self._repeat_expr ]
        )
        self._repeat_constraints.append(self._repeat_expr != c)
        return [ c ]

    def copy(self):
        return SimConcretizationStrategyNorepeats(
            repeat_expr=self._repeat_expr,
            repeat_constraints=list(self._repeat_constraints),
            exact=self._exact
        )

    def merge(self, others):
        seen = set(s.cache_key for s in self._repeat_constraints)
        for c in itertools.chain.from_iterable(o._repeat_constraints for o in others):
            if c.cache_key not in seen:
                seen.add(c.cache_key)
                self._repeat_constraints.append(c)

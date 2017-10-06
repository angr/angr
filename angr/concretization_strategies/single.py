from . import SimConcretizationStrategy

class SimConcretizationStrategySingle(SimConcretizationStrategy):
    """
    Concretization strategy that ensures a single solution for an address.
    """

    def _concretize(self, memory, addr, extra_constraints=()):
        addrs = self._eval(memory, addr, 2, extra_constraints=extra_constraints)
        if len(addrs) == 1:
            return addrs

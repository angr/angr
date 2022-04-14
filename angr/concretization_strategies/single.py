from . import SimConcretizationStrategy

class SimConcretizationStrategySingle(SimConcretizationStrategy):
    """
    Concretization strategy that ensures a single solution for an address.
    """

    def _concretize(self, memory, addr, **kwargs):
        addrs = self._eval(memory, addr, 2, **kwargs)
        if len(addrs) == 1:
            return addrs

from . import SimConcretizationStrategy

class SimConcretizationStrategySingle(SimConcretizationStrategy):
    """
    Concretization strategy that ensures a single solution for an address.
    """

    def _concretize(self, memory, addr):
        addrs = self._eval(memory, addr, 2)
        if len(addrs) == 0:
            return addrs

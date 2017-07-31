from . import SimConcretizationStrategy

class SimConcretizationStrategySolutions(SimConcretizationStrategy):
    """
    Concretization strategy that resolves an address into some
    limited number of solutions.
    """

    def __init__(self, limit, **kwargs):
        super(SimConcretizationStrategySolutions, self).__init__(**kwargs)
        self._limit = limit

    def _concretize(self, memory, addr):
        addrs = self._eval(memory, addr, self._limit + 1)
        if len(addrs) <= self._limit:
            return addrs

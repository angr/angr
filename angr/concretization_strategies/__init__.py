import claripy


class SimConcretizationStrategy:
    """
    Concretization strategies control the resolution of symbolic memory indices
    in SimuVEX. By subclassing this class and setting it as a concretization strategy
    (on state.memory.read_strategies and state.memory.write_strategies), SimuVEX's
    memory index concretization behavior can be modified.
    """

    def __init__(self, filter=None, exact=True): #pylint:disable=redefined-builtin
        """
        Initializes the base SimConcretizationStrategy.

        :param filter: A function, taking arguments of (SimMemory, claripy.AST) that determins
                       if this strategy can handle resolving the provided AST.
        :param exact: A flag (default: True) that determines if the convenience resolution
                      functions provided by this class use exact or approximate resolution.
        """
        self._exact = exact
        self._filter = filter

    def _min(self, memory, addr, **kwargs):
        """
        Gets the minimum solution of an address.
        """
        return memory.state.solver.min(addr, exact=kwargs.pop('exact', self._exact), **kwargs)

    def _max(self, memory, addr, **kwargs):
        """
        Gets the maximum solution of an address.
        """
        return memory.state.solver.max(addr, exact=kwargs.pop('exact', self._exact), **kwargs)

    def _any(self, memory, addr, **kwargs):
        """
        Gets any solution of an address.
        """
        return memory.state.solver.eval(addr, exact=kwargs.pop('exact', self._exact), **kwargs)

    def _eval(self, memory, addr, n, **kwargs):
        """
        Gets n solutions for an address.
        """
        if isinstance(addr, claripy.vsa.StridedInterval):
            return addr.eval(n)
        return memory.state.solver.eval_upto(addr, n, exact=kwargs.pop('exact', self._exact), **kwargs)

    def _range(self, memory, addr, **kwargs):
        """
        Gets the (min, max) range of solutions for an address.
        """
        return (self._min(memory, addr, **kwargs), self._max(memory, addr, **kwargs))

    def concretize(self, memory, addr, **kwargs):
        """
        Concretizes the address into a list of values.
        If this strategy cannot handle this address, returns None.
        """
        if self._filter is None or self._filter(memory, addr):
            return self._concretize(memory, addr, **kwargs)

    def _concretize(self, memory, addr, **kwargs):
        """
        Should be implemented by child classes to handle concretization.
        :param **kwargs:
        """
        raise NotImplementedError()

    def copy(self):
        """
        Returns a copy of the strategy, if there is data that should be kept separate between
        states. If not, returns self.
        """
        return self

    def merge(self, others):
        """
        Merges this strategy with others (if there is data that should be kept separate between
        states. If not, is a no-op.
        """
        pass

from .any import SimConcretizationStrategyAny
from .controlled_data import SimConcretizationStrategyControlledData
from .eval import SimConcretizationStrategyEval
from .max import SimConcretizationStrategyMax
from .nonzero import SimConcretizationStrategyNonzero
from .nonzero_range import SimConcretizationStrategyNonzeroRange
from .norepeats import SimConcretizationStrategyNorepeats
from .norepeats_range import SimConcretizationStrategyNorepeatsRange
from .range import SimConcretizationStrategyRange
from .single import SimConcretizationStrategySingle
from .solutions import SimConcretizationStrategySolutions
from .unlimited_range import SimConcretizationStrategyUnlimitedRange

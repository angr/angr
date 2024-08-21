from ..errors import SimSolverError
from . import SimConcretizationStrategy


class SimConcretizationStrategyMax(SimConcretizationStrategy):
    """
    Concretization strategy that returns the maximum address.
    """

    def __init__(self, max_addr: int | None = None):
        super().__init__()
        self._max_addr = max_addr

    def _concretize(self, memory, addr, **kwargs):
        extra_constraints = kwargs.pop("extra_constraints", None)
        extra_constraints = tuple(extra_constraints) if extra_constraints is not None else ()
        if self._max_addr is None:
            return [self._max(memory, addr, extra_constraints=extra_constraints, **kwargs)]
        else:
            try:
                child_constraints = (addr <= self._max_addr,) + extra_constraints
                return [self._max(memory, addr, extra_constraints=child_constraints)]
            except SimSolverError:
                return [self._max(memory, addr, extra_constraints=extra_constraints, **kwargs)]

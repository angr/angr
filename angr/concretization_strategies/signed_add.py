from . import SimConcretizationStrategy


class SimConcretizationStrategySignedAdd(SimConcretizationStrategy):
    """
    Concretization strategy that changes additions of big offsets to substractions of small offsets.
    """

    def __init__(self, substraction_limit=0x10000):
        super().__init__()
        self._substraction_limit = substraction_limit

    def _concretize(self, memory, addr, **kwargs):
        if addr.depth == 2 and addr.op == "__add__":
            if addr.args[0].singlevalued and addr.args[1].symbolic:
                # Swap variable and immediate
                addr.args = (addr.args[1], addr.args[0])
            if addr.args[0].symbolic and addr.args[1].singlevalued:
                # Check if negative argument
                if memory.state.solver.is_true(addr.args[1] >= 1 << (addr.args[1].size() - 1)):
                    new_arg = (1 << addr.args[1].size()) - memory.state.solver.eval(addr.args[1])
                    if new_arg < self._substraction_limit:
                        addr.op = "__sub__"
                        addr.args = (addr.args[0], memory.state.solver.BVV(new_arg, addr.args[1].size()))

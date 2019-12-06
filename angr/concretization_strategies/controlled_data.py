from itertools import groupby

from . import SimConcretizationStrategy

class SimConcretizationStrategyControlledData(SimConcretizationStrategy):
    """
    Concretization strategy that constraints the address to controlled data.
    Controlled data consists of symbolic data and the addresses given as arguments.
    memory.
    """
    def __init__(self, limit, fixed_addrs, **kwargs):
        super(SimConcretizationStrategyControlledData, self).__init__(**kwargs)
        self._limit = limit
        self._fixed_addrs = fixed_addrs

    def _concretize(self, memory, addr):
        # Get all symbolic variables in memory
        symbolic_vars = filter(lambda key: not key.startswith("reg_") and not key.startswith("mem_"), memory.mem._name_mapping.keys())
        controlled_addrs = sorted([_addr for s_var in symbolic_vars for _addr in memory.addrs_for_name(s_var)])
        controlled_addrs.extend(self._fixed_addrs)

        # Represent controlled addresses in adjacent memory areas as "base+offset"
        base_length_array = [(controlled_addrs[0], 0)]
        for i in range(1, len(controlled_addrs)):
            if controlled_addrs[i - 1] + 1 == controlled_addrs[i]:
                base = base_length_array[i-1][0]
            else:
                base = controlled_addrs[i]

            base_length_array.append((base, controlled_addrs[i] - base))

        # create intervals from memory areas
        intervals = [(t[0], len(list(t[1]))) for t in groupby(base_length_array, key=lambda t: t[0])]

        constraints = []

        # create constraints from intervals
        for base, length in intervals:
           constraints.append(memory.state.solver.And(addr >= base, addr < base+length))

        # try to get solutions for controlled memory
        ored_constraints = memory.state.solver.Or(*constraints)
        solutions = self._eval(memory, addr, self._limit, extra_constraints=(ored_constraints,))
        if not solutions:
            solutions = None
        return solutions

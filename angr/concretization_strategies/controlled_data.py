from __future__ import annotations
from itertools import groupby

import claripy

from . import SimConcretizationStrategy


class SimConcretizationStrategyControlledData(SimConcretizationStrategy):
    """
    Concretization strategy that constraints the address to controlled data.
    Controlled data consists of symbolic data and the addresses given as arguments.
    memory.
    """

    def __init__(self, limit, fixed_addrs, **kwargs):
        super().__init__(**kwargs)
        self._limit = limit
        self._fixed_addrs = fixed_addrs

    def _concretize(self, memory, addr, **kwargs):
        # Get all symbolic variables in memory
        symbolic_vars = filter(
            lambda key: not key.startswith("reg_") and not key.startswith("mem_"), memory._name_mapping.keys()
        )
        controlled_addrs = sorted([_addr for s_var in symbolic_vars for _addr in memory.addrs_for_name(s_var)])
        controlled_addrs.extend(self._fixed_addrs)

        # Represent controlled addresses in adjacent memory areas as "base+offset"
        base_length_array = [(controlled_addrs[0], 0)]
        for i in range(1, len(controlled_addrs)):
            if controlled_addrs[i - 1] + 1 == controlled_addrs[i]:
                base = base_length_array[i - 1][0]
            else:
                base = controlled_addrs[i]

            base_length_array.append((base, controlled_addrs[i] - base))

        # create intervals from memory areas
        intervals = [(t[0], len(list(t[1]))) for t in groupby(base_length_array, key=lambda t: t[0])]

        constraints = []

        # create constraints from intervals
        for base, length in intervals:
            constraints.append(claripy.And(addr >= base, addr < base + length))

        # try to get solutions for controlled memory
        ored_constraints = claripy.Or(*constraints)
        child_constraints = (ored_constraints,)
        extra_constraints = kwargs.pop("extra_constraints", None)
        if extra_constraints is not None:
            child_constraints += tuple(extra_constraints)
        solutions = self._eval(memory, addr, self._limit, extra_constraints=child_constraints, **kwargs)
        if not solutions:
            solutions = None
        return solutions

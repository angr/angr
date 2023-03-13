from . import SimConcretizationStrategy


class SimConcretizationStrategyAnyNamed(SimConcretizationStrategy):
    """
    Concretization strategy that returns any single solution and creates a BVS at the resulting address.
    """

    def __init__(self):
        super().__init__()

    def _concretize(self, memory, addr, **kwargs):
        mn, mx = self._range(memory, addr, **kwargs)
        if mn == mx:
            # Check if a variable already exists
            for _, values in memory._name_mapping.items():
                if mn in values:
                    return [mn]
        # Get any solution
        child_constraints = (addr > 0x1000, addr < (1 << memory.state.arch.bits) - 0x10000, addr % 8 == 0)
        extra_constraints = kwargs.pop("extra_constraints", None)
        if extra_constraints is not None:
            child_constraints += tuple(extra_constraints)
        target = self._any(memory, addr, extra_constraints=child_constraints, **kwargs)
        # Create new BVS
        old_name = " ".join(repr(addr)[:-1].split(" ")[1:])
        new_BVS = memory.state.solver.BVS(f"[{old_name}]", memory.state.arch.bits, explicit_name=True)
        memory.store(target, new_BVS, endness=memory.state.arch.memory_endness)
        # Enforce the address
        memory.state.solver.add(addr == target)

        return [target]

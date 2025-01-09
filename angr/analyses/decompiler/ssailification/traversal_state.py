from __future__ import annotations


class TraversalState:
    """
    The abstract state for the traversal engine.
    """

    def __init__(
        self,
        arch,
        func,
        live_registers: set[int] | None = None,
        live_stackvars: set[tuple[int, int]] | None = None,
    ):
        self.arch = arch
        self.func = func

        self.live_registers: set[int] = set() if live_registers is None else live_registers
        self.live_stackvars: set[tuple[int, int]] = set() if live_stackvars is None else live_stackvars
        self.live_tmps: set[int] = set()  # tmps are internal to a block only and never propagated from another state

    def copy(self) -> TraversalState:
        return TraversalState(
            self.arch,
            self.func,
            live_registers=self.live_registers.copy(),
            live_stackvars=self.live_stackvars.copy(),
        )

    def merge(self, *others: TraversalState) -> bool:
        merge_occurred = False

        all_regs: set[int] = self.live_registers.copy()
        for o in others:
            if o.live_registers.difference(all_regs):
                merge_occurred = True
            all_regs |= o.live_registers

        all_stackvars: set[tuple[int, int]] = self.live_stackvars.copy()
        for o in others:
            if o.live_stackvars.difference(all_stackvars):
                merge_occurred = True
            all_stackvars |= o.live_stackvars

        self.live_registers = all_regs
        self.live_stackvars = all_stackvars
        return merge_occurred

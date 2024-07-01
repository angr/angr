from __future__ import annotations


class TraversalState:
    def __init__(
        self,
        arch,
        func,
        live_registers: set[int] | None = None,
    ):
        self.arch = arch
        self.func = func

        self.live_registers: set[int] = set() if live_registers is None else live_registers

    def copy(self) -> TraversalState:
        state = TraversalState(
            self.arch,
            self.func,
            live_registers=self.live_registers.copy(),
        )
        return state

    def merge(self, *others: TraversalState) -> bool:
        merge_occurred = False

        all_regs: set[int] = self.live_registers.copy()
        for o in others:
            if o.live_registers.difference(all_regs):
                merge_occurred = True
            all_regs |= o.live_registers

        self.live_registers = all_regs
        return merge_occurred

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.s_reaching_definitions import SRDAView
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType
from angr.utils.bits import u2s

if TYPE_CHECKING:
    from angr.analyses.s_reaching_definitions import SRDAModel


class StackArgOffsetManager:
    """
    A manager that keeps track of stack argument offsets and sizes for all call sites in a function. This manager
    also keeps track of the stack virtual variables that can be eliminated for each call site because they are stack
    arguments.

    `all_stackarg_vvars` and `stack_arg_to_vvars` map stack arguments to virtual variable IDs. You must call
    `update_stackoff_vvars()` to populate these two attributes after Stage 1 SSA rewriting. `is_stackarg_vvar()` is
    only valid after `update_stackoff_vvars()` is called.
    """

    def __init__(self, bits: int):
        self.bits = bits
        self.stack_arg_offsets: dict[int, set[tuple[tuple[int, int | None], int, int, int]]] = {}
        self.stack_arg_to_vvars: dict[int, set[int]] | None = None
        self.all_stackarg_vvars: set[int] | None = None

    def add_call_stack_arg_offset(
        self, block_addr: int, block_idx: int | None, ins_addr: int, stack_arg_offset: int, stack_arg_size: int
    ):
        stack_arg_offset = u2s(stack_arg_offset, self.bits)
        if stack_arg_offset not in self.stack_arg_offsets:
            self.stack_arg_offsets[stack_arg_offset] = set()
        self.stack_arg_offsets[stack_arg_offset].add(
            ((block_addr, block_idx), ins_addr, stack_arg_offset, stack_arg_size)
        )

    def merge(self, other: StackArgOffsetManager):
        for offset, records in other.stack_arg_offsets.items():
            if offset not in self.stack_arg_offsets:
                self.stack_arg_offsets[offset] = set()
            self.stack_arg_offsets[offset].update(records)

    def get_stackarg_offsets(self) -> set[int]:
        return set(self.stack_arg_offsets)

    def get_stackarg_insaddrs(self) -> set[int]:
        return {ins_addr for records in self.stack_arg_offsets.values() for (_, ins_addr, _, _) in records}

    def update_stackoff_vvars(self, rd: SRDAModel) -> None:
        stackoff_to_arg_vvars: dict[int, set[int]] = {}
        all_stackarg_vvars: set[int] = set()

        rd_view = SRDAView(rd)
        for off, items in self.stack_arg_offsets.items():
            if off not in stackoff_to_arg_vvars:
                stackoff_to_arg_vvars[off] = set()
            for (block_addr, block_idx), _, _, sz in items:
                stackarg_vvar = rd_view.get_stack_vvar_by_stmt(
                    off,
                    sz,
                    block_addr,
                    block_idx,
                    -1,
                    ObservationPointType.OP_BEFORE,
                )
                if stackarg_vvar is not None:
                    stackoff_to_arg_vvars[off].add(stackarg_vvar.varid)
                    all_stackarg_vvars.add(stackarg_vvar.varid)
        self.stackoff_to_vvars = stackoff_to_arg_vvars
        self.all_stackarg_vvars = all_stackarg_vvars

    def is_stackarg_vvar(self, vvar_id: int) -> bool:
        if self.all_stackarg_vvars is None:
            raise ValueError(
                "StackArgOffsetManager: all_stackarg_vvars is not populated. Call update_stackoff_vvars() first."
            )
        return vvar_id in self.all_stackarg_vvars

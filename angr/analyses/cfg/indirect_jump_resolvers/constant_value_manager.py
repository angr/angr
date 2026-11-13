from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from angr import claripy
from angr.analyses.propagator.vex_vars import VEXReg
from angr.code_location import CodeLocation

from .propagator_utils import PropagatorLoadCallback

if TYPE_CHECKING:
    from angr import SimState
    from angr.knowledge_plugins import Function
    from angr.project import Project


l = logging.getLogger(name=__name__)


class ConstantValueManager:
    """
    Manages the loading of registers who hold constant values.
    """

    __slots__ = (
        "_entry_regs",
        "func",
        "indirect_jump_addr",
        "kb",
        "mapping",
        "project",
    )

    def __init__(self, project: Project, kb, func: Function, ij_addr: int):
        self.project = project
        self.kb = kb
        self.func = func
        self.indirect_jump_addr = ij_addr

        self.mapping: dict[Any, dict[Any, claripy.ast.Base]] | None = None
        self._entry_regs: dict[int, claripy.ast.BV] = {}

    def entry_registers(self) -> dict[int, claripy.ast.BV]:
        """
        Get the constant values of registers on entry to the indirect jump's block, keyed by register offset. The
        instruction pointer is not included, and neither is a register that overlaps another known register.
        """
        if self.mapping is None:
            self._build_mapping()
        return self._entry_regs

    def reg_read_callback(self, state: SimState):
        if self.mapping is None:
            self._build_mapping()
            assert self.mapping is not None

        codeloc = CodeLocation(state.scratch.bbl_addr, state.scratch.stmt_idx, ins_addr=state.scratch.ins_addr)
        if codeloc in self.mapping:
            reg_read_offset = state.inspect.attrs.reg_read_offset
            if isinstance(reg_read_offset, claripy.ast.BV) and reg_read_offset.op == "BVV":
                reg_read_offset = reg_read_offset.args[0]
            variable = VEXReg(reg_read_offset, state.inspect.attrs.reg_read_length)
            if variable in self.mapping[codeloc]:
                v = self.mapping[codeloc][variable]
                if isinstance(v, int):
                    v = claripy.BVV(v, state.inspect.attrs.reg_read_length * state.arch.byte_width)
                state.inspect.attrs.reg_read_expr = v

    def _build_mapping(self):
        # constant propagation
        l.debug("JumpTable: Propagating for %r at %#x.", self.func, self.indirect_jump_addr)

        # determine blocks to run FCP on

        # - include at most three levels of superblock successors from the entrypoint
        self.mapping = {}
        startpoint = self.func.startpoint
        if startpoint is None:
            return

        blocks = set()
        succ_and_levels = [(startpoint, 0)]
        while succ_and_levels:
            new_succs = []
            for node, level in succ_and_levels:
                if node in blocks:
                    continue
                blocks.add(node)
                if node.addr == self.indirect_jump_addr:
                    # stop at the indirect jump block
                    continue
                for _, succ, data in self.func.graph.out_edges(node, data=True):
                    new_level = level if data.get("type") == "fake_return" else level + 1
                    if new_level <= 3:
                        new_succs.append((succ, new_level))
            succ_and_levels = new_succs

        # - include at most six levels of predecessors from the indirect jump block
        ij_block = self.func.get_node(self.indirect_jump_addr)
        preds = [ij_block]
        for _ in range(6):
            new_preds = []
            for node in preds:
                if node in blocks:
                    continue
                blocks.add(node)
                new_preds += list(self.func.graph.predecessors(node))
            preds = new_preds
            if not preds:
                break

        prop = self.project.analyses.FastConstantPropagation(
            self.func,
            blocks=blocks,
            vex_cross_insn_opt=True,
            load_callback=PropagatorLoadCallback(self.project).propagator_load_callback,
        )
        self.mapping = prop.replacements

        regs = prop.block_entry_regs.get(self.indirect_jump_addr, {})
        for offset, sv in regs.items():
            if offset == self.project.arch.ip_offset:
                continue
            # FCP does not remove overlapping entries when it stores a known value, so after writes to eax, ah and eax
            # again both entries remain and nothing records which is newer. Skip both.
            end = offset + sv.bits // 8
            if any(o != offset and o < end and offset < o + v.bits // 8 for o, v in regs.items()):
                continue
            self._entry_regs[offset] = claripy.BVV(sv.value, sv.bits)

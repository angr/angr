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
        "expanded_mapping",
        "expanded_replacement",
        "func",
        "indirect_jump_addr",
        "kb",
        "mapping",
        "predecessor_levels",
        "project",
    )

    def __init__(
        self,
        project: Project,
        kb,
        func: Function,
        ij_addr: int,
        predecessor_levels: int = 6,
        expanded_replacement: tuple[CodeLocation, VEXReg, int] | None = None,
    ):
        self.project = project
        self.kb = kb
        self.func = func
        self.indirect_jump_addr = ij_addr
        self.predecessor_levels = predecessor_levels
        self.expanded_replacement = expanded_replacement

        self.mapping: dict[Any, dict[Any, claripy.ast.Base]] | None = None
        self.expanded_mapping: dict[Any, dict[Any, claripy.ast.Base]] | None = None

    def reg_read_callback(self, state: SimState):
        if self.mapping is None:
            self._build_mapping()
            assert self.mapping is not None

        codeloc = CodeLocation(state.scratch.bbl_addr, state.scratch.stmt_idx, ins_addr=state.scratch.ins_addr)
        reg_read_offset = state.inspect.attrs.reg_read_offset
        if isinstance(reg_read_offset, claripy.ast.BV) and reg_read_offset.op == "BVV":
            reg_read_offset = reg_read_offset.args[0]
        variable = VEXReg(reg_read_offset, state.inspect.attrs.reg_read_length)

        mapping = self.mapping
        required_value = None
        if self.expanded_replacement is not None:
            selected_codeloc, selected_variable, required_value = self.expanded_replacement
            if codeloc == selected_codeloc and variable == selected_variable:
                if self.expanded_mapping is None:
                    self.expanded_mapping = self._compute_mapping(12)
                mapping = self.expanded_mapping

        if codeloc in mapping and variable in mapping[codeloc]:
            v = mapping[codeloc][variable]
            if required_value is not None:
                concrete_value = v if isinstance(v, int) else v.args[0] if v.concrete else None
                if concrete_value != required_value:
                    return
            if isinstance(v, int):
                v = claripy.BVV(v, state.inspect.attrs.reg_read_length * state.arch.byte_width)
            state.inspect.attrs.reg_read_expr = v

    def _build_mapping(self):
        self.mapping = self._compute_mapping(self.predecessor_levels)

    def _compute_mapping(self, predecessor_levels: int) -> dict[Any, dict[Any, claripy.ast.Base]]:
        # constant propagation
        l.debug("JumpTable: Propagating for %r at %#x.", self.func, self.indirect_jump_addr)

        # determine blocks to run FCP on

        # - include at most three levels of superblock successors from the entrypoint
        startpoint = self.func.startpoint
        if startpoint is None:
            return {}

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

        ij_block = self.func.get_node(self.indirect_jump_addr)
        preds = [ij_block]
        for _ in range(predecessor_levels):
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
        return prop.replacements

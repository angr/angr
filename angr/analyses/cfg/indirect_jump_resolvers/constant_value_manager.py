from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import networkx

from angr import claripy
from angr.analyses.propagator.vex_vars import VEXReg, VEXTmp
from angr.code_location import CodeLocation

from .propagator_utils import PropagatorLoadCallback


def fcp_rows(replacements) -> list:
    """
    FCP replacements as the rows the Rust FCP tables give (shadow-mode comparisons).
    """
    rows = []
    for loc, d in replacements.items():
        row = [((("tmp", k.tmp, 0) if isinstance(k, VEXTmp) else ("reg", k.offset, k.size)), v) for k, v in d.items()]
        rows.append(((loc.block_addr, loc.stmt_idx, loc.ins_addr), row))
    return rows


if TYPE_CHECKING:
    from angr import SimState
    from angr.analyses.cfg.cfg_base import CFGBase
    from angr.knowledge_plugins import Function
    from angr.project import Project
    from angr.rustylib.ijr import CvmMapping, FcpService


l = logging.getLogger(name=__name__)


class ConstantValueManager:
    """
    Manages the loading of registers who hold constant values.
    """

    __slots__ = (
        "_cfg",
        "_fcp",
        "_rust_mapping",
        "func",
        "indirect_jump_addr",
        "kb",
        "mapping",
        "project",
    )

    def __init__(
        self,
        project: Project,
        kb,
        func: Function | None,
        ij_addr: int,
        fcp: FcpService | None = None,
        cfg: CFGBase | None = None,
    ):
        self.project = project
        self.kb = kb
        self.func = func
        self.indirect_jump_addr = ij_addr
        # the Rust FCP of a CFGFast run (CFGBase._ijr_fcp) and that CFG
        self._fcp = fcp
        self._cfg = cfg
        self._rust_mapping: CvmMapping | None = None

        self.mapping: dict[Any, dict[Any, claripy.ast.Base]] | None = None

    def release(self) -> None:
        """
        Drop the function and the mapping. A breakpoint that outlives the resolver (e.g., on a state the engine still
        holds) then keeps neither alive.
        """
        self.func = None
        self.mapping = {}
        self._rust_mapping = None
        self._fcp = None
        self._cfg = None

    def reg_read_callback(self, state: SimState):
        if self.mapping is None:
            self._build_mapping()
            assert self.mapping is not None

        rust = self._rust_mapping
        if rust is not None:
            reg_read_offset = state.inspect.attrs.reg_read_offset
            if isinstance(reg_read_offset, claripy.ast.BV) and reg_read_offset.op == "BVV":
                reg_read_offset = reg_read_offset.args[0]
            scratch = state.scratch
            length = state.inspect.attrs.reg_read_length
            if (
                type(reg_read_offset) is int
                and type(scratch.bbl_addr) is int
                and type(scratch.stmt_idx) is int
                and type(scratch.ins_addr) is int
                and type(length) is int
            ):
                v = rust.reg(scratch.bbl_addr, scratch.stmt_idx, scratch.ins_addr, reg_read_offset, length)
                if v is not None:
                    state.inspect.attrs.reg_read_expr = claripy.BVV(v, length * state.arch.byte_width)
            return

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

        # determine blocks to run FCP on; nodes are the function's FunctionGraph IDs
        self.mapping = {}
        assert self.func is not None
        if self._fcp is not None and self._cfg is not None:
            rust = self._fcp.cvm_mapping(self._cfg, self.func.addr, self.indirect_jump_addr)
            if not isinstance(rust, str):
                if not self._fcp.shadow:
                    self._rust_mapping = rust
                    return
                self._build_python_mapping()
                self._fcp.shadow_compare(self.func.addr, self.indirect_jump_addr, rust, fcp_rows(self.mapping))
                return
        self._build_python_mapping()

    def _build_python_mapping(self):
        assert self.func is not None
        func = self.func
        graph = func._graph
        start = graph.startpoint
        if start is None:
            return

        blocks: set[int] = set()
        succ_and_levels = [(start, 0)]
        while succ_and_levels:
            new_succs = []
            for node, level in succ_and_levels:
                if node in blocks:
                    continue
                blocks.add(node)
                if graph.node_addr(node) == self.indirect_jump_addr:
                    # stop at the indirect jump block
                    continue
                if not graph.in_local_view(node):
                    raise networkx.NetworkXError(f"The node {func._node_obj(node)} is not in the digraph.")
                for succ, data in graph.local_out_edges_with_data(node):
                    new_level = level if data.get("type") == "fake_return" else level + 1
                    if new_level <= 3:
                        new_succs.append((succ, new_level))
            succ_and_levels = new_succs

        # - include at most six levels of predecessors from the indirect jump block
        ij_block = graph.block_node_at(self.indirect_jump_addr)
        if ij_block is None:
            raise networkx.NetworkXError("The node None is not in the digraph.")
        preds = [ij_block]
        for _ in range(6):
            new_preds = []
            for node in preds:
                if node in blocks:
                    continue
                blocks.add(node)
                if not graph.in_local_view(node):
                    raise networkx.NetworkXError(f"The node {func._node_obj(node)} is not in the digraph.")
                new_preds += graph.local_predecessors(node)
            preds = new_preds
            if not preds:
                break

        prop = self.project.analyses.FastConstantPropagation(
            func,
            block_addrs={graph.node_addr(node) for node in blocks},
            vex_cross_insn_opt=True,
            load_callback=PropagatorLoadCallback(self.project).propagator_load_callback,
        )
        self.mapping = prop.replacements

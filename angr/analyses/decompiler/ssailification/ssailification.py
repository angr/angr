from __future__ import annotations

import logging
from collections import defaultdict
from itertools import count
from typing import Literal

import networkx

from angr.ailment import Address, Block, Manager
from angr.ailment.expression import (
    IRegister,
    Register,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.analyses.analysis import Analysis, register_analysis
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.analyses.dominance_frontier import DominanceFrontier, calculate_iterated_dominace_frontier_set
from angr.enums import Flavors
from angr.knowledge_plugins.functions import Function
from angr.utils.ail import has_call

from .rewriting import RewritingAnalysis
from .traversal import TraversalAnalysis

l = logging.getLogger(name=__name__)


type Kind = Literal["stack", "reg"]
type UDef = tuple[Kind, int, int]
type Def = StackBaseOffset | Register | IRegister


class Ssailification(Analysis):  # pylint:disable=abstract-method
    """
    Ssailification (SSA-AIL-ification) transforms an AIL graph to its partial-SSA form.
    """

    def __init__(
        self,
        func: Function | str,
        ail_graph: networkx.DiGraph[Block],
        entry: Block | None = None,
        canonical_size: int = 8,
        stack_pointer_tracker=None,
        func_addr: int | None = None,
        ail_manager: Manager | None = None,
        ssa_stackvars: bool = False,
        ssa_tmps: bool = False,
        func_args: set[VirtualVariable] | None = None,
        rewrite_vvars: set[int] | None = None,
        vvar_id_start: int = 0,
        flavor: str = Flavors.DEFAULT_FLAVOR,
    ):
        """
        :param func:                            The subject of the analysis: a function, or a single basic block
        :param ail_graph:                       The AIL graph to transform.
        :param canonical_size:                  The sizes (in bytes) that objects with an UNKNOWN_SIZE are treated as
                                                for operations where sizes are necessary.
        """

        if isinstance(func, str):
            self._function = self.kb.functions[func]
        else:
            self._function = func

        assert ail_manager is not None, "Always need a Manager now"

        self._canonical_size = canonical_size
        self._func_addr = func_addr
        self._ail_manager = ail_manager
        self._ssa_stackvars = ssa_stackvars
        self._ssa_tmps = ssa_tmps
        self._rewrite_vvars = rewrite_vvars or set()
        self._func_args = func_args if func_args is not None else set()
        self._flavor = flavor
        self._entry = (
            entry
            if entry is not None
            else next(iter(bb for bb in ail_graph if bb.addr == self._func_addr and bb.idx == 0))
        )
        self.out_graph = None

        bp_as_gpr = self._function.info.get("bp_as_gpr", False)

        df = DominanceFrontier(self._function, func_graph=ail_graph, entry=self._entry)
        frontiers = df.frontiers
        frontier_blocks: set[tuple[int, int]] = {(b.addr, b.idx) for blocks in frontiers.values() for b in blocks}

        # collect defs
        traversal = TraversalAnalysis(
            self.project,
            self._function,
            ail_graph,
            stack_pointer_tracker,
            bp_as_gpr,
            ssa_stackvars,
            ssa_tmps,
            set(),
            self.kb.functions.get,
            variable_map=variable_map_of(self._ail_manager) if self._ail_manager is not None else None,
            ail_manager=self._ail_manager,
            start_state_blocks=frontier_blocks,
            flavor=self._flavor,
        )

        # calculate virtual variables and phi nodes
        self._udef_to_phiid: dict[tuple, set[int]] = {}
        self._phiid_to_loc: dict[int, tuple[int, int]] = {}

        udef_to_defs: defaultdict[UDef, set[Def]] = defaultdict(set)
        udef_to_blockkeys: defaultdict[UDef, set[Address]] = defaultdict(set)
        blockkey_to_block = {(block.addr, block.idx): block for block in ail_graph}
        def_to_udef: dict[Def, UDef] = {}
        extern_defs: set[UDef] = set()
        incomplete_defs: set[Def] = set()
        for def_, definfo in traversal.def_info.items():
            if definfo.store_size != definfo.variable_size:
                incomplete_defs.add(def_)
            udef = (definfo.kind, definfo.variable_offset, definfo.variable_size)
            udef_to_defs[udef].add(def_)
            if definfo.loc.is_extern:
                extern_defs.add(udef)
                udef_to_blockkeys[udef].add((-1, -1))
            else:
                blockkey = (definfo.loc.addr, definfo.loc.block_idx)
                def_to_udef[def_] = udef
                udef_to_blockkeys[udef].add(blockkey)

        phi_id_ctr = count(vvar_id_start)

        phiid_to_udef: dict[int, UDef] = {}
        block_to_phiids: defaultdict[Block, list[int]] = defaultdict(list)
        for udef, block_keys in udef_to_blockkeys.items():
            blocks = {self._entry if block_key[0] == -1 else blockkey_to_block[block_key] for block_key in block_keys}
            frontier_plus = calculate_iterated_dominace_frontier_set(frontiers, blocks)
            for block in frontier_plus:
                # Don't generate a phi for this udef if the udef does not correspond to the actual live
                # variable at this location
                if (state := traversal.start_states.get(block, None)) is not None:
                    defmap = {"stack": state.stackvar_defs, "reg": state.register_defs}[udef[0]]
                    defs = set(defmap.get(udef[1], ()))
                    if udef[0] == "reg":
                        # a register clobbered by a call on some incoming path is defined by that call
                        for loc in state.register_blackout.get(udef[1], ()):
                            cdef = traversal.clobber_def_for(loc, udef[1])
                            if cdef is not None:
                                defs.add(cdef)
                    if not defs:
                        continue
                    # Generally, we only see multiple sizes if a) the variable is actually unused past this point
                    # or b) this is the top of a loop with one def at the bottom
                    if udef[2] != max(traversal.def_info[def_].variable_size for def_ in defs):
                        # print('passed up phi for', udef, 'at', block, '(1)')
                        continue
                    ranges = set()
                    if udef[0] == "stack":
                        overlapping_defs = (
                            d for _, _, d in state.stackvar_defs.overlapping(udef[1], udef[1] + udef[2])
                        )
                    else:
                        overlapping_defs = (
                            state.register_defs.get(suboffset, ()) for suboffset in range(udef[1], udef[1] + udef[2])
                        )
                    for defs2 in overlapping_defs:
                        for def2 in defs2:
                            definfo2 = traversal.def_info[def2]
                            ranges.add((definfo2.variable_offset, definfo2.variable_size))
                    for def2 in defs:
                        definfo2 = traversal.def_info[def2]
                        ranges.add((definfo2.variable_offset, definfo2.variable_size))
                    # Reaching defs that share this udef's start offset but are narrower are partial writes of the same
                    # variable (e.g. a 1-byte store into a 4-byte variable at the end of a loop). They do not
                    # invalidate the phi for the full-width variable.
                    if any(r_off != udef[1] for r_off, _ in ranges):
                        # print('passed up phi for', udef, 'at', block, '(2)')
                        continue
                phi_id = next(phi_id_ctr)
                phiid_to_udef[phi_id] = udef
                block_to_phiids[block].append(phi_id)

        self._widen_args_reaching_phis(ail_graph, traversal, phiid_to_udef, block_to_phiids, extern_defs)

        # insert phi variables and rewrite uses
        rewriter = RewritingAnalysis(
            self.project,
            self._function,
            ail_graph,
            phiid_to_udef,
            block_to_phiids,
            self._ssa_tmps,
            self._ail_manager,
            self._func_args,
            def_to_udef,
            extern_defs,
            incomplete_defs=incomplete_defs,
            vvar_id_start=next(phi_id_ctr),
            stackvars=self._ssa_stackvars,
            fail_fast=self._fail_fast,
            clobber_defs_by_loc=traversal.clobber_defs_by_loc,
        )
        self.out_graph = rewriter.out_graph
        self.max_vvar_id: int = rewriter.max_vvar_id if rewriter.max_vvar_id is not None else 0
        self.resized_func_args = rewriter.resized_func_args

    def _widen_args_reaching_phis(
        self,
        ail_graph: networkx.DiGraph[Block],
        traversal: TraversalAnalysis,
        phiid_to_udef: dict[int, UDef],
        block_to_phiids: dict[Block, list[int]],
        extern_defs: set[UDef],
    ) -> None:
        """
        A register argument that reaches a register phi unchanged is one of the phi's sources, so it must be as wide as
        the phi. E.g., a float64 argument in xmm1 that is zeroed (all 128 bits) on one path only: without widening the
        argument, the rewriter sees sources of two sizes and drops the phi, leaving its uses undefined.
        """
        arg_sizes = {
            arg.parameter_reg_offset: arg.size
            for arg in self._func_args
            if arg.parameter_category == VirtualVariableCategory.REGISTER
        }
        if not arg_sizes:
            return
        def_blocks: defaultdict[int, set[Address]] = defaultdict(set)
        for definfo in traversal.def_info.values():
            if definfo.kind == "reg" and not definfo.loc.is_extern:
                def_blocks[definfo.variable_offset].add((definfo.loc.addr, definfo.loc.block_idx))
        for block, phi_ids in block_to_phiids.items():
            for phi_id in phi_ids:
                udef = phiid_to_udef[phi_id]
                kind, offset, size = udef
                if kind != "reg" or udef in extern_defs or arg_sizes.get(offset, size) >= size:
                    continue
                if any(k == "reg" and o <= offset and offset + size <= o + s for k, o, s in extern_defs):
                    continue
                stops = set().union(*(keys for off, keys in def_blocks.items() if offset <= off < offset + size))
                if self._entry_reaches(ail_graph, block, stops):
                    extern_defs.add(udef)

    def _entry_reaches(self, graph: networkx.DiGraph[Block], block: Block, stops: set[Address]) -> bool:
        """Whether a path from the function entry to block exists that has no block in stops and no call."""
        queue = list(graph.predecessors(block))
        seen = set(queue)
        while queue:
            node = queue.pop()
            if (node.addr, node.idx) in stops or has_call(node):
                continue
            if node is self._entry:
                return True
            for pred in graph.predecessors(node):
                if pred not in seen:
                    seen.add(pred)
                    queue.append(pred)
        return False


register_analysis(Ssailification, "Ssailification")

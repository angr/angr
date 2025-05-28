from __future__ import annotations
import logging
from typing import Any
from collections import defaultdict
from itertools import count
from bisect import bisect_left

from angr.ailment.expression import (
    Expression,
    Register,
    StackBaseOffset,
    Tmp,
    VirtualVariable,
    VirtualVariableCategory,
    Load,
)
from angr.ailment.statement import Statement, Store

from angr.knowledge_plugins.functions import Function
from angr.code_location import CodeLocation
from angr.analyses import Analysis, register_analysis
from angr.utils.ssa import get_reg_offset_base_and_size
from .traversal import TraversalAnalysis
from .rewriting import RewritingAnalysis

l = logging.getLogger(name=__name__)


class Ssailification(Analysis):  # pylint:disable=abstract-method
    """
    Ssailification (SSA-AIL-ification) transforms an AIL graph to its partial-SSA form.
    """

    def __init__(
        self,
        func: Function | str,
        ail_graph,
        entry=None,
        canonical_size=8,
        stack_pointer_tracker=None,
        func_addr: int | None = None,
        ail_manager=None,
        ssa_stackvars: bool = False,
        ssa_tmps: bool = False,
        func_args: set[VirtualVariable] | None = None,
        vvar_id_start: int = 0,
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

        self._canonical_size = canonical_size
        self._func_addr = func_addr
        self._ail_manager = ail_manager
        self._ssa_stackvars = ssa_stackvars
        self._ssa_tmps = ssa_tmps
        self._func_args = func_args if func_args is not None else set()
        self._entry = (
            entry
            if entry is not None
            else next(iter(bb for bb in ail_graph if bb.addr == self._func_addr and bb.idx is None))
        )
        self.out_graph = None

        bp_as_gpr = self._function.info.get("bp_as_gpr", False)

        # collect defs
        traversal = TraversalAnalysis(
            self.project,
            self._function,
            ail_graph,
            stack_pointer_tracker,
            bp_as_gpr,
            ssa_stackvars,
            ssa_tmps,
            self._func_args,
        )

        # calculate virtual variables and phi nodes
        self._udef_to_phiid: dict[tuple, set[int]] = None
        self._phiid_to_loc: dict[int, tuple[int, int | None]] = None
        self._stackvar_locs: dict[int, set[int]] = None
        self._calculate_virtual_variables(ail_graph, traversal.def_to_loc, traversal.loc_to_defs)

        # insert phi variables and rewrite uses
        rewriter = RewritingAnalysis(
            self.project,
            self._function,
            ail_graph,
            stack_pointer_tracker,
            bp_as_gpr,
            self._udef_to_phiid,
            self._phiid_to_loc,
            self._stackvar_locs,
            self._ssa_tmps,
            self._ail_manager,
            self._func_args,
            vvar_id_start=vvar_id_start,
        )
        self.secondary_stackvars = rewriter.secondary_stackvars
        self.out_graph = rewriter.out_graph
        self.max_vvar_id: int = rewriter.max_vvar_id if rewriter.max_vvar_id is not None else 0

    def _calculate_virtual_variables(
        self,
        ail_graph,
        def_to_loc: list[tuple[Expression | Statement, CodeLocation]],
        loc_to_defs: dict[CodeLocation, Any],
    ):
        """
        Calculate the mapping from defs to virtual variables as well as where to insert phi nodes.
        """

        # Computer the dominance frontier for each node in the graph
        df = self.project.analyses.DominanceFrontier(self._function, func_graph=ail_graph, entry=self._entry)
        frontiers = df.frontiers

        blockkey_to_block = {(block.addr, block.idx): block for block in ail_graph}
        blockkey_to_defs = defaultdict(set)
        for codeloc, defs in loc_to_defs.items():
            block_key = codeloc.block_addr, codeloc.block_idx
            if block_key in blockkey_to_block:
                for def_ in defs:
                    blockkey_to_defs[block_key].add(def_)

        if self._ssa_stackvars:
            # for stack variables, we collect all definitions and identify stack variable locations using heuristics

            stackvar_locs = self._synthesize_stackvar_locs(
                [def_ for def_, _ in def_to_loc if isinstance(def_, (Store, StackBaseOffset))]
            )
            # handle function arguments
            if self._func_args:
                for func_arg in self._func_args:
                    if func_arg.oident[0] == VirtualVariableCategory.STACK:
                        stackvar_locs[func_arg.oident[1]] = {func_arg.size}
            sorted_stackvar_offs = sorted(stackvar_locs)
        else:
            stackvar_locs = {}
            sorted_stackvar_offs = []

        # compute phi node locations for each unified definition
        udef_to_defs = defaultdict(set)
        udef_to_blockkeys = defaultdict(set)
        for def_, loc in def_to_loc:
            if isinstance(def_, Register):
                base_off, base_size = get_reg_offset_base_and_size(def_.reg_offset, self.project.arch, size=def_.size)
                base_reg_bits = base_size * self.project.arch.byte_width
                udef_to_defs[("reg", base_off, base_reg_bits)].add(def_)
                udef_to_blockkeys[("reg", base_off, base_reg_bits)].add((loc.block_addr, loc.block_idx))
                # add a definition for the partial register
                if base_off != def_.reg_offset or base_size != def_.size:
                    reg_bits = def_.size * self.project.arch.byte_width
                    udef_to_defs[("reg", def_.reg_offset, reg_bits)].add(def_)
                    udef_to_blockkeys[("reg", def_.reg_offset, reg_bits)].add((loc.block_addr, loc.block_idx))
            elif isinstance(def_, (Store, Load)):
                if isinstance(def_.addr, StackBaseOffset) and isinstance(def_.addr.offset, int):
                    idx_begin = bisect_left(sorted_stackvar_offs, def_.addr.offset)
                    for i in range(idx_begin, len(sorted_stackvar_offs)):
                        off = sorted_stackvar_offs[i]
                        if off >= def_.addr.offset + def_.size:
                            break
                        full_sz = max(stackvar_locs[off])
                        udef_to_defs[("stack", off, full_sz)].add(def_)
                        udef_to_blockkeys[("stack", off, full_sz)].add((loc.block_addr, loc.block_idx))
                        # add a definition for the partial stack variable
                        if def_.size in stackvar_locs[off] and def_.size < full_sz:
                            udef_to_defs[("stack", off, def_.size)].add(def_)
                            udef_to_blockkeys[("stack", off, def_.size)].add((loc.block_addr, loc.block_idx))
            elif isinstance(def_, StackBaseOffset):
                sz = 1
                idx_begin = bisect_left(sorted_stackvar_offs, def_.offset)
                for i in range(idx_begin, len(sorted_stackvar_offs)):
                    off = sorted_stackvar_offs[i]
                    if off >= def_.offset + sz:
                        break
                    full_sz = max(stackvar_locs[off])
                    udef_to_defs[("stack", off, full_sz)].add(def_)
                    udef_to_blockkeys[("stack", off, full_sz)].add((loc.block_addr, loc.block_idx))
            elif isinstance(def_, Tmp):
                # Tmps are local to each block and do not need phi nodes
                pass
            else:
                raise NotImplementedError
                # other types are not supported yet

        phi_id_ctr = count()

        udef_to_phiid = defaultdict(set)
        phiid_to_loc = {}
        for udef, block_keys in udef_to_blockkeys.items():
            blocks = {blockkey_to_block[block_key] for block_key in block_keys}
            frontier_plus = self._calculate_iterated_dominace_frontier_set(frontiers, blocks)
            for block in frontier_plus:
                phi_id = next(phi_id_ctr)
                udef_to_phiid[udef].add(phi_id)
                phiid_to_loc[phi_id] = block.addr, block.idx

        self._stackvar_locs = stackvar_locs
        self._udef_to_phiid = udef_to_phiid
        self._phiid_to_loc = phiid_to_loc

    @staticmethod
    def _calculate_iterated_dominace_frontier_set(frontiers: dict, blocks: set) -> set:
        last_frontier: set | None = None
        while True:
            frontier = set()
            for b in blocks:
                if b in frontiers:
                    frontier |= frontiers[b]
            if last_frontier is not None and last_frontier == frontier:
                break
            last_frontier = frontier
            blocks |= frontier
        return last_frontier

    @staticmethod
    def _synthesize_stackvar_locs(defs: list[Store | StackBaseOffset]) -> dict[int, set[int]]:
        """
        Derive potential locations (in terms of offsets and sizes) for stack variables based on all stack variable
        definitions provided.

        :param defs:    Store definitions.
        :return:        A dictionary of stack variable offsets and their sizes.
        """

        accesses: defaultdict[int, set[int]] = defaultdict(set)
        offs: set[int] = set()

        for def_ in defs:
            if isinstance(def_, StackBaseOffset):
                stack_off = def_.offset
                accesses[stack_off].add(-1)  # we will fix it later
                offs.add(stack_off)
            elif isinstance(def_, Store) and isinstance(def_.addr, StackBaseOffset):
                stack_off = def_.addr.offset
                accesses[stack_off].add(def_.size)
                offs.add(stack_off)

        sorted_offs = sorted(offs)
        locs: dict[int, set[int]] = {}
        for idx, off in enumerate(sorted_offs):
            sorted_sizes = sorted(accesses[off])
            if -1 in sorted_sizes:
                sorted_sizes.remove(-1)

            allowed_sizes = []
            if not sorted_sizes:
                # this location is only referenced by a ref; we guess its size
                if idx < len(sorted_offs) - 1:
                    next_off = sorted_offs[idx + 1]
                    sz = next_off - off
                    if sz > 0:
                        allowed_sizes = [sz]
            else:
                if idx < len(sorted_offs) - 1:
                    next_off = sorted_offs[idx + 1]
                    allowed_sizes = [sz for sz in sorted_sizes if off + sz <= next_off]
                else:
                    allowed_sizes = sorted_sizes

            if allowed_sizes:
                locs[off] = set(allowed_sizes)

        return locs


register_analysis(Ssailification, "Ssailification")

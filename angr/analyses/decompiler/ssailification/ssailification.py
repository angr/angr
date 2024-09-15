from __future__ import annotations
import logging
from typing import Any
from collections import defaultdict
from itertools import count
from bisect import bisect_left

from ailment.expression import Register, StackBaseOffset
from ailment.statement import Store

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
        )

        # calculate virtual variables and phi nodes
        self._udef_to_phiid: dict[tuple, set[int]] = None
        self._phiid_to_loc: dict[int, tuple[int, int | None]] = None
        self._stackvar_locs: dict[int, int] = None
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
            self._ail_manager,
            vvar_id_start=vvar_id_start,
        )
        self.out_graph = rewriter.out_graph
        self.max_vvar_id = rewriter.max_vvar_id

    def _calculate_virtual_variables(self, ail_graph, def_to_loc: dict, loc_to_defs: dict[CodeLocation, Any]):
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

            stackvar_locs = self._synthesize_stackvar_locs([def_ for def_ in def_to_loc if isinstance(def_, Store)])
            sorted_stackvar_offs = sorted(stackvar_locs)
        else:
            stackvar_locs = {}
            sorted_stackvar_offs = []

        # computer phi node locations for each unified definition
        udef_to_defs = defaultdict(set)
        udef_to_blockkeys = defaultdict(set)
        for def_ in def_to_loc:
            if isinstance(def_, Register):
                loc = def_to_loc[def_]

                base_off, base_size = get_reg_offset_base_and_size(def_.reg_offset, self.project.arch, size=def_.size)
                base_reg_bits = base_size * self.project.arch.byte_width
                udef_to_defs[("reg", base_off, base_reg_bits)].add(def_)
                udef_to_blockkeys[("reg", base_off, base_reg_bits)].add((loc.block_addr, loc.block_idx))
                # add a definition for the partial register
                if base_off != def_.reg_offset:
                    reg_bits = def_.size * self.project.arch.byte_width
                    udef_to_defs[("reg", def_.reg_offset, reg_bits)].add((loc.block_addr, loc.block_idx))
            elif isinstance(def_, Store):
                if isinstance(def_.addr, StackBaseOffset) and isinstance(def_.addr.offset, int):
                    loc = def_to_loc[def_]

                    idx_begin = bisect_left(sorted_stackvar_offs, def_.addr.offset)
                    for i in range(idx_begin, len(sorted_stackvar_offs)):
                        off = sorted_stackvar_offs[i]
                        if off >= def_.addr.offset + def_.size:
                            break
                        udef_to_defs[("stack", off, stackvar_locs[off])].add(def_)
                        udef_to_blockkeys[("stack", off, stackvar_locs[off])].add((loc.block_addr, loc.block_idx))
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
                frontier |= frontiers[b]
            if last_frontier is not None and last_frontier == frontier:
                break
            last_frontier = frontier
            blocks |= frontier
        return last_frontier

    @staticmethod
    def _synthesize_stackvar_locs(defs: list[Store]) -> dict[int, int]:
        accesses: defaultdict[int, set[int]] = defaultdict(set)
        offs: set[int] = set()

        for def_ in defs:
            if isinstance(def_.addr, StackBaseOffset):
                stack_off = def_.addr.offset
                accesses[stack_off].add(def_.size)
                offs.add(stack_off)

        sorted_offs = sorted(offs)
        locs: dict[int, int] = {}
        for idx, off in enumerate(sorted_offs):
            sorted_sizes = sorted(accesses[off])
            if idx < len(sorted_offs) - 1:
                next_off = sorted_offs[idx + 1]
                allowed_sizes = [sz for sz in sorted_sizes if off + sz <= next_off]
            else:
                allowed_sizes = sorted_sizes

            if len(allowed_sizes) == 1:
                locs[off] = allowed_sizes[0]
            # else:
            #     last_off = off
            #     for a in allowed_sizes:
            #         locs[off + a] = off + a - last_off
            #         last_off = off + a
            # TODO: Update locs for sizes beyond allowed_sizes

        return locs


register_analysis(Ssailification, "Ssailification")

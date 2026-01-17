from __future__ import annotations
import logging
from typing import Literal, TypeAlias
from collections import defaultdict
from itertools import count

import networkx

from angr.ailment import Address, Block
from angr.ailment.expression import (
    Register,
    StackBaseOffset,
    VirtualVariable,
)

from angr.analyses.dominance_frontier import DominanceFrontier, calculate_iterated_dominace_frontier_set
from angr.knowledge_plugins.functions import Function
from angr.analyses import Analysis, register_analysis
from .traversal import TraversalAnalysis
from .rewriting import RewritingAnalysis

l = logging.getLogger(name=__name__)


Kind: TypeAlias = Literal["stack", "reg"]
UDef: TypeAlias = tuple[Kind, int, int]
Def: TypeAlias = StackBaseOffset | Register


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
        ail_manager=None,
        ssa_stackvars: bool = False,
        ssa_tmps: bool = False,
        func_args: set[VirtualVariable] | None = None,
        rewrite_vvars: set[int] | None = None,
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
        self._rewrite_vvars = rewrite_vvars or set()
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
            self.kb.functions.get,
        )

        # calculate virtual variables and phi nodes
        self._udef_to_phiid: dict[tuple, set[int]] = {}
        self._phiid_to_loc: dict[int, tuple[int, int | None]] = {}
        self._calculate_virtual_variables(ail_graph, traversal)

        # insert phi variables and rewrite uses
        rewriter = RewritingAnalysis(
            self.project,
            self._function,
            ail_graph,
            self._udef_to_phiid,
            self._phiid_to_loc,
            self._ssa_tmps,
            self._ail_manager,
            self._func_args,
            self._def_to_udef,
            self._extern_defs,
            vvar_id_start=vvar_id_start,
        )
        self.out_graph = rewriter.out_graph
        self.max_vvar_id: int = rewriter.max_vvar_id if rewriter.max_vvar_id is not None else 0

    def _calculate_virtual_variables(
        self,
        ail_graph: networkx.DiGraph[Block],
        traversal: TraversalAnalysis,
    ):
        """
        Calculate the mapping from defs to virtual variables as well as where to insert phi nodes.
        """

        udef_to_defs: defaultdict[UDef, set[Def]] = defaultdict(set)
        udef_to_blockkeys: defaultdict[UDef, set[Address]] = defaultdict(set)
        blockkey_to_block = {(block.addr, block.idx): block for block in ail_graph}
        # blockkey_to_defs: defaultdict[Address, set[Def]] = defaultdict(set)
        def_to_udef: dict[Def, UDef] = {}
        extern_defs: set[UDef] = set()
        for def_, (kind, loc, offset, size, _) in traversal.def_info.items():
            udef = (kind, offset, size)
            udef_to_defs[udef].add(def_)
            # blockkey_to_defs[blockkey].add(def_)
            if loc.is_extern:
                extern_defs.add(udef)
                udef_to_blockkeys[udef].add((-1, None))
            else:
                blockkey = (loc.addr, loc.block_idx)
                def_to_udef[def_] = udef
                udef_to_blockkeys[udef].add(blockkey)

        # Computer the dominance frontier for each node in the graph
        df = DominanceFrontier(self._function, func_graph=ail_graph, entry=self._entry)
        frontiers = df.frontiers

        phi_id_ctr = count()

        udef_to_phiid = defaultdict(set)
        phiid_to_loc = {}
        for udef, block_keys in udef_to_blockkeys.items():
            blocks = {self._entry if block_key[0] == -1 else blockkey_to_block[block_key] for block_key in block_keys}
            frontier_plus = calculate_iterated_dominace_frontier_set(frontiers, blocks)
            for block in frontier_plus:
                phi_id = next(phi_id_ctr)
                udef_to_phiid[udef].add(phi_id)
                phiid_to_loc[phi_id] = block.addr, block.idx

        self._udef_to_phiid = udef_to_phiid
        self._phiid_to_loc = phiid_to_loc
        self._def_to_udef = def_to_udef
        self._extern_defs = extern_defs


register_analysis(Ssailification, "Ssailification")

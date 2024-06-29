from __future__ import annotations
import logging
from typing import DefaultDict, Any
from collections import defaultdict
from itertools import count

from ailment.expression import Register

from angr.knowledge_plugins.functions import Function
from angr.code_location import CodeLocation
from angr.analyses import Analysis, register_analysis
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
        canonical_size=8,
        stack_pointer_tracker=None,
        use_callee_saved_regs_at_return=True,
        func_addr: int | None = None,
        element_limit: int = 5,
    ):
        """
        :param func:                            The subject of the analysis: a function, or a single basic block
        :param ail_graph:                       The AIL graph to transform.
        :param max_iterations:                  The maximum number of iterations before the analysis is terminated.
        :param track_tmps:                      Whether or not temporary variables should be taken into consideration
                                                during the analysis.
        :param iterable observation_points:     A collection of tuples of ("node"|"insn", ins_addr, OP_TYPE) defining
                                                where reaching definitions should be copied and stored. OP_TYPE can be
                                                OP_BEFORE or OP_AFTER.
        :param function_handler:                The function handler to update the analysis state and results on
                                                function calls.
        :param observe_all:                     Observe every statement, both before and after.
        :param visited_blocks:                  A set of previously visited blocks.
        :param dep_graph:                       An initial dependency graph to add the result of the analysis to. Set it
                                                to None to skip dependency graph generation.
        :param canonical_size:                  The sizes (in bytes) that objects with an UNKNOWN_SIZE are treated as
                                                for operations where sizes are necessary.
        :param dep_graph:                       Set this to True to generate a dependency graph for the subject. It will
                                                be available as `result.dep_graph`.
        :param interfunction_level:             The number of functions we should recurse into. This parameter is only
                                                used if function_handler is not provided.
        :param track_liveness:                  Whether to track liveness information. This can consume
                                                sizeable amounts of RAM on large functions. (e.g. ~15GB for a function
                                                with 4k nodes)
        """

        if isinstance(func, str):
            self._function = self.kb.functions[func]
        else:
            self._function = func

        self._canonical_size = canonical_size
        self._use_callee_saved_regs_at_return = use_callee_saved_regs_at_return
        self._func_addr = func_addr
        self._element_limit = element_limit
        self.out_graph = None

        self._node_iterations: DefaultDict[int | tuple, int] = defaultdict(int)

        bp_as_gpr = self._function.info.get("bp_as_gpr", False)

        # collect defs
        traversal = TraversalAnalysis(
            self.project,
            self._function,
            ail_graph,
            stack_pointer_tracker,
            bp_as_gpr,
        )

        # calculate virtual variables and phi nodes
        self._def_to_vvid: dict[Any, int] = None
        self._udef_to_phiid: dict[tuple, set[int]] = None
        self._phiid_to_loc: dict[int, tuple[int, int | None]] = None
        self._calculate_virtual_variables(ail_graph, traversal.def_to_loc, traversal.loc_to_defs)

        # insert phi variables and rewrite uses
        rewriter = RewritingAnalysis(
            self.project,
            self._function,
            ail_graph,
            stack_pointer_tracker,
            bp_as_gpr,
            self._def_to_vvid,
            self._udef_to_phiid,
            self._phiid_to_loc,
        )
        self.out_graph = rewriter.out_graph

    def _calculate_virtual_variables(self, ail_graph, def_to_loc: dict, loc_to_defs: dict[CodeLocation, Any]):
        """
        Calculate the mapping from defs to virtual variables as well as where to insert phi nodes.
        """

        vv_ctr = count()

        def_to_vv = {}
        for def_ in def_to_loc:
            def_to_vv[def_] = next(vv_ctr)

        # Computer the dominance frontier for each node in the graph
        df = self.project.analyses.DominanceFrontier(self._function, func_graph=ail_graph)
        frontiers = df.frontiers

        blockkey_to_block = {(block.addr, block.idx): block for block in ail_graph}
        blockkey_to_defs = defaultdict(set)
        for codeloc, defs in loc_to_defs.items():
            block_key = codeloc.block_addr, codeloc.block_idx
            if block_key in blockkey_to_block:
                for def_ in defs:
                    blockkey_to_defs[block_key].add(def_)

        # computer phi node locations for each unified definition
        udef_to_defs = defaultdict(set)
        udef_to_blockkeys = defaultdict(set)
        for def_ in def_to_loc:
            if isinstance(def_, Register):
                # TODO: unify it to the base register
                base_regoffset = def_.reg_offset
                reg_bits = def_.bits
                udef_to_defs[("reg", base_regoffset, reg_bits)].add(def_)
                loc = def_to_loc[def_]
                udef_to_blockkeys[("reg", base_regoffset, reg_bits)].add((loc.block_addr, loc.block_idx))
            # other types are not supported

        udef_to_phiid = defaultdict(set)
        phiid_to_loc = {}
        for udef, block_keys in udef_to_blockkeys.items():
            blocks = {blockkey_to_block[block_key] for block_key in block_keys}
            frontier_plus = self._calculate_iterated_dominace_frontier_set(frontiers, blocks)
            for block in frontier_plus:
                phi_id = next(vv_ctr)
                udef_to_phiid[udef].add(phi_id)
                phiid_to_loc[phi_id] = block.addr, block.idx

        self._def_to_vvid = def_to_vv
        self._udef_to_phiid = udef_to_phiid
        self._phiid_to_loc = phiid_to_loc

    def _calculate_iterated_dominace_frontier_set(self, frontiers: dict, blocks: set) -> set:
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


register_analysis(Ssailification, "Ssailification")

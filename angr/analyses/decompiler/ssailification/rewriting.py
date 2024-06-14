from __future__ import annotations
from typing import Any
import logging

import networkx

import ailment

from angr.code_location import CodeLocation
from angr.analyses import ForwardAnalysis
from angr.analyses.forward_analysis.visitors.graph import NodeType
from angr.analyses.forward_analysis import FunctionGraphVisitor
from .rewriting_engine import SimEngineSSARewriting
from .rewriting_state import RewritingState


l = logging.getLogger(__name__)


class RewritingAnalysis(ForwardAnalysis[RewritingState, NodeType, object, object]):
    """
    RewritingAnalysis traverses the AIL graph, inserts phi nodes, and rewrites all expression uses to virtual variables
    when necessary.
    """

    def __init__(
        self,
        project,
        func,
        ail_graph,
        sp_tracker,
        bp_as_gpr: bool,
        def_to_vvid: dict[Any, int],
        udef_to_phiid: dict[tuple, set[int]],
        phiid_to_loc: dict[int, tuple[int, int | None]],
    ):
        self.project = project
        self._function = func
        self._graph_visitor = FunctionGraphVisitor(self._function, ail_graph)

        ForwardAnalysis.__init__(
            self, order_jobs=True, allow_merging=True, allow_widening=False, graph_visitor=self._graph_visitor
        )
        self._def_to_vvid = def_to_vvid
        self._udef_to_phiid = udef_to_phiid
        self._phiid_to_loc = phiid_to_loc
        self._engine_ail = SimEngineSSARewriting(
            self.project.arch,
            sp_tracker=sp_tracker,
            bp_as_gpr=bp_as_gpr,
            def_to_vvid=self._def_to_vvid,
            udef_to_phiid=self._udef_to_phiid,
            phiid_to_loc=self._phiid_to_loc,
        )

        self._visited_blocks: set[Any] = set()
        self.out_blocks = {}

        self._analyze()

        self.out_graph = self._make_new_graph(ail_graph)

    def _make_new_graph(self, old_graph: networkx.DiGraph) -> networkx.DiGraph:
        new_graph = networkx.DiGraph()
        for node in old_graph:
            new_graph.add_node(self.out_blocks.get((node.addr, node.idx), node))

        for src, dst in old_graph.edges:
            new_graph.add_edge(
                self.out_blocks.get((src.addr, src.idx), src), self.out_blocks.get((dst.addr, dst.idx), dst)
            )

        return new_graph

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _initial_abstract_state(self, node) -> RewritingState:
        return RewritingState(
            CodeLocation(node.addr, stmt_idx=0, ins_addr=node.addr, block_idx=node.idx),
            self.project.arch,
            self._function,
            node,
        )

    def _merge_states(self, node: ailment.Block, *states: RewritingState) -> tuple[RewritingState, bool]:
        merged_state = RewritingState(
            CodeLocation(node.addr, stmt_idx=0, ins_addr=node.addr, block_idx=node.idx),
            self.project.arch,
            self._function,
            node,
        )
        merge_occurred = merged_state.merge(node, self._udef_to_phiid, self._phiid_to_loc, *states)
        return merged_state, not merge_occurred

    def _run_on_node(self, node, state: RewritingState):
        """

        :param node:    The current node.
        :param state:   The analysis state.
        :return:        A tuple: (any changes occur, successor state)
        """

        if isinstance(node, ailment.Block):
            block = node
            block_key = (node.addr, node.idx)
            engine = self._engine_ail
        else:
            l.warning("Unsupported node type %s.", node.__class__)
            return False, state

        engine: SimEngineSSARewriting

        old_state = state
        state = old_state.copy()
        state.loc = CodeLocation(block.addr, stmt_idx=0, ins_addr=block.addr, block_idx=block.idx)
        state.original_block = block
        if old_state.out_block is not None:
            state.out_block = old_state.out_block.copy()

        engine.process(
            state,
            block=block,
        )

        self._visited_blocks.add(block_key)

        if state.out_block is not None:
            assert state.out_block.addr == block.addr

            state.insert_phi_statements()
            if self.out_blocks.get(block_key, None) == state.out_block:
                return False, state
            self.out_blocks[block_key] = state.out_block
            state.out_block = None
            return True, state

        return False, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

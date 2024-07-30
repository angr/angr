from __future__ import annotations
from typing import Any
import logging

import ailment

from angr.analyses import ForwardAnalysis
from angr.analyses.forward_analysis.visitors.graph import NodeType
from angr.analyses.forward_analysis import FunctionGraphVisitor
from .traversal_engine import SimEngineSSATraversal
from .traversal_state import TraversalState


l = logging.getLogger(__name__)


class TraversalAnalysis(ForwardAnalysis[None, NodeType, object, object]):
    """
    TraversalAnalysis traverses the AIL graph and collects definitions.
    """

    def __init__(self, project, func, ail_graph, sp_tracker, bp_as_gpr: bool, stackvars: bool):

        self.project = project
        self._stackvars = stackvars
        self._function = func
        self._graph_visitor = FunctionGraphVisitor(self._function, ail_graph)

        ForwardAnalysis.__init__(
            self, order_jobs=True, allow_merging=True, allow_widening=False, graph_visitor=self._graph_visitor
        )
        self._engine_ail = SimEngineSSATraversal(
            self.project.arch,
            sp_tracker=sp_tracker,
            bp_as_gpr=bp_as_gpr,
            stackvars=self._stackvars,
        )

        self._visited_blocks: set[Any] = set()

        self._analyze()

        self.def_to_loc = self._engine_ail.def_to_loc
        self.loc_to_defs = self._engine_ail.loc_to_defs

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _initial_abstract_state(self, node: ailment.Block) -> TraversalState:
        return TraversalState(self.project.arch, self._function)

    def _merge_states(self, node: ailment.Block, *states: TraversalState) -> tuple[TraversalState, bool]:
        merged_state = TraversalState(
            self.project.arch,
            self._function,
            live_registers=states[0].live_registers.copy(),
        )
        merge_occurred = merged_state.merge(*states[1:])
        return merged_state, not merge_occurred

    def _run_on_node(self, node, state: TraversalState):
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

        if block_key in self._visited_blocks:
            # we visit each block exactly once
            return False, state

        engine: SimEngineSSATraversal

        state = state.copy()
        engine.process(state, block=block)

        self._visited_blocks.add(block_key)
        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

from __future__ import annotations
from typing import Any
import logging

import ailment

from angr.analyses import ForwardAnalysis
from angr.analyses.forward_analysis.visitors.graph import NodeType
from angr.analyses.forward_analysis import FunctionGraphVisitor
from .traversal_engine import SimEngineSSATraversal


l = logging.getLogger(__name__)


class TraversalAnalysis(ForwardAnalysis[None, NodeType, object, object]):
    """
    TraversalAnalysis traverses the AIL graph and collects definitions.
    """

    def __init__(self, project, func, ail_graph, sp_tracker, bp_as_gpr: bool):

        self.project = project
        self._function = func
        self._graph_visitor = FunctionGraphVisitor(self._function, ail_graph)

        ForwardAnalysis.__init__(
            self, order_jobs=False, allow_merging=False, allow_widening=False, graph_visitor=self._graph_visitor
        )
        self._engine_ail = SimEngineSSATraversal(
            self.project.arch,
            sp_tracker=sp_tracker,
            bp_as_gpr=bp_as_gpr,
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

    def _initial_abstract_state(self, node) -> None:
        return None

    def _run_on_node(self, node, state: None):
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
            return False, None

        if block_key in self._visited_blocks:
            # we visit each block exactly once
            return False, None

        engine: SimEngineSSATraversal

        engine.process(
            None,
            block=block,
        )

        self._visited_blocks.add(block_key)
        return True, None

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

from __future__ import annotations
from typing import Any
import logging

import networkx

import ailment

from angr.utils.ail import is_phi_assignment
from angr.analyses import ForwardAnalysis
from angr.analyses.forward_analysis.visitors.graph import NodeType
from angr.analyses.forward_analysis import FunctionGraphVisitor
from .rewriting_engine import SimEngineDephiRewriting


l = logging.getLogger(__name__)


class GraphRewritingAnalysis(ForwardAnalysis[None, NodeType, object, object]):
    """
    This analysis traverses the AIL graph and rewrites virtual variables accordingly.
    """

    def __init__(
        self,
        project,
        func,
        ail_graph,
        vvar_to_vvar: dict[int, int],
    ):
        self.project = project
        self._function = func
        self._graph_visitor = FunctionGraphVisitor(self._function, ail_graph)

        ForwardAnalysis.__init__(
            self, order_jobs=False, allow_merging=False, allow_widening=False, graph_visitor=self._graph_visitor
        )
        self._graph = ail_graph
        self._vvar_to_vvar = vvar_to_vvar
        self._engine_ail = SimEngineDephiRewriting(self.project.arch, self._vvar_to_vvar)

        self._visited_blocks: set[Any] = set()
        self.out_blocks = {}

        self._analyze()

        # remove phi statements
        # modifying blocks inline should be fine here - no one has ever used these blocks
        for block in self.out_blocks.values():
            block.statements = [stmt for stmt in block.statements if not is_phi_assignment(stmt)]

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
            return False, None

        engine: SimEngineDephiRewriting
        engine.out_block = None
        engine.process(None, block=block)

        self._visited_blocks.add(block_key)

        if engine.out_block is not None:
            assert engine.out_block.addr == block.addr

            if self.out_blocks.get(block_key, None) == engine.out_block:
                return True, None
            self.out_blocks[block_key] = engine.out_block
            engine.out_block = None
            return True, None

        return True, None

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

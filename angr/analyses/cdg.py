from __future__ import annotations
import logging

import networkx

from ..utils.graph import compute_dominance_frontier, PostDominators, TemporaryNode
from . import Analysis

_l = logging.getLogger(name=__name__)


class CDG(Analysis):
    """
    Implements a control dependence graph.
    """

    def __init__(self, cfg, start=None, no_construct=False):
        """
        Constructor.

        :param cfg:             The control flow graph upon which this control dependence graph will build
        :param start:           The starting point to begin constructing the control dependence graph
        :param no_construct:    Skip the construction step. Only used in unit-testing.
        """
        self._start = start if start is not None else self.project.entry
        self._cfg = cfg

        self._ancestor = None
        self._semi = None
        self._post_dom: networkx.DiGraph | None = None

        self._graph: networkx.DiGraph | None = None
        self._normalized_cfg = None

        if not no_construct:
            if self._cfg is None:
                # This leads to import cycles otherwise
                # pylint: disable=import-outside-toplevel
                from angr.analyses.cfg.cfg_emulated import CFGEmulated

                self._cfg = self.project.analyses[CFGEmulated].prep()()

            # FIXME: We should not use get_any_irsb in such a real setting...
            self._entry = self._cfg.model.get_any_node(self._start)

            self._construct()

    #
    # Properties
    #

    @property
    def graph(self):
        return self._graph

    #
    # Public methods
    #

    def get_post_dominators(self):
        """
        Return the post-dom tree
        """
        return self._post_dom

    def get_dependants(self, run):
        """
        Return a list of nodes that are control dependent on the given node in the control dependence graph
        """
        if run in self._graph.nodes():
            return list(self._graph.successors(run))
        return []

    def get_guardians(self, run):
        """
        Return a list of nodes on whom the specific node is control dependent in the control dependence graph
        """
        if run in self._graph.nodes():
            return list(self._graph.predecessors(run))
        return []

    #
    # Private methods
    #

    def _construct(self):
        """
        Construct a control dependence graph.

        This implementation is based on figure 6 of paper An Efficient Method of Computing Static Single Assignment
        Form by Ron Cytron, etc.
        """

        if not self._cfg._model.ident.startswith("CFGEmulated"):
            raise ValueError("CDG is only supported by CFGEmulated.")

        self._acyclic_cfg = self._cfg.copy()
        # TODO: Cycle-removing is not needed - confirm it later
        # The CFG we use should be acyclic!
        # self._acyclic_cfg.remove_cycles()

        # Pre-process the acyclic CFG
        self._pre_process_cfg()

        # Construct post-dominator tree
        self._pd_construct()

        self._graph: networkx.DiGraph = networkx.DiGraph()

        # Construct the reversed dominance frontier mapping
        rdf = compute_dominance_frontier(self._normalized_cfg, self._post_dom)

        for y in self._cfg.graph.nodes():
            if y not in rdf:
                continue
            for x in rdf[y]:
                self._graph.add_edge(x, y)

        # self._post_process()

    def _pre_process_cfg(self):
        """
        Pre-process the acyclic CFG.
        - Change all FakeRet edges to normal edges when necessary (e.g. the normal/expected return edge does not exist)
        """
        for _, dst, data in self._acyclic_cfg.graph.edges(data=True):
            if "jumpkind" in data and data["jumpkind"] == "Ijk_FakeRet":
                all_edges_to_dst = self._acyclic_cfg.graph.in_edges([dst], data=True)
                if not any((s, d) for s, d, da in all_edges_to_dst if da["jumpkind"] != "Ijk_FakeRet"):
                    # All in edges are FakeRets
                    # Change them to a normal edge
                    for _, _, data_ in all_edges_to_dst:
                        data_["jumpkind"] = "Ijk_Boring"

    def _post_process(self):
        """
        There are cases where a loop has two overlapping loop headers thanks
        to the way VEX is dealing with continuous instructions. As we were
        breaking the connection between the second loop header and its
        successor, we shall restore them in our CDG.
        """
        # TODO: Verify its correctness
        loop_back_edges = self._cfg.get_loop_back_edges()
        for b1, b2 in loop_back_edges:
            self._graph.add_edge(b1, b2)

    #
    # Post-dominator tree related
    #

    def _pd_construct(self):
        pdoms = PostDominators(self._acyclic_cfg, self._entry, successors_func=self._pd_graph_successors)

        self._post_dom = pdoms.post_dom

        self._pd_post_process(self._acyclic_cfg)

        # Create the normalized_cfg without the annoying ContainerNodes
        self._normalized_cfg = networkx.DiGraph()
        for src, dst in pdoms.prepared_graph.edges():
            self._normalized_cfg.add_edge(src.obj, dst.obj)

    @staticmethod
    def _pd_graph_successors(graph, node):
        # The true condition is for testing
        return graph.graph.successors(node) if type(node) is TemporaryNode else graph.model.get_successors(node)

    def _pd_post_process(self, cfg):
        """
        Take care of those loop headers/tails where we manually broke their
        connection to the next BBL
        """
        loop_back_edges = self._cfg.get_loop_back_edges()

        for b1, b2 in loop_back_edges:
            # The edge between b1 and b2 is manually broken
            # The post dominator of b1 should be b2 (or not?)

            successors = list(self._pd_graph_successors(cfg, b1))

            if len(successors) == 0:
                if b2 in self._post_dom:
                    self._post_dom.add_edge(b1, b2)
                else:
                    _l.debug("%s is not in post dominator dict.", b2)


from angr.analyses import AnalysesHub

AnalysesHub.register_default("CDG", CDG)

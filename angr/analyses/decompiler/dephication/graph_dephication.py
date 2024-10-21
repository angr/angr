from __future__ import annotations
import logging
from collections import defaultdict

import networkx

from ailment.expression import Phi, VirtualVariable
from ailment.statement import Assignment

from angr.knowledge_plugins.functions import Function
from angr.analyses import register_analysis
from .graph_rewriting import GraphRewritingAnalysis
from .dephication_base import DephicationBase

l = logging.getLogger(name=__name__)


class GraphDephication(DephicationBase):  # pylint:disable=abstract-method
    """
    GraphDephication removes phi expressions from an AIL graph, essentially transforms a partial-SSA form of AIL graph
    to a normal AIL graph.
    """

    def __init__(
        self,
        func: Function | str,
        ail_graph,
        vvar_to_vvar_mapping: dict[int, int] | None = None,
        rewrite: bool = False,
    ):
        """
        :param func:                            The subject of the analysis: a function, or a single basic block
        :param ail_graph:                       The AIL graph to transform.
        """

        self._graph = ail_graph

        super().__init__(func, vvar_to_vvar_mapping=vvar_to_vvar_mapping, rewrite=rewrite)

        self._analyze()

    def _collect_phi_assignments(self) -> dict[int, set[int]]:
        g = self._graph
        phi_to_src = defaultdict(set)

        for block in g:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi):
                    for _, vvar in stmt.src.src_and_vvars:
                        if vvar is None:
                            l.debug("Invalid vvar None found in %r.src.src_and_vvars.", stmt)
                        else:
                            phi_to_src[stmt.dst.varid].add(vvar.varid)

        return phi_to_src

    def _rewrite_container(self) -> networkx.DiGraph:
        # replace all vvars with phi variables in the graph
        rewriter = GraphRewritingAnalysis(self.project, self._function, self._graph, self.vvar_to_vvar_mapping)
        return rewriter.out_graph


register_analysis(GraphDephication, "GraphDephication")

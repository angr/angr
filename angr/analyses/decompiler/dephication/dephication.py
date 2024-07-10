from __future__ import annotations
import logging
from collections import defaultdict

import networkx

from ailment.expression import Phi, VirtualVariable
from ailment.statement import Assignment

from angr.knowledge_plugins.functions import Function
from angr.analyses import Analysis, register_analysis
from .rewriting import RewritingAnalysis

l = logging.getLogger(name=__name__)


class Dephication(Analysis):  # pylint:disable=abstract-method
    """
    Dephication removes phi expressions from an AIL graph, essentially transforms a partial-SSA form of AIL graph to a
    normal AIL graph.
    """

    def __init__(
        self,
        func: Function | str,
        ail_graph,
    ):
        """
        :param func:                            The subject of the analysis: a function, or a single basic block
        :param ail_graph:                       The AIL graph to transform.
        """

        if isinstance(func, str):
            self._function = self.kb.functions[func]
        else:
            self._function = func

        self.out_graph = self._collect_and_rewrite(ail_graph)

    def _collect_and_rewrite(self, g: networkx.DiGraph) -> networkx.DiGraph:
        # collect phi assignments
        phi_to_srcvarid = self._collect_phi_assignments(g)

        vvar_to_vvar = {}
        for phi_varid, varids in phi_to_srcvarid.items():
            for varid in varids:
                if varid in vvar_to_vvar:
                    l.warning(
                        "VVar %d is already mapped to another VVar (%d). This means Phi assignment is incorrect.",
                        varid,
                        vvar_to_vvar[varid],
                    )
                    continue
                vvar_to_vvar[varid] = phi_varid

        # replace all vvars with phi variables
        rewriter = RewritingAnalysis(self.project, self._function, g, vvar_to_vvar)
        return rewriter.out_graph

    def _collect_phi_assignments(self, g: networkx.DiGraph) -> dict[int, set[int]]:
        phi_to_src = defaultdict(set)

        for block in g:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi):
                    for _, vvar in stmt.src.src_and_vvars:
                        if vvar is None:
                            l.warning("Invalid vvar None found in %r.src.src_and_vvars.", stmt)
                        else:
                            phi_to_src[stmt.dst.varid].add(vvar.varid)

        return phi_to_src


register_analysis(Dephication, "Dephication")

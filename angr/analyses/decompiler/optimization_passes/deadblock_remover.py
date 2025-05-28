# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
import logging

import networkx

import claripy

from angr.ailment.statement import Jump
from angr.ailment.expression import Const
from angr.utils.graph import to_acyclic_graph
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


class DeadblockRemover(OptimizationPass):
    """
    Removes condition-unreachable blocks from the graph.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_REGION_IDENTIFICATION
    NAME = "Remove blocks with unsatisfiable conditions"
    DESCRIPTION = __doc__.strip()  # type: ignore

    def __init__(self, func, node_cutoff: int = 200, **kwargs):
        super().__init__(func, **kwargs)
        self._node_cutoff = node_cutoff
        self.analyze()

    def _check(self):
        # don't run this optimization on super large functions
        assert self._graph is not None
        if len(self._graph) >= self._node_cutoff:
            return False, None

        cond_proc = ConditionProcessor(self.project.arch)
        if networkx.is_directed_acyclic_graph(self._graph):
            acyclic_graph = self._graph
        else:
            acyclic_graph = to_acyclic_graph(self._graph)
        cond_proc.recover_reaching_conditions(region=None, graph=acyclic_graph, simplify_conditions=False)

        if not any(claripy.is_false(c) for c in cond_proc.reaching_conditions.values()):
            return False, None

        cache = {"cond_proc": cond_proc}
        return True, cache

    def _analyze(self, cache: dict | None = None):
        assert cache is not None
        assert self._graph is not None

        cond_proc = cache["cond_proc"]
        to_remove = {
            blk
            for blk in self._graph.nodes()
            if (blk.addr != self._func.addr and self._graph.in_degree(blk) == 0)
            or claripy.is_false(cond_proc.reaching_conditions[blk])
        }

        # fix up predecessors
        for b in to_remove:
            for p in self._graph.predecessors(b):
                if self._graph.out_degree(p) != 2:
                    continue
                other_successor = next(s for s in self._graph.successors(p) if s != b)
                p.statements[-1] = Jump(
                    None,
                    Const(None, None, other_successor.addr, self.project.arch.bits),
                    other_successor.idx,
                    **p.statements[-1].tags,
                )

        for n in to_remove:
            self._graph.remove_node(n)

        self.out_graph = self._graph

# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

import logging

import networkx

from angr import claripy
from angr.ailment.expression import Const
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.utils.graph import to_acyclic_graph

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
    DESCRIPTION = (__doc__ or "").strip()

    def __init__(self, *args, node_cutoff: int = 200, **kwargs):
        super().__init__(*args, **kwargs)
        self._node_cutoff = node_cutoff
        self.analyze()

    def _check(self):
        # don't run this optimization on super large functions
        assert self._graph is not None
        if len(self._graph) >= self._node_cutoff:
            return False, None

        if networkx.is_directed_acyclic_graph(self._graph):
            acyclic_graph = self._graph
        else:
            acyclic_graph = to_acyclic_graph(self._graph)

        # recover_reaching_conditions() takes the head of a graph to be a node with no in-edges, so the
        # conditions below are about the entry block only when the entry block is one of those.
        entry_block = next((blk for blk in acyclic_graph if (blk.addr, blk.idx) == self.entry_node_addr), None)
        if entry_block is None or acyclic_graph.in_degree(entry_block) != 0:
            return False, None

        cond_proc = ConditionProcessor(self.project.arch, self.manager)
        cond_proc.recover_reaching_conditions(region=None, graph=acyclic_graph, simplify_conditions=False)

        dead_edges = self._find_dead_edges(cond_proc, acyclic_graph)
        if not dead_edges and not any(claripy.is_false(c) for c in cond_proc.reaching_conditions.values()):
            return False, None

        cache = {"cond_proc": cond_proc, "dead_edges": dead_edges}
        return True, cache

    def _find_dead_edges(self, cond_proc: ConditionProcessor, acyclic_graph: networkx.DiGraph) -> list[tuple]:
        """
        Find conditional-jump edges whose condition contradicts the jump into their (single-predecessor) source block,
        e.g. ``if (x != c) { if (x == c) goto A; }`` after a flag-join block is duplicated into its predecessors.
        """
        assert self._graph is not None
        in_cycle = set()
        for scc in networkx.strongly_connected_components(self._graph):
            if len(scc) > 1:
                in_cycle |= scc
        dead_edges = []
        for src in self._graph:
            if src in in_cycle or not src.statements or not isinstance(src.statements[-1], ConditionalJump):
                continue
            preds = list(self._graph.predecessors(src))
            succs = list(self._graph.successors(src))
            if len(preds) != 1 or len(succs) != 2 or not acyclic_graph.has_edge(preds[0], src):
                continue
            if any(not acyclic_graph.has_edge(src, succ) for succ in succs):
                continue
            # only syntactic contradictions with the jump into src: FP compares are modelled as bit-vector compares,
            # so range reasoning over them would be unsound
            in_cond = cond_proc.recover_edge_condition(acyclic_graph, preds[0], src)
            conjuncts = in_cond.args if in_cond.op == "And" else (in_cond,)
            for succ in succs:
                neg_edge_cond = claripy.Not(cond_proc.recover_edge_condition(acyclic_graph, src, succ))
                if any(c.hash() == neg_edge_cond.hash() for c in conjuncts):
                    dead_edges.append((src, succ))
                    break
        return dead_edges

    def _analyze(self, cache: dict | None = None):
        assert cache is not None
        assert self._graph is not None

        cond_proc = cache["cond_proc"]
        for src, dead_succ in cache["dead_edges"]:
            other_successor = next(s for s in self._graph.successors(src) if s is not dead_succ)
            src.statements[-1] = Jump(
                self.manager.next_atom(),
                Const(self.manager.next_atom(), other_successor.addr, self.project.arch.bits),
                other_successor.idx,
                **src.statements[-1].tags,
            )
            self._graph.remove_edge(src, dead_succ)
        if cache["dead_edges"]:
            # drop whatever is now only reachable through the removed edges
            heads = [n for n in self._graph if n.addr == self._func.addr]
            if len(heads) == 1:
                reachable = networkx.descendants(self._graph, heads[0]) | {heads[0]}
                self._graph.remove_nodes_from([n for n in self._graph if n not in reachable])

        to_remove = {
            blk
            for blk in self._graph.nodes()
            if (blk.addr != self._func.addr and self._graph.in_degree(blk) == 0)
            or claripy.is_false(cond_proc.reaching_conditions.get(blk, claripy.true()))
        }

        # fix up predecessors
        for b in to_remove:
            for p in self._graph.predecessors(b):
                if self._graph.out_degree(p) != 2:
                    continue
                other_successor = next(s for s in self._graph.successors(p) if s != b)
                p.statements[-1] = Jump(
                    self.manager.next_atom(),
                    Const(self.manager.next_atom(), other_successor.addr, self.project.arch.bits),
                    other_successor.idx,
                    **p.statements[-1].tags,
                )

        for n in to_remove:
            self._graph.remove_node(n)

        self.out_graph = self._graph

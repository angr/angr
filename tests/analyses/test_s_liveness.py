#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os.path
import unittest
from unittest import mock

import networkx

import angr
from angr.ailment.expression import VirtualVariable
from angr.ailment.statement import Assignment, SideEffectStatement
from angr.analyses.s_liveness import SLivenessAnalysis
from angr.utils.ail import is_phi_assignment
from angr.utils.ssa import VVarUsesCollector
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSLiveness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(test_location, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()
        cls.proj = proj
        cls.cfg = cfg
        cls.graphs = {}
        for name in ("main", "verify_password", "doit", "read_str"):
            func = proj.kb.functions[name]
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
            assert dec.ail_graph is not None
            entry = next(b for b in dec.ail_graph if b.addr == func.addr and b.idx is None)
            cls.graphs[name] = (func, dec.ail_graph, entry)

    def _liveness(self, name):
        func, graph, entry = self.graphs[name]
        return graph, self.proj.analyses[SLivenessAnalysis].prep()(func, func_graph=graph, entry=entry, arg_vvars=[])

    def test_live_ins_propagate_to_predecessor_live_outs(self):
        """The worklist must run to a fixpoint, not stop early."""
        for name in self.graphs:
            graph, liveness = self._liveness(name)
            for block in graph:
                for succ in graph.successors(block):
                    if any(is_phi_assignment(stmt) for stmt in succ.statements):
                        # a phi block's live-in is per-predecessor, tracked on the edge
                        continue
                    if block is succ:
                        continue
                    live_in = liveness.model.live_ins[succ.addr, succ.idx]
                    live_out = liveness.model.live_outs[block.addr, block.idx]
                    assert live_in <= live_out, (
                        f"{name}: {succ.addr:#x} live-in leaks past {block.addr:#x} live-out: "
                        f"{sorted(live_in - live_out)}"
                    )

    def test_vars_used_before_definition_are_live_in(self):
        """The defining property of liveness, checked block by block."""
        collector = VVarUsesCollector()
        for name in self.graphs:
            graph, liveness = self._liveness(name)
            for block in graph:
                defined: set[int] = set()
                live_in = liveness.model.live_ins[block.addr, block.idx]
                for stmt in block.statements:
                    if is_phi_assignment(stmt):
                        # phi operands come from specific predecessors, not from live-in
                        assert isinstance(stmt, Assignment)
                        defined.add(stmt.dst.varid)
                        continue
                    collector.reset()
                    collector.walk_statement(stmt)
                    for varid in collector.vvars - defined:
                        assert varid in live_in, (
                            f"{name}: vvar {varid} is used at {block.addr:#x} before any definition "
                            f"but is not live-in there"
                        )
                    if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                        defined.add(stmt.dst.varid)
                    elif isinstance(stmt, SideEffectStatement) and isinstance(stmt.ret_expr, VirtualVariable):
                        defined.add(stmt.ret_expr.varid)

    def test_worklist_does_not_traverse_the_graph_per_update(self):
        """One ordering DFS for the whole analysis, not one per changed block.

        Liveness is backward, so a block that changes only needs its predecessors
        re-queued. Re-deriving the reachable set every time made this quadratic:
        on a 2215-block function it visited 1.4M nodes, 639x the graph.
        """
        func, graph, entry = self.graphs["main"]
        real = networkx.dfs_postorder_nodes
        calls = []

        def counting(G, source=None, depth_limit=None):
            calls.append(source)
            return real(G, source=source, depth_limit=depth_limit)

        with mock.patch.object(networkx, "dfs_postorder_nodes", counting):
            self.proj.analyses[SLivenessAnalysis].prep()(func, func_graph=graph, entry=entry, arg_vvars=[])

        assert len(calls) == 1, f"expected a single ordering traversal, got {len(calls)}"
        assert calls[0] is entry

    def test_result_is_independent_of_run(self):
        """The worklist order must not leak into the result."""
        for name in self.graphs:
            _, first = self._liveness(name)
            _, second = self._liveness(name)
            assert first.model.live_ins == second.model.live_ins
            assert first.model.live_outs == second.model.live_outs
            assert first.model.block_end_vvars == second.model.block_end_vvars


if __name__ == "__main__":
    unittest.main()

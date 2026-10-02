#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os.path
import unittest
from unittest import mock

import networkx

import angr
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return, SideEffectStatement
from angr.analyses.s_liveness import SLivenessAnalysis
from angr.utils.ail import is_phi_assignment
from angr.utils.ssa import VVarUsesCollector
from angr.utils.vvar_set import VVarSet
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


class TestInterferenceGraphRestriction(unittest.TestCase):
    """interference_graph(vvar_ids=...) must be the induced subgraph of the full graph, built without touching the rest."""

    @staticmethod
    def _vvar(varid: int) -> VirtualVariable:
        return VirtualVariable(varid, varid, 64, VirtualVariableCategory.REGISTER, oident=16)

    def _liveness(self):
        v = self._vvar
        # v1 and v2 interfere with v3's definition site; v2 is dead once v3 is defined
        stmts = [
            Assignment(0, v(1), Const(0, 1, 64), ins_addr=0x400000),
            Assignment(1, v(2), Const(1, 2, 64), ins_addr=0x400001),
            Assignment(2, v(3), BinaryOp(2, "Add", [v(1), v(2)], bits=64), ins_addr=0x400002),
            Assignment(3, v(4), BinaryOp(3, "Add", [v(1), v(3)], bits=64), ins_addr=0x400003),
            Return(4, [v(4)], ins_addr=0x400004),
        ]
        block = Block(0x400000, 5, statements=stmts)
        graph = networkx.DiGraph()
        graph.add_node(block)
        proj = angr.load_shellcode(b"\x90", arch="AMD64")
        func = proj.kb.functions.function(addr=0x400000, name="dummy", create=True)
        return proj.analyses[SLivenessAnalysis].prep()(func, func_graph=graph, entry=block, arg_vvars=[])

    @staticmethod
    def _edges(graph: networkx.Graph) -> set[frozenset[int]]:
        return {frozenset(e) for e in graph.edges}

    def test_restricted_graph_is_the_induced_subgraph(self):
        liveness = self._liveness()
        full = liveness.interference_graph()
        assert frozenset({1, 3}) in self._edges(full)
        assert frozenset({2, 3}) not in self._edges(full)

        for vvar_ids in ({1, 3}, {2, 3}, {1, 2, 3, 4}, {4}, {99}):
            restricted = liveness.interference_graph(vvar_ids=vvar_ids)
            assert set(restricted.nodes) <= vvar_ids
            assert self._edges(restricted) == self._edges(full.subgraph(vvar_ids))

    def test_empty_restriction_builds_nothing(self):
        liveness = self._liveness()
        with mock.patch.object(VVarUsesCollector, "walk_statement") as walk:
            graph = liveness.interference_graph(vvar_ids=set())
        assert graph.number_of_nodes() == 0
        walk.assert_not_called()


class TestInterferenceGraphFilter(unittest.TestCase):
    """
    The vvar_ids filter of interference_graph must be converted to a VVarSet once. Intersecting the live VVarSet with
    a plain set rebuilds the bitmask for every defining statement, which is quadratic on large functions (the Go
    endpoints.init function took 73 minutes in dephication alone).
    """

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(test_location, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()
        func = proj.kb.functions["doit"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.ail_graph is not None
        entry = next(b for b in dec.ail_graph if b.addr == func.addr and b.idx is None)
        cls.liveness = proj.analyses[SLivenessAnalysis].prep()(
            func, func_graph=dec.ail_graph, entry=entry, arg_vvars=[]
        )

    def test_plain_set_filter_is_converted_once(self):
        full = self.liveness.interference_graph()
        assert full.number_of_edges() > 0
        vvar_ids = set(full.nodes())

        orig_to_bits = VVarSet._to_bits  # pylint:disable=protected-access
        with mock.patch.object(VVarSet, "_to_bits", side_effect=orig_to_bits) as to_bits:
            filtered = self.liveness.interference_graph(vvar_ids=vvar_ids)
        conversions = sum(1 for call in to_bits.call_args_list if call.args[0] is vvar_ids)
        assert conversions == 0, f"the plain-set filter was converted {conversions} times"

        assert set(filtered.edges()) == set(full.edges())
        assert set(self.liveness.interference_graph(vvar_ids=VVarSet(vvar_ids)).edges()) == set(full.edges())


if __name__ == "__main__":
    unittest.main()

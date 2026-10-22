#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest
from collections import Counter
from unittest import TestCase, mock

import networkx

import angr
from angr import claripy
from angr.analyses.decompiler import condition_processor as cp_module
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.utils.graph import dfs_preorder_nodes
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _oracle_guarding_conditions(graph: networkx.DiGraph, inverted_graph: networkx.DiGraph, edge_conditions: dict):
    # the loop that recover_reaching_conditions ran before reachability was looked up in the slice set: one
    # networkx.has_path per successor of every slice node
    guarding_conditions = {}
    for the_node in graph:
        if len(list(graph.predecessors(the_node))) != 2:
            continue
        slice_nodes = list(networkx.dfs_tree(inverted_graph, the_node))
        subgraph = networkx.subgraph(graph, slice_nodes)
        nodes_do_not_reach_the_node = set()
        for node_ in subgraph:
            if node_ is the_node:
                continue
            for succ in graph.successors(node_):
                if not networkx.has_path(graph, succ, the_node):
                    nodes_do_not_reach_the_node.add(succ)
        diverging_conditions = []
        for node_ in nodes_do_not_reach_the_node:
            for pred_ in list(graph.predecessors(node_)):
                if pred_ in nodes_do_not_reach_the_node:
                    continue
                edge_condition = edge_conditions.get((pred_, node_))
                if edge_condition is not None:
                    diverging_conditions.append(edge_condition)
        if diverging_conditions:
            guarding_conditions[the_node] = claripy.Or(*map(claripy.Not, diverging_conditions))
    return guarding_conditions


class TestGuardingConditionsReachability(TestCase):
    def test_guarding_conditions_match_the_has_path_oracle(self):
        # BudgIT main: a 53-node acyclic graph with 14 two-predecessor nodes, 9 of them guarded
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "BudgIT")

        captured: dict = {}
        counts: Counter = Counter()
        guarded: list[int] = []

        real_inverted_idoms = cp_module.inverted_idoms
        real_recover_edge_conditions = ConditionProcessor.recover_edge_conditions
        real_recover_reaching_conditions = ConditionProcessor.recover_reaching_conditions

        def recording_inverted_idoms(graph, *args, **kwargs):
            result = real_inverted_idoms(graph, *args, **kwargs)
            captured["graph"], captured["inverted_graph"] = graph, result[0]
            return result

        def recording_recover_edge_conditions(self, *args, **kwargs):
            captured["edge_conditions"] = real_recover_edge_conditions(self, *args, **kwargs)
            return captured["edge_conditions"]

        def checking_recover_reaching_conditions(self, *args, **kwargs):
            real_recover_reaching_conditions(self, *args, **kwargs)
            graph, inverted_graph = captured["graph"], captured["inverted_graph"]
            for node in graph:
                if graph.in_degree(node) == 2:
                    assert dfs_preorder_nodes(inverted_graph, node) == list(networkx.dfs_tree(inverted_graph, node))
            expected = _oracle_guarding_conditions(graph, inverted_graph, captured["edge_conditions"])
            assert {n: str(c) for n, c in self.guarding_conditions.items()} == {n: str(c) for n, c in expected.items()}
            guarded.append(len(expected))

        class CountingNetworkx:
            def __getattr__(self, name):
                counts[name] += 1
                return getattr(networkx, name)

        with (
            mock.patch.object(cp_module, "networkx", CountingNetworkx()),
            mock.patch.object(cp_module, "inverted_idoms", recording_inverted_idoms),
            mock.patch.object(ConditionProcessor, "recover_edge_conditions", recording_recover_edge_conditions),
            mock.patch.object(ConditionProcessor, "recover_reaching_conditions", checking_recover_reaching_conditions),
        ):
            proj = angr.Project(bin_path, auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)
            dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg.model, fail_fast=True)

        assert dec.codegen is not None and dec.codegen.text
        assert sum(guarded) >= 5
        assert counts["has_path"] == 0
        assert counts["dfs_tree"] == 0
        assert counts["subgraph"] == 0

    def test_dfs_preorder_nodes_follows_networkx_dfs_tree_order(self):
        # a reversed diamond with a dummy sink that has no in-edges, as inverted_idoms builds it
        graph = networkx.DiGraph([(4, 3), (4, 2), (3, 1), (2, 1), (1, 0), ("DUMMY_NODE", 4), (5, 2)])
        for source in (4, 3, 2, 1, 0):
            assert dfs_preorder_nodes(graph, source) == list(networkx.dfs_tree(graph, source))
        assert "DUMMY_NODE" not in dfs_preorder_nodes(graph, 4)


if __name__ == "__main__":
    unittest.main()

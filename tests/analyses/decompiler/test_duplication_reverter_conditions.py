#!/usr/bin/env python3
from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use,protected-access
import os.path
import unittest
from unittest import TestCase
from unittest.mock import patch

import networkx as nx

from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.optimization_passes.duplication_reverter.duplication_reverter import DuplicationReverter
from tests.common import bin_location, load_project_with_scoped_cfg

# sub_140003a50 tries four duplication candidates; their blocks are guarded through guarding conditions as well as
# reaching conditions, and one reaching condition is wider than simplify_condition() accepts.
CANCEL_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "cancel.sys")
CANCEL_FUNC = 0x140003A50


def _reference_conditions(cond_proc: ConditionProcessor, graph: nx.DiGraph, source, sinks, max_depth=15) -> dict:
    """
    collect_conditions_between_nodes() as it was before the per-node simplification became selective: every node of
    the path subgraph is simplified, then each sink is read.
    """
    graph_nodes = set(sinks)
    for sink in set(sinks):
        paths_between = nx.all_simple_paths(graph, source=source, target=sink, cutoff=max_depth)
        graph_nodes.update({node for path in paths_between for node in path})
    full_condition_graph = nx.DiGraph(nx.subgraph(graph, graph_nodes))
    while True:
        try:
            cycles = nx.find_cycle(full_condition_graph)
        except nx.NetworkXNoCycle:
            break
        full_condition_graph.remove_edge(*cycles[0])

    cond_proc.recover_reaching_conditions(None, graph=full_condition_graph)
    conditions = {}
    for sink in sinks:
        if sink in cond_proc.guarding_conditions:
            condition = cond_proc.guarding_conditions[sink]
        else:
            condition = cond_proc.reaching_conditions[sink]
        condition = ConditionProcessor.simplify_condition(condition)
        if condition.is_true() or condition.is_false():
            condition = ConditionProcessor.simplify_condition(cond_proc.reaching_conditions[sink])
        conditions[sink] = cond_proc.convert_claripy_bool_ast(condition)
    return conditions


class TestDuplicationReverterConditions(TestCase):
    def test_selective_simplification_keeps_the_sink_conditions(self):
        proj, cfg = load_project_with_scoped_cfg(CANCEL_BIN, CANCEL_FUNC)
        func = cfg.functions[CANCEL_FUNC]

        simplify_calls = {"n": 0}
        orig_simplify = ConditionProcessor.simplify_condition

        def simplify(cond, *args, **kwargs):
            simplify_calls["n"] += 1
            return orig_simplify(cond, *args, **kwargs)

        counts = {"collect": 0, "sinks": 0, "new": 0, "reference": 0}
        orig_collect = DuplicationReverter.collect_conditions_between_nodes

        def collect(self, graph, source, sinks, max_depth=15):
            before = simplify_calls["n"]
            new = orig_collect(self, graph, source, sinks, max_depth)
            counts["new"] += simplify_calls["n"] - before

            # the reference pays the full cost, like the pass did without a memo
            cond_proc = self._ri.cond_proc
            cond_proc._simplified_conditions.clear()
            before = simplify_calls["n"]
            reference = _reference_conditions(cond_proc, graph, source, sinks, max_depth)
            counts["reference"] += simplify_calls["n"] - before

            assert list(new) == list(reference)
            for sink in sinks:
                assert str(new[sink]) == str(reference[sink]), (sink, new[sink], reference[sink])
            counts["collect"] += 1
            counts["sinks"] += len(sinks)
            return new

        with (
            patch.object(ConditionProcessor, "simplify_condition", staticmethod(simplify)),
            patch.object(DuplicationReverter, "collect_conditions_between_nodes", collect),
        ):
            dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")

        assert dec.codegen is not None and dec.codegen.text
        assert counts["collect"] >= 4 and counts["sinks"] >= 8
        assert 0 < counts["new"] < counts["reference"] // 2, counts


if __name__ == "__main__":
    unittest.main()

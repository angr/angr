#!/usr/bin/env python3
"""Mutation-isolation tests for optimization-pass structurability probes."""

# pylint: disable=protected-access
from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

import networkx

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const
from angr.ailment.statement import Jump, Label
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.optimization_passes.lowered_switch_simplifier import LoweredSwitchSimplifier
from angr.analyses.decompiler.optimization_passes.optimization_pass import StructuringOptimizationPass
from angr.analyses.decompiler.redundant_label_remover import RedundantLabelRemover
from angr.analyses.decompiler.region_identifier import RegionIdentifier
from angr.analyses.decompiler.structurer_nodes import IncompleteSwitchCaseHeadStatement, SequenceNode
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.sim_variable import SimRegisterVariable


class TestStructurabilityProbeIsolation(unittest.TestCase):
    """A read-only structurability check must never leak mutations into its input AIL graph."""

    def test_incomplete_switch_head_block_deep_copy_protocol(self):
        manager = Manager()
        comparator = Block(0x100, 1, statements=[Label(manager.next_atom(), "case", ins_addr=0x100)])
        switch_variable = Const(manager.next_atom(), 3, 64)
        source_stmt = IncompleteSwitchCaseHeadStatement(
            manager.next_atom(),
            switch_variable,
            [(comparator, 3, 0x300, 7, 0x110)],
            peephole_optimized=True,
            ins_addr=0x200,
            extra_defs=[1, 2],
        )
        source = Block(0x200, 1, statements=[cast(Any, source_stmt)])
        variable = SimRegisterVariable(8, 8, ident="switch_var")
        variable_map = variable_map_of(manager)
        variable_map.set_variable(source_stmt, variable, 4)
        variable_map.set_variable(switch_variable, variable, 8)

        source_case_addrs = list(source_stmt.case_addrs)
        source_tags = copy.deepcopy(source_stmt.tags)
        copied = source.deep_copy(manager)
        copied_stmt = copied.statements[0]

        self.assertIsInstance(copied_stmt, IncompleteSwitchCaseHeadStatement)
        assert isinstance(copied_stmt, IncompleteSwitchCaseHeadStatement)
        self.assertNotEqual(copied_stmt.idx, source_stmt.idx)
        self.assertIsNot(copied_stmt.switch_variable, switch_variable)
        self.assertNotEqual(copied_stmt.switch_variable.idx, switch_variable.idx)
        self.assertIs(variable_map.variable(copied_stmt), variable)
        self.assertEqual(variable_map.variable_offset(copied_stmt), 4)
        self.assertIs(variable_map.variable(copied_stmt.switch_variable), variable)
        self.assertEqual(variable_map.variable_offset(copied_stmt.switch_variable), 8)
        self.assertIsNot(copied_stmt.case_addrs, source_stmt.case_addrs)
        self.assertIs(copied_stmt.case_addrs[0][0], comparator)
        self.assertTrue(copied_stmt.peephole_optimized)
        self.assertEqual(copied_stmt.tags, source_tags)

        copied_stmt.case_addrs.append((comparator, "default", 0x400, None, 0x120))
        copied_stmt.tags["extra_defs"].append(3)
        self.assertEqual(source_stmt.case_addrs, source_case_addrs)
        self.assertEqual(source_stmt.tags, source_tags)

    def test_switch_comparator_backrefs_are_isolated_by_probe_graph_copy(self):
        manager = Manager()
        comparator = Block(0x100, 1, statements=[Label(manager.next_atom(), "case", ins_addr=0x100)])
        detached_comparator = Block(0x110, 1, statements=[Label(manager.next_atom(), "detached", ins_addr=0x110)])
        switch_stmt = IncompleteSwitchCaseHeadStatement(
            manager.next_atom(),
            Const(manager.next_atom(), 3, 64),
            [
                (comparator, 3, 0x300, 7, 0x120),
                (detached_comparator, 4, 0x310, 8, 0x130),
                (detached_comparator, 5, 0x320, 9, 0x140),
                (None, "default", 0x330, 10, 0x150),
            ],
            ins_addr=0x200,
        )
        switch_head = Block(0x200, 1, statements=[cast(Any, switch_stmt)])
        graph = networkx.DiGraph()
        graph.add_nodes_from((switch_head, comparator))
        probe = object.__new__(StructuringOptimizationPass)
        probe.manager = manager

        probe_manager = probe._manager_for_structurability_probe()
        copied_graph = probe._deepcopy_ail_graph_for_probe(graph, probe_manager)
        copied_head = next(block for block in copied_graph if block.addr == switch_head.addr)
        copied_graph_comparator = next(block for block in copied_graph if block.addr == comparator.addr)
        copied_stmt = cast(IncompleteSwitchCaseHeadStatement, copied_head.statements[0])
        copied_comparator = copied_stmt.case_addrs[0][0]
        first_detached_copy = copied_stmt.case_addrs[1][0]
        second_detached_copy = copied_stmt.case_addrs[2][0]

        self.assertIsNot(copied_head, switch_head)
        assert copied_comparator is not None
        assert first_detached_copy is not None
        self.assertIs(copied_comparator, copied_graph_comparator)
        self.assertIsNot(copied_graph_comparator, comparator)
        self.assertIsNot(copied_comparator.statements[0], comparator.statements[0])
        self.assertEqual(copied_comparator.addr, comparator.addr)
        self.assertIs(first_detached_copy, second_detached_copy)
        self.assertIsNot(first_detached_copy, detached_comparator)
        self.assertIsNone(copied_stmt.case_addrs[3][0])

    def test_probe_uses_local_manager_variable_map_and_condition_processor(self):
        manager = Manager()
        source_jump = Jump(
            manager.next_atom(),
            Const(manager.next_atom(), 0x300, 64),
            target_idx=7,
            ins_addr=0x100,
        )
        source = Block(0x100, 1, statements=[source_jump])
        target = Block(0x300, 1, statements=[], idx=7)
        graph = networkx.DiGraph([(source, target)])
        jump_variable = SimRegisterVariable(8, 8, ident="jump")
        target_variable = SimRegisterVariable(16, 8, ident="target")
        variable_map = variable_map_of(manager)
        variable_map.set_variable(source_jump, jump_variable, 4)
        variable_map.set_variable(source_jump.target, target_variable, 8)

        live_cond_proc = ConditionProcessor(None, manager)
        live_cond_proc._condition_mapping["seed"] = "condition"
        live_cond_proc.jump_table_conds[0x100].add("jump-table")
        live_cond_proc.reaching_conditions["node"] = "reaching"
        live_cond_proc.guarding_conditions["node"] = "guarding"
        live_cond_proc._ast2annotations["ast"] = "annotation"

        live_atom_ctr = manager.atom_ctr
        variable_map_snapshot = {slot: copy.deepcopy(getattr(variable_map, slot)) for slot in variable_map.__slots__}
        cond_proc_snapshot = {
            name: copy.deepcopy(getattr(live_cond_proc, name))
            for name in (
                "_condition_mapping",
                "jump_table_conds",
                "reaching_conditions",
                "guarding_conditions",
                "_ast2annotations",
            )
        }
        captured = {}

        def _region_identifier(_function, *, graph, ail_manager, cond_proc, **_kwargs):
            captured["graph"] = graph
            captured["manager"] = ail_manager
            captured["cond_proc"] = cond_proc

        analysis_factory = MagicMock()
        analysis_factory.prep.return_value = _region_identifier
        analyses = MagicMock()
        analyses.__getitem__.return_value = analysis_factory
        probe = object.__new__(StructuringOptimizationPass)
        probe.manager = manager
        project = SimpleNamespace(analyses=analyses, kb=SimpleNamespace(), arch=None)
        cast(Any, probe)._func = SimpleNamespace(name="probe", addr=source.addr, project=project)
        cast(Any, probe)._ri = SimpleNamespace(cond_proc=live_cond_proc)
        probe.entry_node_addr = (source.addr, None)
        probe._edges_to_remove = []

        self.assertEqual(probe._compute_structurability(graph, True), (False, None, None, None))

        probe_manager = captured["manager"]
        probe_cond_proc = captured["cond_proc"]
        copied_source = next(block for block in captured["graph"] if block.addr == source.addr)
        copied_jump = copied_source.statements[-1]
        self.assertIsNot(probe_manager, manager)
        self.assertIsNot(probe_manager.variable_map, variable_map)
        self.assertGreater(probe_manager.atom_ctr, live_atom_ctr)
        self.assertNotEqual(copied_jump.idx, source_jump.idx)
        self.assertNotEqual(copied_jump.target.idx, source_jump.target.idx)
        self.assertGreaterEqual(copied_jump.idx, live_atom_ctr)
        self.assertGreaterEqual(copied_jump.target.idx, live_atom_ctr)
        self.assertIs(probe_manager.variable_map.variable(copied_jump), jump_variable)
        self.assertIs(probe_manager.variable_map.variable(copied_jump.target), target_variable)
        copied_labels = [
            statement for block in captured["graph"] for statement in block.statements if isinstance(statement, Label)
        ]
        self.assertTrue(copied_labels)
        self.assertTrue(all(label.idx >= live_atom_ctr for label in copied_labels))
        self.assertIsNot(probe_cond_proc, live_cond_proc)
        self.assertIs(probe_cond_proc.ail_manager, probe_manager)

        self.assertEqual(manager.atom_ctr, live_atom_ctr)
        for slot, before in variable_map_snapshot.items():
            self.assertEqual(getattr(variable_map, slot), before)
        for name, before in cond_proc_snapshot.items():
            self.assertEqual(getattr(live_cond_proc, name), before)

    def test_probe_pipeline_shares_one_local_manager_and_condition_processor(self):
        manager = Manager()
        source = Block(
            0x100,
            1,
            statements=[Jump(manager.next_atom(), Const(manager.next_atom(), 0x200, 64), ins_addr=0x100)],
        )
        target = Block(0x200, 1, statements=[])
        graph = networkx.DiGraph([(source, target)])
        captures = {}

        def _region_identifier(_function, *, graph, ail_manager, cond_proc, **_kwargs):
            captures["ri_manager"] = ail_manager
            captures["ri_cond_proc"] = cond_proc
            return SimpleNamespace(
                region=next(block for block in graph if block.addr == source.addr), cond_proc=cond_proc
            )

        def _recursive_structurer(region, *, ail_manager, cond_proc, **_kwargs):
            captures["recursive_manager"] = ail_manager
            captures["recursive_cond_proc"] = cond_proc
            return SimpleNamespace(result=region, result_incomplete=False)

        def _region_simplifier(_function, region, ail_manager, **_kwargs):
            captures["simplifier_manager"] = ail_manager
            return SimpleNamespace(result=region, goto_manager=SimpleNamespace())

        region_factory = MagicMock()
        region_factory.prep.return_value = _region_identifier
        recursive_factory = MagicMock()
        recursive_factory.prep.return_value = _recursive_structurer
        analyses = MagicMock()
        analyses.__getitem__.side_effect = lambda analysis: (
            region_factory if analysis is RegionIdentifier else recursive_factory
        )
        analyses.RegionSimplifier.side_effect = _region_simplifier
        probe = object.__new__(StructuringOptimizationPass)
        probe.manager = manager
        project = SimpleNamespace(analyses=analyses, kb=SimpleNamespace(), arch=None)
        cast(Any, probe)._func = SimpleNamespace(name="probe", addr=source.addr, project=project)
        cast(Any, probe)._ri = SimpleNamespace(cond_proc=ConditionProcessor(None, manager))
        probe.entry_node_addr = (source.addr, None)
        probe._edges_to_remove = []
        probe._arg_vvars = None

        structurable, region_identifier, goto_manager, result = probe._compute_structurability(graph, False)

        self.assertTrue(structurable)
        self.assertIsNotNone(region_identifier)
        self.assertIsNotNone(goto_manager)
        self.assertIsNotNone(result)
        self.assertIs(captures["ri_manager"], captures["recursive_manager"])
        self.assertIs(captures["ri_manager"], captures["simplifier_manager"])
        self.assertIs(captures["ri_cond_proc"], captures["recursive_cond_proc"])
        self.assertIs(captures["ri_cond_proc"].ail_manager, captures["ri_manager"])
        self.assertIsNot(captures["ri_manager"], manager)

    def test_probe_condition_processor_does_not_outlive_the_probe(self):
        manager = Manager()
        source = Block(
            0x100,
            1,
            statements=[Jump(manager.next_atom(), Const(manager.next_atom(), 0x200, 64), ins_addr=0x100)],
        )
        target = Block(0x200, 1, statements=[])
        graph = networkx.DiGraph([(source, target)])
        live_cond_proc = ConditionProcessor(None, manager)
        captures = {}

        def _region_identifier(_function, *, graph, ail_manager, cond_proc, **_kwargs):
            captures["probe_cond_proc"] = cond_proc
            return SimpleNamespace(
                region=next(block for block in graph if block.addr == source.addr),
                cond_proc=cond_proc,
                ail_manager=ail_manager,
            )

        def _recursive_structurer(region, **_kwargs):
            return SimpleNamespace(result=region, result_incomplete=False)

        def _region_simplifier(_function, region, _ail_manager, **_kwargs):
            return SimpleNamespace(result=region, goto_manager=SimpleNamespace())

        region_factory = MagicMock()
        region_factory.prep.return_value = _region_identifier
        recursive_factory = MagicMock()
        recursive_factory.prep.return_value = _recursive_structurer
        analyses = MagicMock()
        analyses.__getitem__.side_effect = lambda analysis: (
            region_factory if analysis is RegionIdentifier else recursive_factory
        )
        analyses.RegionSimplifier.side_effect = _region_simplifier
        probe = object.__new__(StructuringOptimizationPass)
        probe.manager = manager
        project = SimpleNamespace(analyses=analyses, kb=SimpleNamespace(), arch=None)
        cast(Any, probe)._func = SimpleNamespace(name="probe", addr=source.addr, project=project)
        cast(Any, probe)._ri = SimpleNamespace(cond_proc=live_cond_proc)
        probe.entry_node_addr = (source.addr, None)
        probe._edges_to_remove = []
        probe._arg_vvars = None
        probe._scratch = {}
        probe._must_improve_rel_quality = False

        self.assertTrue(probe._graph_is_structurable(graph, initial=True))

        retained_ri = cast(Any, probe)._ri
        self.assertIsNot(captures["probe_cond_proc"], live_cond_proc)
        self.assertIsNot(captures["probe_cond_proc"].ail_manager, manager)
        self.assertIs(retained_ri.cond_proc, live_cond_proc)
        self.assertIsNot(retained_ri.ail_manager, manager)

    def test_lowered_switch_callback_uses_probe_variable_map(self):
        live_manager = Manager()
        probe_manager = Manager()
        live_variable_map = variable_map_of(live_manager)
        probe_variable_map = variable_map_of(probe_manager)
        lowered_switch = object.__new__(LoweredSwitchSimplifier)
        lowered_switch.manager = live_manager
        cast(Any, lowered_switch)._ri = SimpleNamespace(ail_manager=probe_manager)
        lowered_switch._must_improve_rel_quality = False
        region = object()

        with patch(
            "angr.analyses.decompiler.optimization_passes.lowered_switch_simplifier.SwitchClusterFinder"
        ) as finder:
            finder.return_value.var2switches = {}
            lowered_switch._analyze_simplified_region(region)

        finder.assert_called_once_with(region, probe_variable_map)
        self.assertIsNot(probe_variable_map, live_variable_map)

    def test_redundant_label_retargeting_only_mutates_probe_copy(self):
        manager = Manager()
        source_jump = Jump(
            manager.next_atom(),
            Const(manager.next_atom(), 0x300, 64),
            target_idx=7,
            ins_addr=0x100,
        )
        source = Block(0x100, 1, statements=[source_jump])
        preceding_label = Block(
            0x200,
            1,
            statements=[Label(manager.next_atom(), "preceding", ins_addr=0x200, block_idx=3)],
            idx=3,
        )
        target_label = Block(
            0x300,
            1,
            statements=[Label(manager.next_atom(), "target", ins_addr=0x300, block_idx=7)],
            idx=7,
        )
        graph = networkx.DiGraph()
        graph.add_nodes_from((source, preceding_label, target_label))
        graph.add_edge(source, target_label, kind="probe")
        original_nodes = tuple(graph.nodes)
        original_edges = tuple(graph.edges(data=True))
        original_statements = {block: tuple(block.statements) for block in graph}
        original_serialized = {block: tuple(str(stmt) for stmt in block.statements) for block in graph}

        captured = {}

        def _region_identifier(_function, *, graph, **_kwargs):
            copied_by_addr = {block.addr: block for block in graph}
            for original_block in original_nodes:
                copied_block = copied_by_addr[original_block.addr]
                self.assertIsNot(copied_block, original_block)
                for original_statement, copied_statement in zip(
                    original_statements[original_block], copied_block.statements, strict=True
                ):
                    self.assertIsNot(copied_statement, original_statement)
            copied_source = copied_by_addr[source.addr]
            copied_jump = copied_source.statements[-1]
            copied_sequence = SequenceNode(
                copied_source.addr,
                nodes=[copied_source, copied_by_addr[preceding_label.addr], copied_by_addr[target_label.addr]],
            )
            RedundantLabelRemover(copied_sequence, {(target_label.addr, target_label.idx)})
            self.assertEqual(copied_jump.target.value, preceding_label.addr)
            self.assertEqual(copied_jump.target_idx, preceding_label.idx)
            captured["graph"] = graph

        analysis_factory = MagicMock()
        analysis_factory.prep.return_value = _region_identifier
        analyses = MagicMock()
        analyses.__getitem__.return_value = analysis_factory
        probe = object.__new__(StructuringOptimizationPass)
        probe.manager = manager
        project = SimpleNamespace(analyses=analyses, kb=SimpleNamespace(), arch=None)
        cast(Any, probe)._func = SimpleNamespace(name="probe", addr=source.addr, project=project)
        cast(Any, probe)._ri = SimpleNamespace(cond_proc=None)
        probe.entry_node_addr = (source.addr, None)
        probe._edges_to_remove = []

        structurable, region_identifier, goto_manager, region = probe._compute_structurability(graph, False)

        self.assertFalse(structurable)
        self.assertIsNone(region_identifier)
        self.assertIsNone(goto_manager)
        self.assertIsNone(region)
        copied_graph = captured["graph"]
        self.assertEqual({block.addr for block in copied_graph}, {block.addr for block in graph})
        for original_block in graph:
            copied_block = next(block for block in copied_graph if block.addr == original_block.addr)
            self.assertIsNot(copied_block, original_block)

        self.assertEqual(tuple(graph.nodes), original_nodes)
        self.assertEqual(tuple(graph.edges(data=True)), original_edges)
        for block in graph:
            self.assertEqual(tuple(block.statements), original_statements[block])
            self.assertEqual(tuple(str(stmt) for stmt in block.statements), original_serialized[block])
        self.assertIs(source.statements[-1], source_jump)
        self.assertEqual(source_jump.target.value, target_label.addr)
        self.assertEqual(source_jump.target_idx, target_label.idx)


if __name__ == "__main__":
    unittest.main()

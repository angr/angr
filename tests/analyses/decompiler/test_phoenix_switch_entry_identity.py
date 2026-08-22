#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from collections import defaultdict
from types import SimpleNamespace
from typing import Any, cast

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import BinaryOp, Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Return
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.optimization_passes import LoweredSwitchSimplifier
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.structurer_nodes import (
    CodeNode,
    IncompleteSwitchCaseHeadStatement,
    IncompleteSwitchCaseNode,
    SequenceNode,
    SwitchCaseNode,
)
from angr.analyses.decompiler.structuring import PhoenixStructurer, SAILRStructurer


class _FilteredDiGraph(networkx.DiGraph):
    def filtered(self):
        return self


def _const(idx: int, value: int) -> Const:
    return Const(idx, value, 64)


def _build_lowered_switch_graph():
    project = angr.load_shellcode(b"\x90", "AMD64", load_address=0x4000)
    manager = Manager(arch=project.arch)
    switch_variable = VirtualVariable(0, 1, 64, VirtualVariableCategory.REGISTER, oident=0)
    assignment_variable = VirtualVariable(1, 2, 64, VirtualVariableCategory.REGISTER, oident=8)

    def comparison(idx: int, value: int) -> BinaryOp:
        return BinaryOp(idx, "CmpEQ", [switch_variable, _const(idx + 1, value)], False)

    head = Block(
        0x4000,
        1,
        statements=[
            ConditionalJump(
                10,
                comparison(11, 1),
                _const(12, 0x5000),
                _const(13, 0x4010),
                true_target_idx=None,
                false_target_idx=None,
                ins_addr=0x4000,
            )
        ],
    )
    final_comparison = Block(
        0x4010,
        1,
        statements=[
            Assignment(20, assignment_variable, _const(21, 5)),
            ConditionalJump(
                22,
                comparison(23, 20),
                _const(24, 0x6000),
                _const(25, 0x7000),
                true_target_idx=None,
                false_target_idx=None,
                ins_addr=0x4010,
            ),
        ],
    )
    case_1 = Block(0x5000, 1, statements=[Return(30, [])])
    case_20 = Block(0x6000, 1, statements=[Return(31, [])])
    default = Block(0x7000, 1, statements=[Return(32, [])])
    graph = networkx.DiGraph(
        [
            (head, case_1),
            (head, final_comparison),
            (final_comparison, case_20),
            (final_comparison, default),
        ]
    )

    blocks_by_addr = defaultdict(set)
    blocks_by_addr_and_idx = {}
    for node in graph:
        blocks_by_addr[node.addr].add(node)
        blocks_by_addr_and_idx[node.addr, node.idx] = node

    function = SimpleNamespace(addr=head.addr, project=project, name="synthetic_lowered_switch")
    simplified = LoweredSwitchSimplifier(
        function,
        manager,
        graph=graph,
        blocks_by_addr=blocks_by_addr,
        blocks_by_addr_and_idx=blocks_by_addr_and_idx,
        region_identifier=SimpleNamespace(regions_by_block_addrs=[]),
    )
    assert simplified.out_graph is not None
    return simplified.out_graph, manager, project


def _find_switch_case_node(node):
    if isinstance(node, SwitchCaseNode):
        return node
    if isinstance(node, SequenceNode):
        for child in node.nodes:
            switch = _find_switch_case_node(child)
            if switch is not None:
                return switch
    return None


class TestPhoenixSwitchEntryIdentity(unittest.TestCase):
    def test_switch_entry_identity_helpers(self):
        entry_addr = 0x5000
        left = CodeNode(Block(entry_addr, 0, idx=1), None)
        right = IncompleteSwitchCaseNode(entry_addr, Block(entry_addr, 0, idx=1), [])
        different = IncompleteSwitchCaseNode(entry_addr, Block(entry_addr, 0, idx=2), [])

        self.assertEqual(PhoenixStructurer._switch_entry_idx(left), 1)
        self.assertEqual(PhoenixStructurer._switch_entry_idx(right), 1)
        self.assertTrue(PhoenixStructurer._switch_entries_match(left, right))
        self.assertFalse(PhoenixStructurer._switch_entries_match(left, different))

    def test_switch_entry_resolution_with_missing_and_mismatched_identities(self):
        entry_addr = 0x5000
        expected_entries: set[tuple[int, int | None]] = {(entry_addr, 1), (entry_addr, 2)}
        matching = Block(entry_addr, 0, idx=1)

        resolved = PhoenixStructurer._switch_resolve_entry_nodes([matching], expected_entries)
        self.assertEqual(resolved, {(entry_addr, 1): matching, (entry_addr, 2): None})

        mismatched = Block(entry_addr, 0, idx=3)
        for candidates in ([matching, mismatched], [mismatched, matching]):
            with self.subTest(candidate_indices=[candidate.idx for candidate in candidates]):
                self.assertIsNone(PhoenixStructurer._switch_resolve_entry_nodes(candidates, expected_entries))

    def test_lowered_switch_identity_survives_recursive_structuring(self):
        for structurer_cls in (PhoenixStructurer, SAILRStructurer):
            for reverse_successors in (False, True):
                with self.subTest(structurer=structurer_cls.NAME, reverse_successors=reverse_successors):
                    lowered_graph, manager, project = _build_lowered_switch_graph()
                    head = next(node for node in lowered_graph if node.addr == 0x4000)
                    switch_stmt = head.statements[-1]
                    self.assertIsInstance(switch_stmt, IncompleteSwitchCaseHeadStatement)
                    entries = {
                        (target_addr, target_idx): value
                        for _, value, target_addr, target_idx, _ in switch_stmt.case_addrs
                    }
                    self.assertEqual(entries[0x4010, None], 20)
                    self.assertEqual(entries[0x4010, 1002], "default")

                    case_entry = next(
                        node for node in lowered_graph.successors(head) if (node.addr, node.idx) == (0x4010, None)
                    )
                    default_entry = next(
                        node for node in lowered_graph.successors(head) if (node.addr, node.idx) == (0x4010, 1002)
                    )
                    lowered_graph.remove_edge(head, case_entry)
                    lowered_graph.remove_edge(head, default_entry)
                    same_address_successors = [case_entry, default_entry]
                    if reverse_successors:
                        same_address_successors.reverse()
                    for successor in same_address_successors:
                        lowered_graph.add_edge(head, successor)

                    project.analyses.CFGFast(normalize=True)
                    region_identifier = project.analyses.RegionIdentifier(
                        None,
                        graph=lowered_graph,
                        ail_manager=manager,
                        update_graph=False,
                    )
                    structured = project.analyses.RecursiveStructurer(
                        region_identifier.region,
                        cond_proc=region_identifier.cond_proc,
                        func=None,
                        structurer_cls=structurer_cls,
                        ail_manager=manager,
                    )

                    self.assertFalse(structured.result_incomplete)
                    switch = _find_switch_case_node(structured.result)
                    self.assertIsNotNone(switch)
                    if switch is None:
                        self.fail("RecursiveStructurer did not produce a switch-case node")
                    self.assertEqual(switch.cases[20].nodes[-1].addr, 0x6000)
                    self.assertEqual(switch.default_node.nodes[-1].addr, 0x7000)

    def test_ambiguous_structured_entry_bails_without_mutation(self):
        comparison = Block(0x3000, 0)
        switch_stmt = IncompleteSwitchCaseHeadStatement(
            0,
            Const(0, 0, 32),
            [
                (comparison, 20, 0x5000, None, 0),
                (comparison, "default", 0x5000, 1002, 0),
            ],
            ins_addr=0x4000,
        )
        head = Block(0x4000, 0, statements=cast(list[Any], [switch_stmt]))
        unknown_entry = SequenceNode(0x5000, [])
        graph = _FilteredDiGraph([(head, unknown_entry)])
        nodes_before = set(graph)
        edges_before = set(graph.edges)
        statements_before = list(head.statements)

        structurer = object.__new__(PhoenixStructurer)
        structurer._region = cast(Any, SimpleNamespace(head=head))
        structurer.cond_proc = ConditionProcessor

        def fail_on_mutation(*_args, **_kwargs):
            self.fail("switch matching mutated state before resolving an ambiguous entry")

        structurer._switch_build_cases = fail_on_mutation
        self.assertFalse(structurer._match_acyclic_switch_cases_incomplete_switch_head(head, graph, graph))
        self.assertEqual(set(graph), nodes_before)
        self.assertEqual(set(graph.edges), edges_before)
        self.assertEqual(head.statements, statements_before)
        self.assertEqual(unknown_entry.nodes, [])

    def test_loop_back_gotos_use_selected_entry_objects(self):
        for reverse_successors in (False, True):
            with self.subTest(reverse_successors=reverse_successors):
                head = SequenceNode(0x4000, [Block(0x4000, 0, idx=None)])
                case = Block(0x5000, 0, idx=None)
                default = Block(0x5000, 0, idx=1002)
                successors = [case, default]
                if reverse_successors:
                    successors.reverse()

                graph = networkx.DiGraph()
                graph.add_edges_from((head, successor) for successor in successors)
                graph.add_edges_from(((case, head), (default, head)))
                region = OverlayManager(graph).root
                region.head = head

                structurer = cast(Any, object.__new__(PhoenixStructurer))
                structurer._region = region
                structurer.cond_proc = ConditionProcessor
                structurer.project = SimpleNamespace(arch=SimpleNamespace(bits=64))
                structurer.ail_manager = Manager()
                structurer._graph_helper = SimpleNamespace(
                    add_node_successor=lambda *_: None,
                    replace_node=lambda *_: None,
                )
                structurer.dowhile_known_tail_nodes = set()

                expected_entries = {(case.addr, case.idx), (default.addr, default.idx)}
                entry_nodes = structurer._switch_resolve_entry_nodes(region.graph.successors(head), expected_entries)
                self.assertIsNotNone(entry_nodes)
                if entry_nodes is None:
                    self.fail("switch entry resolution unexpectedly failed")

                selected_entry_to_case = {}
                # pylint: disable-next=assignment-from-no-return
                cases, selected_default, to_remove = structurer._switch_build_cases(
                    {20: (case.addr, case.idx)},
                    head,
                    head,
                    default.addr,
                    region.graph,
                    entry_nodes=entry_nodes,
                    default_entry=(default.addr, default.idx),
                    selected_entry_to_case=selected_entry_to_case,
                )
                self.assertIsInstance(selected_default, SequenceNode)

                self.assertTrue(
                    structurer._make_switch_cases_core(
                        head,
                        None,
                        cases,
                        default.addr,
                        selected_default,
                        head.addr,
                        to_remove,
                        region.graph,
                        region.graph_with_successors,
                        selected_entry_to_case=selected_entry_to_case,
                    )
                )
                self.assertIsInstance(cases[20].nodes[-1].statements[-1], Jump)
                self.assertIsInstance(selected_default.nodes[-1].statements[-1], Jump)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
from __future__ import annotations

import unittest
from collections.abc import Callable, Sequence
from types import SimpleNamespace
from typing import Any, cast
from unittest import mock

import archinfo
import networkx
from archinfo import Arch

from angr import ailment
from angr.analyses.decompiler.clinic import Clinic, _is_function_entry_fallthrough_block
from angr.codenode import BlockNode, FuncNode
from angr.utils.constants import DEFAULT_STATEMENT


class TestClinicEntryState(unittest.TestCase):
    @staticmethod
    def _assignment(
        manager: ailment.Manager, reg_offset: int, bits: int, value: int, *, ins_addr: int | None = None
    ) -> ailment.Stmt.Assignment:
        return ailment.Stmt.Assignment(
            manager.next_atom(),
            ailment.Expr.Register(manager.next_atom(), reg_offset, bits, ins_addr=ins_addr),
            ailment.Expr.Const(manager.next_atom(), value, bits, ins_addr=ins_addr),
            ins_addr=ins_addr,
        )

    @staticmethod
    def _guarded_statements(
        manager: ailment.Manager,
        arch: Arch,
        block_addr: int,
        condition_reg_offset: int,
        true_target: int,
        false_target: int | None = None,
    ) -> list[ailment.Stmt.Statement]:
        source_tmp = ailment.Expr.Tmp(manager.next_atom(), 0, arch.bits, ins_addr=block_addr)
        condition_tmp = ailment.Expr.Tmp(manager.next_atom(), 1, arch.bits, ins_addr=block_addr)
        return [
            ailment.Stmt.Assignment(
                manager.next_atom(),
                source_tmp,
                ailment.Expr.Register(manager.next_atom(), condition_reg_offset, arch.bits, ins_addr=block_addr),
                ins_addr=block_addr,
            ),
            ailment.Stmt.Assignment(manager.next_atom(), condition_tmp, source_tmp, ins_addr=block_addr),
            ailment.Stmt.ConditionalJump(
                manager.next_atom(),
                condition_tmp,
                ailment.Expr.Const(manager.next_atom(), true_target, arch.bits, ins_addr=block_addr),
                (
                    ailment.Expr.Const(manager.next_atom(), false_target, arch.bits, ins_addr=block_addr)
                    if false_target is not None
                    else None
                ),
                ins_addr=block_addr,
            ),
        ]

    @staticmethod
    def _convert(
        function_addr: int,
        block_addr: int,
        thumb: bool,
        original_statements: Callable[[ailment.Manager, Arch], Sequence[ailment.Stmt.Statement]],
        *,
        block_size: int = 8,
        instruction_addrs: list[int] | None = None,
        predecessors: list[tuple[int, int]] | None = None,
    ) -> tuple[Arch, ailment.Block, list[ailment.Stmt.Statement]]:
        arch = archinfo.ArchARMCortexM()
        manager = ailment.Manager(arch=arch)
        block = SimpleNamespace(
            addr=block_addr,
            size=block_size,
            thumb=thumb,
            instruction_addrs=instruction_addrs if instruction_addrs is not None else [block_addr, block_addr + 4],
        )
        clinic = cast(Any, Clinic.__new__(Clinic))
        clinic.project = SimpleNamespace(
            arch=arch,
            factory=SimpleNamespace(block=mock.Mock(return_value=block)),
        )
        clinic.function = SimpleNamespace(addr=function_addr)
        clinic._ail_manager = manager
        block_node = BlockNode(block_addr, block.size)
        clinic._func_graph = networkx.DiGraph()
        clinic._func_graph.add_node(block_node)
        for predecessor_addr, predecessor_size in predecessors or []:
            clinic._func_graph.add_edge(
                BlockNode(predecessor_addr, predecessor_size),
                block_node,
                type="transition",
                stmt_idx=DEFAULT_STATEMENT,
            )
        lifted_statements = list(original_statements(manager, arch))
        converted = ailment.Block(block_addr, block.size, statements=list(lifted_statements))

        with mock.patch.object(Clinic, "_convert_vex", return_value=converted):
            result = clinic._convert(block_node)
        return arch, result, lifted_statements

    def test_thumb_entry_clears_itstate_before_lifted_statements(self):
        def original(manager, arch):
            return [self._assignment(manager, arch.registers["r0"][0], arch.bits, 1)]

        arch, result, original_statements = self._convert(0x1001, 0x1001, True, original)

        self.assertEqual(len(result.statements), 2)
        assignment = result.statements[0]
        assert isinstance(assignment, ailment.Stmt.Assignment)
        destination = cast(Any, assignment.dst)
        source = cast(Any, assignment.src)
        self.assertIsInstance(destination, ailment.Expr.Register)
        self.assertEqual(destination.reg_offset, arch.registers["itstate"][0])
        self.assertIsInstance(source, ailment.Expr.Const)
        self.assertEqual(source.value, 0)
        self.assertIs(result.statements[1], original_statements[0])

    def test_thumb_entry_removes_only_itstate_guard_skipping_first_instruction(self):
        def original(manager, arch):
            statements = self._guarded_statements(
                manager,
                arch,
                0x1001,
                arch.registers["itstate"][0],
                0x1005,
            )
            statements.append(self._assignment(manager, arch.registers["r0"][0], arch.bits, 1, ins_addr=0x1001))
            return statements

        _, result, original_statements = self._convert(0x1001, 0x1001, True, original)

        self.assertNotIn(original_statements[2], result.statements)
        self.assertIn(original_statements[3], result.statements)

    def test_single_instruction_thumb_entry_removes_itstate_guard_to_block_end(self):
        def original(manager, arch):
            return self._guarded_statements(
                manager,
                arch,
                0x1001,
                arch.registers["itstate"][0],
                0x1005,
                false_target=0x1005,
            )

        _, result, original_statements = self._convert(
            0x1001,
            0x1001,
            True,
            original,
            block_size=4,
            instruction_addrs=[0x1001],
        )

        self.assertNotIn(original_statements[2], result.statements)

    def test_thumb_entry_keeps_guard_not_depending_on_itstate(self):
        def original(manager, arch):
            return self._guarded_statements(manager, arch, 0x1001, arch.registers["r0"][0], 0x1005)

        _, result, original_statements = self._convert(0x1001, 0x1001, True, original)

        self.assertIn(original_statements[2], result.statements)

    def test_thumb_entry_keeps_itstate_guard_not_skipping_to_next_instruction(self):
        def original(manager, arch):
            return self._guarded_statements(manager, arch, 0x1001, arch.registers["itstate"][0], 0x1011)

        _, result, original_statements = self._convert(0x1001, 0x1001, True, original)

        self.assertIn(original_statements[2], result.statements)

    def test_thumb_entry_removes_itstate_guard_with_external_false_target(self):
        def original(manager, arch):
            return self._guarded_statements(
                manager,
                arch,
                0x1001,
                arch.registers["itstate"][0],
                0x1005,
                false_target=0x1011,
            )

        _, result, original_statements = self._convert(0x1001, 0x1001, True, original)

        self.assertNotIn(original_statements[2], result.statements)

    def test_thumb_entry_keeps_genuine_itstate_branch_with_external_true_target(self):
        def original(manager, arch):
            return self._guarded_statements(
                manager,
                arch,
                0x1001,
                arch.registers["itstate"][0],
                0x1011,
                false_target=0x1005,
            )

        _, result, original_statements = self._convert(0x1001, 0x1001, True, original)

        self.assertIn(original_statements[2], result.statements)

    def test_thumb_entry_fallthrough_block_removes_itstate_guard(self):
        def original(manager, arch):
            return self._guarded_statements(
                manager,
                arch,
                0x1005,
                arch.registers["itstate"][0],
                0x1009,
                false_target=0x1011,
            )

        arch, result, original_statements = self._convert(
            0x1001,
            0x1005,
            True,
            original,
            predecessors=[(0x1001, 4)],
        )

        self.assertNotIn(original_statements[2], result.statements)
        assignment = result.statements[0]
        assert isinstance(assignment, ailment.Stmt.Assignment)
        destination = cast(Any, assignment.dst)
        self.assertIsInstance(destination, ailment.Expr.Register)
        self.assertEqual(destination.reg_offset, arch.registers["itstate"][0])

    def test_thumb_entry_fallthrough_chain_stops_at_join(self):
        def original(manager, arch):
            return self._guarded_statements(
                manager,
                arch,
                0x1005,
                arch.registers["itstate"][0],
                0x1009,
                false_target=0x1011,
            )

        _, result, original_statements = self._convert(
            0x1001,
            0x1005,
            True,
            original,
            predecessors=[(0x1001, 4), (0x1011, 4)],
        )

        self.assertEqual(result.statements, original_statements)

    def test_thumb_entry_fallthrough_chain_reaches_entry_through_multiple_blocks(self):
        graph = networkx.DiGraph()
        entry = BlockNode(0x1001, 4)
        middle = BlockNode(0x1005, 4)
        target = BlockNode(0x1009, 4)
        graph.add_edge(entry, middle, type="transition", stmt_idx=DEFAULT_STATEMENT)
        graph.add_edge(middle, target, type="transition", stmt_idx=DEFAULT_STATEMENT)

        self.assertTrue(_is_function_entry_fallthrough_block(graph, entry.addr, target))

    def test_thumb_entry_fallthrough_chain_rejects_explicit_branch_to_adjacent_block(self):
        graph = networkx.DiGraph()
        entry = BlockNode(0x1001, 4)
        target = BlockNode(0x1005, 4)
        graph.add_edge(entry, target, type="transition", stmt_idx=3)

        self.assertFalse(_is_function_entry_fallthrough_block(graph, entry.addr, target))

    def test_thumb_entry_fallthrough_chain_rejects_nontransition_edge(self):
        graph = networkx.DiGraph()
        entry = BlockNode(0x1001, 4)
        target = BlockNode(0x1005, 4)
        graph.add_edge(entry, target, type="exception", stmt_idx=DEFAULT_STATEMENT)

        self.assertFalse(_is_function_entry_fallthrough_block(graph, entry.addr, target))

    def test_thumb_entry_fallthrough_chain_rejects_noncontiguous_predecessor(self):
        graph = networkx.DiGraph()
        entry = BlockNode(0x1001, 2)
        target = BlockNode(0x1005, 4)
        graph.add_edge(entry, target, type="transition", stmt_idx=DEFAULT_STATEMENT)

        self.assertFalse(_is_function_entry_fallthrough_block(graph, entry.addr, target))

    def test_thumb_entry_fallthrough_chain_rejects_nonblock_predecessor(self):
        graph = networkx.DiGraph()
        entry = FuncNode(0x1005)
        target = BlockNode(0x1005, 4)
        graph.add_edge(entry, target, type="transition", stmt_idx=DEFAULT_STATEMENT)

        self.assertFalse(_is_function_entry_fallthrough_block(graph, 0x1001, target))

    def test_thumb_entry_fallthrough_chain_rejects_zero_size_cycle(self):
        graph = networkx.DiGraph()
        zero_size = BlockNode(0x1005, 0)
        target = BlockNode(0x1005, 4)
        graph.add_edge(zero_size, zero_size, type="transition", stmt_idx=DEFAULT_STATEMENT)
        graph.add_edge(zero_size, target, type="transition", stmt_idx=DEFAULT_STATEMENT)

        self.assertFalse(_is_function_entry_fallthrough_block(graph, 0x1001, target))

    def test_thumb_interior_block_keeps_lifted_itstate_guard(self):
        def original(manager, arch):
            return self._guarded_statements(manager, arch, 0x1011, arch.registers["itstate"][0], 0x1015)

        _, result, original_statements = self._convert(0x1001, 0x1011, True, original)

        self.assertEqual(result.statements, original_statements)

    def test_arm_entry_does_not_seed_thumb_itstate(self):
        def original(manager, arch):
            return [self._assignment(manager, arch.registers["r0"][0], arch.bits, 1)]

        _, result, original_statements = self._convert(0x1000, 0x1000, False, original)

        self.assertEqual(result.statements, original_statements)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest
from pathlib import Path
from typing import Literal
from unittest import TestCase

import archinfo
import networkx
import pytest

from angr import Project, ailment, claripy
from angr.ailment.expression import BinaryOp, Const, Convert, Extract, Load, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import ConditionalJump, Jump, Return
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.structurer_nodes import IncompleteSwitchCaseHeadStatement, MultiNode
from angr.analyses.decompiler.structuring.structurer_base import StructurerBase
from tests.common import bin_location


def _recover_edge_condition_with_internal_side_exits(
    side_exits: tuple[int | None, ...],
    *,
    false_side_exits: tuple[int | None, ...] | None = None,
    side_exit_target_indices: tuple[int | None, ...] | None = None,
    terminal_target: int | None = 0x5000,
    terminal_target_idx: int | None = None,
    dst_idx: int | None = None,
    internal_jump_target: int | None = None,
    internal_control: Literal["return", "switch"] | None = None,
    wrap_destination: bool = False,
) -> claripy.ast.Bool:
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager()
    condition_processor = ConditionProcessor(arch, manager)
    src_addr = 0x4000
    dst_addr = 0x5000
    false_side_exits = false_side_exits if false_side_exits is not None else (None,) * len(side_exits)
    side_exit_target_indices = side_exit_target_indices or (None,) * len(side_exits)
    assert len(false_side_exits) == len(side_exits)
    assert len(side_exit_target_indices) == len(side_exits)

    statements = []
    for side_exit, false_side_exit, side_exit_target_idx in zip(
        side_exits, false_side_exits, side_exit_target_indices, strict=True
    ):
        condition = VirtualVariable(
            manager.next_atom(),
            1,
            1,
            VirtualVariableCategory.REGISTER,
            oident=arch.registers["rax"][0],
        )
        side_exit_target = (
            Const(manager.next_atom(), side_exit, arch.bits)
            if side_exit is not None
            else VirtualVariable(
                manager.next_atom(),
                arch.bits,
                2,
                VirtualVariableCategory.REGISTER,
                oident=arch.registers["rbx"][0],
            )
        )
        false_side_exit_target = (
            Const(manager.next_atom(), false_side_exit, arch.bits) if false_side_exit is not None else None
        )
        statements.append(
            ConditionalJump(
                manager.next_atom(),
                condition,
                side_exit_target,
                false_side_exit_target,
                true_target_idx=side_exit_target_idx,
                ins_addr=src_addr,
            )
        )

    if internal_jump_target is not None:
        statements.append(
            Jump(
                manager.next_atom(),
                Const(manager.next_atom(), internal_jump_target, arch.bits),
                ins_addr=src_addr + 1,
            )
        )

    if internal_control == "return":
        statements.append(Return(manager.next_atom(), [], ins_addr=src_addr + 1))
    elif internal_control == "switch":
        case_block = ailment.Block(0x6000, 4)
        switch_expr = Const(manager.next_atom(), 0, arch.bits)
        statements.append(
            IncompleteSwitchCaseHeadStatement(
                manager.next_atom(),
                switch_expr,
                [(case_block, 0, case_block.addr, case_block.idx, 0x6004)],
                ins_addr=src_addr + 1,
            )
        )

    direct_target = (
        Const(manager.next_atom(), terminal_target, arch.bits)
        if terminal_target is not None
        else VirtualVariable(
            manager.next_atom(),
            arch.bits,
            3,
            VirtualVariableCategory.REGISTER,
            oident=arch.registers["rcx"][0],
        )
    )
    statements.append(
        Jump(
            manager.next_atom(),
            direct_target,
            target_idx=terminal_target_idx,
            ins_addr=src_addr + 1,
        )
    )
    src = ailment.Block(
        src_addr,
        4,
        statements=statements,
    )
    dst = ailment.Block(dst_addr, 4, idx=dst_idx)
    if wrap_destination:
        dst = MultiNode([dst])
    graph = networkx.DiGraph([(src, dst)])

    return condition_processor.recover_edge_condition(graph, src, dst)


@pytest.mark.parametrize("wrap_destination", [False, True], ids=["block", "multinode"])
def test_internal_side_exit_and_terminal_jump_converge(wrap_destination: bool):
    predicate = _recover_edge_condition_with_internal_side_exits(
        (0x5000, 0x5000),
        side_exit_target_indices=(1, 1),
        terminal_target_idx=1,
        dst_idx=1,
        wrap_destination=wrap_destination,
    )

    assert claripy.is_true(predicate)


def test_internal_side_exit_differs_from_terminal_jump():
    predicate = _recover_edge_condition_with_internal_side_exits((0x6000,))

    assert predicate.symbolic
    assert predicate.op == "Not"


def test_second_internal_side_exit_differs_from_terminal_jump():
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000, 0x6000))

    assert predicate.symbolic


@pytest.mark.parametrize(
    ("side_exits", "terminal_target"),
    [
        pytest.param((None,), 0x5000, id="indirect-side-exit"),
        pytest.param((0x5000,), 0x6000, id="different-terminal-target"),
        pytest.param((0x5000,), None, id="indirect-terminal-target"),
    ],
)
def test_convergence_requires_direct_matching_targets(side_exits, terminal_target):
    predicate = _recover_edge_condition_with_internal_side_exits(side_exits, terminal_target=terminal_target)

    assert predicate.symbolic


def test_convergence_requires_matching_target_indices():
    predicate = _recover_edge_condition_with_internal_side_exits(
        (0x5000,),
        side_exit_target_indices=(2,),
        terminal_target_idx=1,
        dst_idx=1,
    )

    assert predicate.symbolic


def test_convergence_rejects_internal_jump():
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000,), internal_jump_target=0x6000)

    assert predicate.symbolic


@pytest.mark.parametrize("internal_control", ["return", "switch"])
def test_convergence_rejects_internal_control(internal_control):
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000,), internal_control=internal_control)

    assert predicate.symbolic


def test_explicit_false_side_exit_converges():
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000,), false_side_exits=(0x5000,))

    assert claripy.is_true(predicate)


def test_explicit_false_side_exit_differs():
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000,), false_side_exits=(0x6000,))

    assert predicate.symbolic


def test_convergence_requires_matching_terminal_target_idx():
    predicate = _recover_edge_condition_with_internal_side_exits(
        (0x5000,),
        side_exit_target_indices=(1,),
        terminal_target_idx=2,
        dst_idx=1,
    )

    assert predicate.symbolic


def test_convergence_requires_matching_multinode_target_idx():
    predicate = _recover_edge_condition_with_internal_side_exits(
        (0x5000,),
        side_exit_target_indices=(1,),
        terminal_target_idx=1,
        dst_idx=2,
        wrap_destination=True,
    )

    assert predicate.symbolic


@pytest.mark.parametrize("terminal_idx", [1, 2], ids=["convergent", "distinct-indices"])
def test_convergence_preserves_indices_after_sequence_merges(terminal_idx):
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager()
    condition_processor = ConditionProcessor(arch, manager)
    condition = VirtualVariable(0, 1, 1, VirtualVariableCategory.REGISTER, oident=arch.registers["rax"][0])
    src = ailment.Block(
        0x4000,
        4,
        statements=[
            ConditionalJump(0, condition, Const(1, 0x5000, 64), None, true_target_idx=1, ins_addr=0x4000),
            Jump(1, Const(2, 0x5000, 64), target_idx=terminal_idx, ins_addr=0x4001),
        ],
    )
    graph = networkx.DiGraph()
    pairs = []
    for idx in sorted({1, terminal_idx}):
        tail = ailment.Block(0x5100 + idx * 0x10, 4, statements=[Return(idx, [])])
        entry = ailment.Block(0x5000, 4, idx=idx, statements=[Jump(idx, Const(idx, tail.addr, 64))])
        graph.add_edges_from([(src, entry), (entry, tail)])
        pairs.append((entry, tail))
    overlay = OverlayManager(graph).root
    structurer = StructurerBase(overlay, condition_processor=condition_processor, ail_manager=manager)
    sequences = []
    for entry, tail in pairs:
        sequence = structurer._merge_nodes(entry, tail)  # pylint:disable=protected-access
        overlay.replace_nodes(entry, sequence, old_node_1=tail)
        sequences.append(sequence)
    assert graph.out_degree(src) == len(pairs)
    predicate = condition_processor.recover_edge_condition(graph, src, sequences[0])

    if terminal_idx == 1:
        assert claripy.is_true(predicate)
    else:
        assert predicate.symbolic


def _vvar(idx, bits, oident):
    return VirtualVariable(idx, idx, bits, VirtualVariableCategory.REGISTER, oident=oident)


class TestConditionProcessor(TestCase):
    def test_extract_placeholders_include_semantic_properties(self):
        arch = archinfo.ArchAMD64()
        manager = ailment.Manager()
        condition_processor = ConditionProcessor(arch, manager)

        base = VirtualVariable(0, 1, 64, VirtualVariableCategory.REGISTER, oident=arch.registers["rax"][0])
        offset = Const(1, 0, 64)
        extract_byte = Extract(2, 8, base, offset, arch.memory_endness)
        extract_word = Extract(3, 16, base, offset, arch.memory_endness)
        extract_byte_be = Extract(4, 8, base, offset, archinfo.Endness.BE)

        byte_ast = condition_processor.claripy_ast_from_ail_condition(extract_byte)
        word_ast = condition_processor.claripy_ast_from_ail_condition(extract_word)
        byte_be_ast = condition_processor.claripy_ast_from_ail_condition(extract_byte_be)

        assert byte_ast.args[0] != word_ast.args[0]
        assert byte_ast.args[0] != byte_be_ast.args[0]
        assert condition_processor.convert_claripy_bool_ast(byte_ast) is extract_byte
        assert condition_processor.convert_claripy_bool_ast(word_ast) is extract_word
        assert condition_processor.convert_claripy_bool_ast(byte_be_ast) is extract_byte_be

    def test_operands_of_different_widths_are_unified(self):
        # a shift amount wider than the value (busybox encode_then_append_var_plusminus) used to trip an assertion, and
        # a comparison whose operands convert to bit-vectors of different widths died in claripy
        arch = archinfo.ArchAMD64()
        manager = ailment.Manager()
        cp = ConditionProcessor(arch, manager)
        byte = Load(0, _vvar(1, 64, 16), 1, arch.memory_endness, bits=8)
        amount = Convert(2, 8, 64, False, _vvar(3, 8, 24))
        shifted = cp.claripy_ast_from_ail_condition(BinaryOp(4, "Shr", [byte, amount], False, bits=8))
        assert shifted.size() == 8
        cmp = BinaryOp(5, "CmpEQ", [_vvar(6, 32, 16), _vvar(7, 64, 24)], False, bits=1)
        assert cp.claripy_ast_from_ail_condition(cmp) is not None

    def test_signed_comparisons_map_to_signed_claripy_operations(self):
        arch = archinfo.ArchAMD64()
        cp = ConditionProcessor(arch, ailment.Manager())
        for ail_op, claripy_op in (("CmpLE", "SLE"), ("CmpLT", "SLT"), ("CmpGE", "SGE"), ("CmpGT", "SGT")):
            cmp = BinaryOp(0, ail_op, [_vvar(1, 32, 16), _vvar(2, 32, 24)], True, bits=1)
            assert cmp.verbose_op == ail_op + "s"
            assert cp.claripy_ast_from_ail_condition(cmp).op == claripy_op


# Exact _crt0_entry bodies from the public DecBench ChibiOS binaries. Only PC-relative call offsets differ.
@pytest.mark.parametrize("structurer", ["sailr", "phoenix"])
@pytest.mark.parametrize("optimization", ["O0", "O2", "O2-noinline"])
def test_chibios_crt0_entry_convergent_side_exits(structurer, optimization):
    fixture = Path(bin_location, "tests", "armel", "chibios_crt0_entry", f"{optimization}.bin")
    project = Project(
        fixture,
        main_opts={
            "arch": "ARMCortexM",
            "backend": "blob",
            "base_addr": 0x80001E0,
            "entry_point": 0,
        },
    )
    assert project.filename is not None
    assert Path(project.filename) == fixture
    cfg = project.analyses.CFGFast(
        normalize=True,
        regions=[(0x80001E0, 0x8000266)],
        function_starts=[0x80001E1],
        start_at_entry=False,
        symbols=False,
        force_smart_scan=False,
        show_progressbar=False,
    )
    function = cfg.kb.functions.get_by_addr(0x80001E1)

    decompilation = project.analyses[Decompiler].prep(fail_fast=True)(
        function,
        cfg=cfg.model,
        options=[("structurer_cls", structurer)],
        preset="full",
        use_cache=False,
    )

    assert decompilation.codegen is not None, optimization
    assert not decompilation.errors, optimization


if __name__ == "__main__":
    unittest.main()

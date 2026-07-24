#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest
from unittest import TestCase

import archinfo
import claripy
import networkx
import pytest

from angr import ailment, load_shellcode
from angr.ailment.expression import BinaryOp, Const, Convert, Extract, Load, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.decompiler import Decompiler


def _recover_edge_condition_with_internal_side_exits(
    side_exits: tuple[int | None, ...],
    *,
    side_exit_target_indices: tuple[int | None, ...] | None = None,
    terminal_target: int | None = 0x5000,
    terminal_target_idx: int | None = None,
    dst_idx: int | None = None,
    internal_jump_target: int | None = None,
) -> claripy.ast.Bool:
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)
    src_addr = 0x4000
    dst_addr = 0x5000
    side_exit_target_indices = side_exit_target_indices or (None,) * len(side_exits)
    assert len(side_exit_target_indices) == len(side_exits)

    statements = []
    for side_exit, side_exit_target_idx in zip(side_exits, side_exit_target_indices, strict=True):
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
        statements.append(
            ConditionalJump(
                manager.next_atom(),
                condition,
                side_exit_target,
                None,
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
    graph = networkx.DiGraph([(src, dst)])

    return condition_processor.recover_edge_condition(graph, src, dst)


def test_internal_side_exit_and_terminal_jump_converge():
    predicate = _recover_edge_condition_with_internal_side_exits(
        (0x5000, 0x5000),
        side_exit_target_indices=(1, 1),
        terminal_target_idx=1,
        dst_idx=1,
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


# Exact 134-byte _crt0_entry bodies from the public DecBench ChibiOS binaries. Only PC-relative call offsets differ.
@pytest.mark.parametrize(
    ("optimization", "code"),
    [
        pytest.param(
            "O0",
            bytes.fromhex(
                "72b6264880f30888254880f30988254825490860022080f31488bff36f8f00f0d5f901f001fd4ff0553020491b4a"
                "91423cbf41f8040bfae71d49194a91423cbf41f8040bfae71b491b4a1c4b9a423ebf51f8040b42f8040bf8e70020"
                "1849194a91423cbf41f8040bfae700f0bff900f0b3f9154c154dac4203da54f8041b8847f9e70ff0c7f9"
            ),
            id="O0",
        ),
        pytest.param(
            "O2",
            bytes.fromhex(
                "72b6264880f30888254880f30988254825490860022080f31488bff36f8f00f0d5f900f0c7fe4ff0553020491b4a"
                "91423cbf41f8040bfae71d49194a91423cbf41f8040bfae71b491b4a1c4b9a423ebf51f8040b42f8040bf8e70020"
                "1849194a91423cbf41f8040bfae700f0b5f900f0aff9154c154dac4203da54f8041b8847f9e709f0a9fb"
            ),
            id="O2",
        ),
        pytest.param(
            "O2-noinline",
            bytes.fromhex(
                "72b6264880f30888254880f30988254825490860022080f31488bff36f8f00f0d5f900f05bff4ff0553020491b4a"
                "91423cbf41f8040bfae71d49194a91423cbf41f8040bfae71b491b4a1c4b9a423ebf51f8040b42f8040bf8e70020"
                "1849194a91423cbf41f8040bfae700f0b5f900f0aff9154c154dac4203da54f8041b8847f9e709f08ffb"
            ),
            id="O2-noinline",
        ),
    ],
)
def test_chibios_crt0_entry_convergent_side_exits(optimization, code):
    project = load_shellcode(code, arch="ARMCortexM", load_address=0x80001E0)
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
        use_cache=False,
    )

    assert decompilation.codegen is not None, optimization
    assert not decompilation.errors, optimization


if __name__ == "__main__":
    unittest.main()

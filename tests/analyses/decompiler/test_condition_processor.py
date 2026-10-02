#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest
from unittest import TestCase

import archinfo

from angr import ailment, claripy
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Extract,
    Load,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.analyses.decompiler.condition_processor import ConditionProcessor


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

    def test_float_constant_operand_is_converted(self):
        # a float-valued Const must go through the bit-pattern conversion instead of being handed to claripy as-is
        arch = archinfo.ArchAMD64()
        cp = ConditionProcessor(arch, ailment.Manager())
        for op in ("Add", "Mul"):
            expr = BinaryOp(0, op, [_vvar(1, 64, 16), Const(2, 1.0, 64)], False, bits=64, floating_point=True)
            ast = cp.claripy_ast_from_ail_condition(expr)
            assert isinstance(ast, claripy.ast.BV) and ast.size() == 64

    def test_bitwise_op_on_one_bit_operands_round_trips(self):
        # a 1-bit operand of a bitwise op must stay a bit-vector; as a Bool, claripy coerces it into If(b, 1, 0),
        # which has no AIL conversion
        arch = archinfo.ArchAMD64()
        cp = ConditionProcessor(arch, ailment.Manager())
        a = Convert(1, 32, 1, False, _vvar(2, 32, 16))
        b = Convert(3, 32, 1, False, _vvar(4, 32, 24))
        for op in ("And", "Or", "Xor"):
            expr = BinaryOp(5, op, [a, b], False, bits=1)
            cond = BinaryOp(6, "CmpNE", [expr, Const(7, 0, 1)], False, bits=1)
            ast = cp.claripy_ast_from_ail_condition(cond)
            assert "If" not in repr(ast), ast
            assert cp.convert_claripy_bool_ast(ast) is not None

    def test_signed_comparisons_map_to_signed_claripy_operations(self):
        arch = archinfo.ArchAMD64()
        cp = ConditionProcessor(arch, ailment.Manager())
        for ail_op, claripy_op in (("CmpLE", "SLE"), ("CmpLT", "SLT"), ("CmpGE", "SGE"), ("CmpGT", "SGT")):
            cmp = BinaryOp(0, ail_op, [_vvar(1, 32, 16), _vvar(2, 32, 24)], True, bits=1)
            assert cmp.verbose_op == ail_op + "s"
            assert cp.claripy_ast_from_ail_condition(cmp).op == claripy_op

    def test_stack_base_offset_operand_is_abstracted_instead_of_raising(self):
        # A comparison against a raw stack address -- (sp+0 == 0) in a 32-bit ARM ELF of a
        # corpus sweep -- reached the op-handler lookup, which reads .verbose_op. A
        # StackBaseOffset has no operation, so the lookup raised AttributeError instead of
        # falling through to the catch-all, and the whole function decompiled to nothing.
        arch = archinfo.ArchARMEL()
        cp = ConditionProcessor(arch, ailment.Manager())
        cmp = BinaryOp(0, "CmpEQ", [StackBaseOffset(1, 32, 0), Const(2, 0, 32)], False, bits=1)
        assert cp.claripy_ast_from_ail_condition(cmp) is not None
        operand = cp.claripy_ast_from_ail_condition(StackBaseOffset(3, 32, -8))
        assert isinstance(operand, claripy.ast.BV)
        assert operand.size() == 32

    def test_division_by_a_concrete_zero_keeps_the_condition(self):
        # claripy refuses to fold a division by a concrete zero, and the ZeroDivisionError used to escape the
        # conversion and cost the containing function its whole decompiled output. A machine divide by zero
        # traps, so no folded value is right either: keep the division opaque and convertible back.
        arch = archinfo.ArchX86()
        for signed in (False, True):
            cp = ConditionProcessor(arch, ailment.Manager())
            div = BinaryOp(0, "Div", [_vvar(1, 8, 16), Const(2, 0, 8)], signed, bits=8)
            ast = cp.claripy_ast_from_ail_condition(div)
            assert isinstance(ast, claripy.ast.BV)
            assert ast.op == "BVS"
            assert ast.size() == 8
            assert cp.convert_claripy_bool_ast(ast) is div

        # the shape it was found in: the division under a comparison the structurer has to recover
        cp = ConditionProcessor(arch, ailment.Manager())
        div = BinaryOp(0, "Div", [_vvar(1, 8, 16), Const(2, 0, 8)], False, bits=8)
        summed = BinaryOp(3, "Add", [div, _vvar(4, 8, 24)], False, bits=8)
        cmp = BinaryOp(5, "CmpGT", [summed, Const(6, 0, 8)], True, bits=1)
        assert cp.claripy_ast_from_ail_condition(cmp).op == "SGT"

        # a divisor that is not zero still folds
        cp = ConditionProcessor(arch, ailment.Manager())
        nonzero = BinaryOp(0, "Div", [_vvar(1, 32, 16), Const(2, 7, 32)], False, bits=32)
        assert cp.claripy_ast_from_ail_condition(nonzero).op == "__floordiv__"


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest
from unittest import TestCase

import archinfo

from angr import ailment
from angr.ailment.expression import BinaryOp, Const, Convert, Extract, Load, VirtualVariable, VirtualVariableCategory
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

    def test_one_bit_arithmetic_operands_stay_bitvectors(self):
        # a 1-bit second operand converted to a claripy Bool, which the arithmetic operation widened to
        # If(bool, 1, 0); nothing maps If back to AIL, so the conversion raised and the function decompiled empty
        arch = archinfo.ArchAMD64()
        cp = ConditionProcessor(arch, ailment.Manager())
        operand0 = Convert(0, 8, 1, False, _vvar(1, 8, 16))
        operand1 = Convert(2, 8, 1, False, _vvar(3, 8, 24))
        add = BinaryOp(4, "Add", [operand0, operand1], False, bits=1)
        ast = cp.claripy_ast_from_ail_condition(add)
        assert [arg.op for arg in ast.args] == ["BVS", "BVS"]
        assert str(cp.convert_claripy_bool_ast(ast)) == f"({operand0} Add {operand1})"

    def test_signed_comparisons_map_to_signed_claripy_operations(self):
        arch = archinfo.ArchAMD64()
        cp = ConditionProcessor(arch, ailment.Manager())
        for ail_op, claripy_op in (("CmpLE", "SLE"), ("CmpLT", "SLT"), ("CmpGE", "SGE"), ("CmpGT", "SGT")):
            cmp = BinaryOp(0, ail_op, [_vvar(1, 32, 16), _vvar(2, 32, 24)], True, bits=1)
            assert cmp.verbose_op == ail_op + "s"
            assert cp.claripy_ast_from_ail_condition(cmp).op == claripy_op


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import archinfo

from angr import ailment, claripy
from angr.ailment.expression import BinaryOp, Const, Convert, Extract, VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.condition_processor import ConditionProcessor


def test_extract_placeholders_include_semantic_properties():
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


def test_narrow_shift_count_is_extended_to_value_width():
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager()
    condition_processor = ConditionProcessor(arch, manager)

    for op in ("Shl", "Shr", "Sar"):
        value_bits, count_bits = 64, 8
        value = VirtualVariable(0, 1, value_bits, VirtualVariableCategory.REGISTER, oident=0)
        count = VirtualVariable(1, 2, count_bits, VirtualVariableCategory.REGISTER, oident=8)
        shift = BinaryOp(2, op, [value, count], op == "Sar", bits=value_bits)

        shift_ast = condition_processor.claripy_ast_from_ail_condition(shift)

        assert isinstance(shift_ast, claripy.ast.BV)
        assert shift_ast.size() == value_bits
        converted_shift = condition_processor.convert_claripy_bool_ast(shift_ast)
        assert isinstance(converted_shift, BinaryOp)
        assert converted_shift.op == op
        converted_count = converted_shift.operands[1]
        assert isinstance(converted_count, Convert)
        assert converted_count.from_bits == count_bits
        assert converted_count.to_bits == value_bits
        assert not converted_count.is_signed
        assert converted_count.operand.likes(count)


def test_wide_shift_count_does_not_get_truncated():
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager()
    condition_processor = ConditionProcessor(arch, manager)

    for op in ("Shl", "Shr", "Sar"):
        value_bits, count_bits = 8, 64
        value = VirtualVariable(0, 1, value_bits, VirtualVariableCategory.REGISTER, oident=0)
        count = VirtualVariable(1, 2, count_bits, VirtualVariableCategory.REGISTER, oident=8)
        shift = BinaryOp(2, op, [value, count], op == "Sar", bits=value_bits)

        shift_ast = condition_processor.claripy_ast_from_ail_condition(shift)

        assert isinstance(shift_ast, claripy.ast.BV)
        assert shift_ast.size() == value_bits
        converted_result = condition_processor.convert_claripy_bool_ast(shift_ast)
        assert isinstance(converted_result, Convert)
        assert converted_result.from_bits == count_bits
        assert converted_result.to_bits == value_bits
        assert not converted_result.is_signed
        converted_shift = converted_result.operand
        assert isinstance(converted_shift, BinaryOp)
        assert converted_shift.op == op
        converted_value, converted_count = converted_shift.operands
        assert isinstance(converted_value, Convert)
        assert converted_value.from_bits == value_bits
        assert converted_value.to_bits == count_bits
        assert converted_value.is_signed == (op == "Sar")
        assert converted_value.operand.likes(value)
        assert converted_count.likes(count)

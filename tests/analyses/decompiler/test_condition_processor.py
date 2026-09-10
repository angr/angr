from __future__ import annotations

import archinfo

from angr import ailment
from angr.ailment.expression import BinaryOp, Const, Convert, Extract, Load, VirtualVariable, VirtualVariableCategory
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


def _vvar(idx, bits, oident):
    return VirtualVariable(idx, idx, bits, VirtualVariableCategory.REGISTER, oident=oident)


def test_operands_of_different_widths_are_unified():
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

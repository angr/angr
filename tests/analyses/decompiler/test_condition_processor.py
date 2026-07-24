from __future__ import annotations

import archinfo
import claripy

from angr import ailment
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Extract,
    Register,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.analyses.decompiler.condition_processor import ConditionProcessor


def test_extract_placeholders_include_semantic_properties():
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
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


def test_floating_comparisons_remain_opaque_during_boolean_simplification():
    arch = archinfo.ArchARM()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)

    lhs = Register(0, arch.registers["s0"][0], 32)
    rhs = Register(1, arch.registers["s1"][0], 32)
    comparison = BinaryOp(2, "CmpGT", (lhs, rhs), False, bits=1, floating_point=True)

    comparison_ast = condition_processor.claripy_ast_from_ail_condition(comparison, must_bool=True)
    assert comparison_ast.op == "BoolS"
    assert condition_processor.convert_claripy_bool_ast(comparison_ast) is comparison

    negated = condition_processor.convert_claripy_bool_ast(claripy.Not(comparison_ast))
    assert isinstance(negated, UnaryOp)
    assert negated.op == "Not"
    assert negated.operand.likes(comparison)

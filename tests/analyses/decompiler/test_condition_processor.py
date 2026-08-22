from __future__ import annotations

import archinfo
import networkx

from angr import ailment
from angr.ailment.expression import Const, Extract, VirtualVariable, VirtualVariableCategory
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


def test_segmented_indirect_jump_target_uses_opaque_condition_variable():
    arch = archinfo.ArchX86()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)

    selector = VirtualVariable(0, 1, 16, VirtualVariableCategory.REGISTER, oident=arch.registers["cs"][0])
    offset = VirtualVariable(1, 2, 16, VirtualVariableCategory.REGISTER, oident=arch.registers["ax"][0])
    target = ailment.Expr.SegmentedAddress(2, selector, offset, "x86-protected-16:16")

    target_ast = condition_processor.claripy_ast_from_ail_condition(target, ins_addr=0x100)

    assert target_ast.op == "BVS"
    assert target_ast.size() == 32
    assert condition_processor.convert_claripy_bool_ast(target_ast) is target

    source = ailment.Block(
        0x100,
        1,
        statements=[ailment.Stmt.Jump(3, target, ins_addr=0x3631)],
    )
    destination = ailment.Block(0x200, 1)
    graph = networkx.DiGraph([(source, destination)])

    predicate = condition_processor.recover_edge_condition(graph, source, destination)

    assert predicate.op == "__eq__"
    assert predicate.variables == target_ast.variables

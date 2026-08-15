from __future__ import annotations

import archinfo
import claripy
import networkx

from angr import ailment
from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Const, Extract, Register, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import ConditionalJump
from angr.analyses.decompiler.condition_processor import ConditionProcessor


def _condition(arch, manager, reg_name):
    reg_offset = arch.registers[reg_name][0]
    return BinaryOp(
        manager.next_atom(),
        "CmpEQ",
        (Register(manager.next_atom(), reg_offset, arch.bits), Const(manager.next_atom(), 0, arch.bits)),
        False,
    )


def _conditional_block(arch, manager, addr, condition, true_addr, false_addr):
    jump = ConditionalJump(
        manager.next_atom(),
        condition,
        Const(manager.next_atom(), true_addr, arch.bits),
        Const(manager.next_atom(), false_addr, arch.bits),
        ins_addr=addr,
    )
    return Block(addr, 1, statements=[jump])


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


def test_guarding_condition_excludes_all_diverging_paths():
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)

    first_exit = Block(0x1010, 1)
    second_exit = Block(0x1030, 1)
    first_predecessor = Block(0x1050, 1)
    second_predecessor = Block(0x1060, 1)
    target = Block(0x1070, 1)

    first_condition = _condition(arch, manager, "rax")
    second_condition = _condition(arch, manager, "rbx")
    fork_condition = _condition(arch, manager, "rcx")
    head = _conditional_block(arch, manager, 0x1000, first_condition, first_exit.addr, 0x1020)
    second_branch = _conditional_block(arch, manager, 0x1020, second_condition, second_exit.addr, 0x1040)
    fork = _conditional_block(arch, manager, 0x1040, fork_condition, first_predecessor.addr, second_predecessor.addr)

    graph = networkx.DiGraph(
        [
            (head, first_exit),
            (head, second_branch),
            (second_branch, second_exit),
            (second_branch, fork),
            (fork, first_predecessor),
            (fork, second_predecessor),
            (first_predecessor, target),
            (second_predecessor, target),
        ]
    )

    condition_processor.recover_reaching_conditions(None, graph=graph)
    guarding_condition = condition_processor.guarding_conditions[target]
    first_divergence = condition_processor.recover_edge_condition(graph, head, first_exit)
    second_divergence = condition_processor.recover_edge_condition(graph, second_branch, second_exit)

    solver = claripy.Solver()
    for first_diverges, second_diverges, target_is_guarded in (
        (False, False, True),
        (False, True, False),
        (True, False, False),
        (True, True, False),
    ):
        path_constraints = (
            first_divergence if first_diverges else claripy.Not(first_divergence),
            second_divergence if second_diverges else claripy.Not(second_divergence),
        )
        assert solver.satisfiable(extra_constraints=path_constraints)
        contradicting_guard = claripy.Not(guarding_condition) if target_is_guarded else guarding_condition
        assert not solver.satisfiable(extra_constraints=(*path_constraints, contradicting_guard))


def test_guarding_condition_includes_divergence_path_context():
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)

    left_exit = Block(0x1030, 1)
    right_exit = Block(0x1060, 1)
    left_predecessor = Block(0x1070, 1)
    right_predecessor = Block(0x1080, 1)
    target = Block(0x1090, 1)

    head = _conditional_block(arch, manager, 0x1000, _condition(arch, manager, "rax"), 0x1010, 0x1040)
    left_branch = _conditional_block(
        arch, manager, 0x1010, _condition(arch, manager, "rbx"), left_exit.addr, left_predecessor.addr
    )
    right_branch = _conditional_block(
        arch, manager, 0x1040, _condition(arch, manager, "rcx"), right_exit.addr, right_predecessor.addr
    )

    graph = networkx.DiGraph(
        [
            (head, left_branch),
            (head, right_branch),
            (left_branch, left_exit),
            (left_branch, left_predecessor),
            (right_branch, right_exit),
            (right_branch, right_predecessor),
            (left_predecessor, target),
            (right_predecessor, target),
        ]
    )

    condition_processor.recover_reaching_conditions(None, graph=graph)
    guarding_condition = condition_processor.guarding_conditions[target]
    take_left = condition_processor.recover_edge_condition(graph, head, left_branch)
    left_divergence = condition_processor.recover_edge_condition(graph, left_branch, left_exit)
    right_divergence = condition_processor.recover_edge_condition(graph, right_branch, right_exit)

    solver = claripy.Solver()
    for takes_left in (False, True):
        for left_diverges in (False, True):
            for right_diverges in (False, True):
                path_constraints = (
                    take_left if takes_left else claripy.Not(take_left),
                    left_divergence if left_diverges else claripy.Not(left_divergence),
                    right_divergence if right_diverges else claripy.Not(right_divergence),
                )
                target_is_guarded = (takes_left and not left_diverges) or (not takes_left and not right_diverges)
                contradicting_guard = claripy.Not(guarding_condition) if target_is_guarded else guarding_condition
                assert solver.satisfiable(extra_constraints=path_constraints)
                assert not solver.satisfiable(extra_constraints=(*path_constraints, contradicting_guard))


def test_guarding_condition_respects_disabled_simplification(monkeypatch):
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)

    exit_node = Block(0x1010, 1)
    first_predecessor = Block(0x1030, 1)
    second_predecessor = Block(0x1040, 1)
    target = Block(0x1050, 1)
    head = _conditional_block(arch, manager, 0x1000, _condition(arch, manager, "rax"), exit_node.addr, 0x1020)
    fork = _conditional_block(
        arch, manager, 0x1020, _condition(arch, manager, "rbx"), first_predecessor.addr, second_predecessor.addr
    )
    graph = networkx.DiGraph(
        [
            (head, exit_node),
            (head, fork),
            (fork, first_predecessor),
            (fork, second_predecessor),
            (first_predecessor, target),
            (second_predecessor, target),
        ]
    )

    def fail_on_simplification(_):
        raise AssertionError("condition simplification must remain disabled")

    monkeypatch.setattr(condition_processor, "simplify_condition", fail_on_simplification)
    condition_processor.recover_reaching_conditions(None, graph=graph, simplify_conditions=False)
    assert target in condition_processor.guarding_conditions

from __future__ import annotations

import networkx
import pytest

import angr
from angr import ailment
from angr.ailment.statement import Statement
from angr.analyses.s_reaching_definitions.s_rda_model import SRDAModel, populate_model
from angr.analyses.s_reaching_definitions.s_rda_view import SRDAView
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType
from angr.utils.ssa import CALL_RESULT_FIXUP_TAG


def _reg_vvar(project, idx, varid, reg_name, bits, ins_addr):
    return ailment.Expr.VirtualVariable(
        idx,
        varid,
        bits,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers[reg_name][0],
        ins_addr=ins_addr,
    )


@pytest.mark.parametrize("fold_call_into_fixup", (False, True))
def test_call_clobbers_are_ordered_before_explicit_register_definitions(fold_call_into_fixup):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    arch = project.arch
    rax_offset = arch.registers["rax"][0]
    rdi_offset = arch.registers["rdi"][0]
    rbx_offset = arch.registers["rbx"][0]

    old_ax = _reg_vvar(project, 0, 1, "rax", 16, 0x1000)
    old_rax = _reg_vvar(project, 1, 2, "rax", 64, 0x1001)
    old_rdi = _reg_vvar(project, 2, 3, "rdi", 64, 0x1002)
    old_rbx = _reg_vvar(project, 3, 4, "rbx", 64, 0x1003)
    final_rax = _reg_vvar(project, 4, 6, "rax", 64, 0x1005)

    statements: list[Statement] = [
        ailment.Stmt.Assignment(10, old_ax, ailment.Expr.Const(11, 0x1234, 16), ins_addr=0x1000),
        ailment.Stmt.Assignment(12, old_rax, ailment.Expr.Const(13, 0x12345678, 64), ins_addr=0x1001),
        ailment.Stmt.Assignment(14, old_rdi, ailment.Expr.Const(15, 1, 64), ins_addr=0x1002),
        ailment.Stmt.Assignment(16, old_rbx, ailment.Expr.Const(17, 2, 64), ins_addr=0x1003),
    ]
    call = ailment.Expr.Call(
        18,
        ailment.Expr.Const(19, 0x4000, 64),
        args=[],
        bits=32,
        ins_addr=0x1004,
    )
    offset = ailment.Expr.Const(20, 0, 64)

    if fold_call_into_fixup:
        fixup_src = ailment.Expr.Insert(21, old_rax, offset, call, arch.register_endness, ins_addr=0x1004)
        statements.append(
            ailment.Stmt.Assignment(
                22,
                final_rax,
                fixup_src,
                **{"ins_addr": 0x1004, CALL_RESULT_FIXUP_TAG: True},
            )
        )
        expected_rax_defs = {8: final_rax.varid}
    else:
        raw_eax = _reg_vvar(project, 5, 5, "rax", 32, 0x1004)
        statements.extend(
            [
                ailment.Stmt.SideEffectStatement(21, call, ret_expr=raw_eax, ins_addr=0x1004),
                ailment.Stmt.Assignment(
                    22,
                    final_rax,
                    ailment.Expr.Insert(
                        23,
                        old_rax,
                        offset,
                        raw_eax,
                        arch.register_endness,
                        ins_addr=0x1005,
                    ),
                    **{"ins_addr": 0x1005, CALL_RESULT_FIXUP_TAG: True},
                ),
            ]
        )
        expected_rax_defs = {4: raw_eax.varid, 8: final_rax.varid}

    call_block = ailment.Block(0x1000, 0x10, statements=statements)
    successor = ailment.Block(0x1010, 1, statements=[])
    graph = networkx.DiGraph([(call_block, successor)])
    model = SRDAModel(graph, set(), arch, platform="Linux")
    populate_model(model, {(block.addr, block.idx): block for block in graph}, set())
    view = SRDAView(model)

    observation = ("node", (successor.addr, successor.idx), ObservationPointType.OP_BEFORE)
    dominance_result = view.observe([observation], entry=call_block)[observation]
    forward_result = view.observe([observation])[observation]

    assert dominance_result == forward_result
    assert dominance_result[rax_offset] == expected_rax_defs
    assert rdi_offset not in dominance_result
    assert dominance_result[rbx_offset] == {8: old_rbx.varid}


@pytest.mark.parametrize("fold_call_into_fixup", (False, True))
def test_backward_register_queries_stop_at_wrapped_calls(fold_call_into_fixup):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    arch = project.arch
    rax_offset = arch.registers["rax"][0]
    rdi_offset = arch.registers["rdi"][0]
    rbx_offset = arch.registers["rbx"][0]

    old_rax = _reg_vvar(project, 0, 1, "rax", 64, 0x1000)
    old_rdi = _reg_vvar(project, 1, 2, "rdi", 64, 0x1001)
    old_rbx = _reg_vvar(project, 2, 3, "rbx", 64, 0x1002)
    call = ailment.Expr.Call(
        3,
        ailment.Expr.Const(4, 0x4000, 64),
        args=[],
        bits=32,
        ins_addr=0x1004,
    )
    statements: list[Statement] = [
        ailment.Stmt.Assignment(5, old_rax, ailment.Expr.Const(6, 1, 64), ins_addr=0x1000),
        ailment.Stmt.Assignment(7, old_rdi, ailment.Expr.Const(8, 2, 64), ins_addr=0x1001),
        ailment.Stmt.Assignment(9, old_rbx, ailment.Expr.Const(10, 3, 64), ins_addr=0x1002),
    ]

    if fold_call_into_fixup:
        call_result = _reg_vvar(project, 11, 4, "rax", 64, 0x1004)
        statements.append(
            ailment.Stmt.Assignment(
                12,
                call_result,
                ailment.Expr.Insert(
                    13,
                    old_rax,
                    ailment.Expr.Const(14, 0, 64),
                    call,
                    arch.register_endness,
                    ins_addr=0x1004,
                ),
                **{"ins_addr": 0x1004, CALL_RESULT_FIXUP_TAG: True},
            )
        )
        result_min_size = 8
    else:
        call_result = _reg_vvar(project, 11, 4, "rax", 32, 0x1004)
        statements.append(ailment.Stmt.Assignment(12, call_result, call, ins_addr=0x1004))
        result_min_size = 4

    block = ailment.Block(0x1000, 0x10, idx=0, statements=statements)
    graph = networkx.DiGraph()
    graph.add_node(block)
    model = SRDAModel(graph, set(), arch, platform="Linux")
    populate_model(model, {(block.addr, block.idx): block}, set())
    view = SRDAView(model)
    call_stmt_idx = len(statements) - 1

    query_results = (
        (
            view.get_reg_vvar_by_stmt(
                rax_offset,
                result_min_size,
                block.addr,
                block.idx,
                call_stmt_idx,
                ObservationPointType.OP_AFTER,
            ),
            view.get_reg_vvar_by_stmt(
                rdi_offset,
                8,
                block.addr,
                block.idx,
                call_stmt_idx,
                ObservationPointType.OP_AFTER,
            ),
            view.get_reg_vvar_by_stmt(
                rbx_offset,
                8,
                block.addr,
                block.idx,
                call_stmt_idx,
                ObservationPointType.OP_AFTER,
            ),
        ),
        (
            view.get_reg_vvar_by_insn(
                rax_offset,
                result_min_size,
                0x1004,
                ObservationPointType.OP_AFTER,
                block_idx=block.idx,
            ),
            view.get_reg_vvar_by_insn(
                rdi_offset,
                8,
                0x1004,
                ObservationPointType.OP_AFTER,
                block_idx=block.idx,
            ),
            view.get_reg_vvar_by_insn(
                rbx_offset,
                8,
                0x1004,
                ObservationPointType.OP_AFTER,
                block_idx=block.idx,
            ),
        ),
    )

    for result_vvar, rdi_vvar, rbx_vvar in query_results:
        assert result_vvar is not None and result_vvar.varid == call_result.varid
        assert rdi_vvar is None
        assert rbx_vvar is not None and rbx_vvar.varid == old_rbx.varid

    if not fold_call_into_fixup:
        # The 32-bit result does not satisfy a 64-bit query, but the call still blocks the old 64-bit RAX definition.
        assert (
            view.get_reg_vvar_by_stmt(
                rax_offset,
                8,
                block.addr,
                block.idx,
                call_stmt_idx,
                ObservationPointType.OP_AFTER,
            )
            is None
        )


if __name__ == "__main__":
    pytest.main(args=[__file__, "-v"])

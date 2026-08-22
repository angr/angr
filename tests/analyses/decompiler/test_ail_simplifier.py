from __future__ import annotations

import networkx
import pytest

import angr
from angr import ailment


@pytest.mark.parametrize(
    ("ret_varid", "fp_ret_varid", "avoid_varid"),
    (
        (1, 2, 1),
        (2, 1, 2),
        (1, 2, 2),
        (2, 1, 1),
    ),
)
def test_avoided_result_of_multi_result_call_survives_dead_sibling(ret_varid, fp_ret_varid, avoid_varid):
    project = angr.load_shellcode(b"\xc3", arch="AMD64", load_address=0)
    function = project.kb.functions.function(addr=0, create=True)
    assert function is not None
    manager = ailment.Manager(arch=project.arch)
    ret_expr = ailment.Expr.VirtualVariable(
        manager.next_atom(),
        ret_varid,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.get_register_offset("rax"),
    )
    fp_ret_expr = ailment.Expr.VirtualVariable(
        manager.next_atom(),
        fp_ret_varid,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.get_register_offset("xmm0"),
    )
    call = ailment.Expr.Call(
        manager.next_atom(),
        ailment.Expr.Const(manager.next_atom(), 0x100, project.arch.bits),
        args=[],
        bits=project.arch.bits,
    )
    block = ailment.Block(
        0,
        1,
        statements=[
            ailment.Stmt.SideEffectStatement(
                manager.next_atom(),
                call,
                ret_expr=ret_expr,
                fp_ret_expr=fp_ret_expr,
                ins_addr=0,
            )
        ],
    )
    graph = networkx.DiGraph()
    graph.add_node(block)

    simplifier = project.analyses.AILSimplifier(
        function,
        func_graph=graph,
        ail_manager=manager,
        avoid_vvar_ids={avoid_varid},
        fold_expressions=False,
        rewrite_ccalls=False,
        rewrite_dirty=False,
    )

    [statement] = next(iter(simplifier.func_graph)).statements
    assert isinstance(statement, ailment.Stmt.SideEffectStatement)
    results = [result for result in (statement.ret_expr, statement.fp_ret_expr) if result is not None]
    assert len(results) == 1
    assert isinstance(results[0], ailment.Expr.VirtualVariable)
    assert results[0].varid == avoid_varid

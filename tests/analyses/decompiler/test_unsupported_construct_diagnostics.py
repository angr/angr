from __future__ import annotations

import archinfo

import angr
from angr import ailment
from angr.analyses.decompiler import UnsupportedConstruct, UnsupportedConstructLocation
from angr.analyses.decompiler.structurer_nodes import SequenceNode
from angr.sim_type import SimTypeFunction, SimTypeInt


def _codegen(statements):
    arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
    project = angr.load_shellcode(
        b"\xc3",
        arch,
        0,
        0,
        engine=angr.engines.UberEnginePcode,
        rebase_granularity=0x10,
    )
    function = project.kb.functions.function(addr=0, create=True)
    assert function is not None
    function.prototype = SimTypeFunction([], SimTypeInt()).with_arch(arch)
    block = ailment.Block(0, 1, statements=statements)
    sequence = SequenceNode(0, nodes=[block])
    return project, function, project.analyses.CStructuredCodeGenerator(function, sequence)


def _dirty_statement(idx, operation, ins_addr, stmt_idx):
    tags = {"ins_addr": ins_addr, "vex_block_addr": 0x100, "vex_stmt_idx": stmt_idx}
    expression = ailment.Expr.DirtyExpression(
        idx,
        operation,
        [ailment.Expr.Const(idx + 1, idx, 16)],
        bits=16,
        **tags,
    )
    return ailment.Stmt.DirtyStatement(idx + 2, expression, **tags)


def test_unsupported_pcode_construct_diagnostics_are_structured_and_stable():
    nested_popcount = ailment.Expr.DirtyExpression(
        3,
        "POPCOUNT",
        [ailment.Expr.Const(4, 1, 16)],
        bits=16,
        ins_addr=0x102,
        vex_block_addr=0x100,
        vex_stmt_idx=1,
    )
    float_sqrt = ailment.Expr.DirtyExpression(
        6,
        "FLOAT_SQRT",
        [nested_popcount],
        bits=16,
        ins_addr=0x106,
        vex_block_addr=0x100,
        vex_stmt_idx=3,
    )
    project, function, codegen = _codegen(
        [
            _dirty_statement(0, "CALLOTHER", 0x100, 0),
            _dirty_statement(9, "CALLOTHER", 0x104, 2),
            ailment.Stmt.DirtyStatement(
                12,
                float_sqrt,
                ins_addr=0x106,
                vex_block_addr=0x100,
                vex_stmt_idx=3,
            ),
        ]
    )

    expected = (
        UnsupportedConstruct(
            kind="dirty_expression",
            operation="CALLOTHER",
            count=2,
            locations=(
                UnsupportedConstructLocation(0x100, 0x100, 0),
                UnsupportedConstructLocation(0x104, 0x100, 2),
            ),
        ),
        UnsupportedConstruct(
            kind="dirty_expression",
            operation="FLOAT_SQRT",
            count=1,
            locations=(UnsupportedConstructLocation(0x106, 0x100, 3),),
        ),
        UnsupportedConstruct(
            kind="dirty_expression",
            operation="POPCOUNT",
            count=1,
            locations=(UnsupportedConstructLocation(0x102, 0x100, 1),),
        ),
    )
    assert codegen.unsupported_constructs == expected

    restored = codegen.parse(codegen.serialize(), project=project, kb=project.kb, func=function)
    assert restored.unsupported_constructs == expected


def test_ordinary_ail_has_no_unsupported_construct_diagnostics():
    _, _, codegen = _codegen(
        [
            ailment.Stmt.Return(
                0,
                [ailment.Expr.BinaryOp(1, "Add", [ailment.Expr.Const(2, 1, 16), ailment.Expr.Const(3, 2, 16)])],
                ins_addr=0,
            )
        ]
    )

    assert codegen.unsupported_constructs == ()

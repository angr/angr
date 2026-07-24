# pylint: disable=protected-access
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import networkx
import pytest

import angr
from angr import ailment
from angr.ailment.expression import Call, Expression
from angr.ailment.statement import Return, SideEffectStatement
from angr.analyses.decompiler.ail_simplifier import AILSimplifier
from angr.analyses.decompiler.block_io_finder import BlockIOFinder
from angr.analyses.decompiler.callsite_maker import CallSiteMaker
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.decompiler.expression_narrower import EffectiveSizeExtractor, ExpressionNarrower
from angr.analyses.decompiler.optimization_passes.call_stmt_rewriter import CallStatementRewriter
from angr.analyses.decompiler.optimization_passes.ite_region_converter import ITERegionConverter
from angr.analyses.decompiler.optimization_passes.return_duplicator_base import FreshVirtualVariableRewriter
from angr.analyses.decompiler.peephole_optimizations.rewrite_cxx_operator_calls import RewriteCxxOperatorCalls
from angr.analyses.decompiler.region_simplifiers.expr_folding import ExpressionCounter
from angr.analyses.decompiler.semantic_naming.call_result_naming import CallResultNaming
from angr.analyses.decompiler.semantic_naming.pointer_naming import PointerNaming
from angr.analyses.decompiler.ssailification.rewriting_engine import SimEngineSSARewriting
from angr.analyses.decompiler.ssailification.rewriting_state import RewritingState
from angr.analyses.decompiler.ssailification.ssailification import Def, UDef
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStructuredCodeGenerator,
)
from angr.analyses.decompiler.structured_codegen.rust import RustFunctionCall, RustStructuredCodeGenerator
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.analyses.deobfuscator.string_obf_opt_passes import StringObfType3Rewriter
from angr.analyses.s_reaching_definitions import SRDAModel, SRDAView
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions.atoms import Register as RegisterAtom
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType
from angr.sim_type import SimTypeDouble, SimTypeFunction, SimTypeLongLong
from angr.sim_variable import SimRegisterVariable
from angr.utils.ssa import CALL_RESULT_FIXUP_TAG, find_semantic_terminal_call


def _rebuild_call_expr(call: Call, *, args: list[Expression] | None = None, bits: int | None = None) -> Call:
    return cast(
        Call,
        ailment.Expr.Call(
            call.idx,
            call.target,
            args=call.args if args is None else args,
            bits=call.bits if bits is None else bits,
            arg_vvars=call.arg_vvars,
            **call.tags,
        ),
    )


def _rebuild_call_stmt(
    stmt: SideEffectStatement,
    *,
    expr: Expression | None = None,
    keep_ret_expr: bool = True,
    keep_fp_ret_expr: bool = True,
) -> SideEffectStatement:
    return cast(
        SideEffectStatement,
        ailment.Stmt.SideEffectStatement(
            stmt.idx,
            stmt.expr if expr is None else expr,
            ret_expr=stmt.ret_expr if keep_ret_expr else None,
            fp_ret_expr=stmt.fp_ret_expr if keep_fp_ret_expr else None,
            **stmt.tags,
        ),
    )


def _make_dual_vvar_call(project, *, ret_varid=1, fp_varid=2):
    ret_expr = ailment.Expr.VirtualVariable(
        0,
        ret_varid,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["rax"][0],
        ins_addr=0x1000,
    )
    fp_ret_expr = ailment.Expr.VirtualVariable(
        1,
        fp_varid,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["xmm0"][0],
        ins_addr=0x1000,
    )
    call = ailment.Expr.Call(2, "callee", args=[], bits=64, ins_addr=0x1000)
    stmt = ailment.Stmt.SideEffectStatement(
        3,
        call,
        ret_expr=ret_expr,
        fp_ret_expr=fp_ret_expr,
        ins_addr=0x1000,
    )
    return stmt, ret_expr, fp_ret_expr


def _single_block_graph(block):
    graph = networkx.DiGraph()
    graph.add_node(block)
    return graph


def _count_calls(block):
    class CallCounter(ailment.AILBlockViewer):
        """Count call expressions while walking a test block."""

        def __init__(self):
            super().__init__()
            self.count = 0

        def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
            self.count += 1
            super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    counter = CallCounter()
    counter.walk(block)
    return counter.count


def _rewrite_ssa_block(project, block, def_to_udef, *, incomplete_defs=None, stackvars=False):
    function = project.kb.functions.function(addr=block.addr, create=True)
    state = RewritingState(
        AILCodeLocation(block.addr, block.idx, 0, block.addr),
        project.arch,
        function,
        block,
    )
    engine = SimEngineSSARewriting(
        project,
        ail_manager=ailment.Manager(arch=project.arch),
        def_to_udef=def_to_udef,
        incomplete_defs=set() if incomplete_defs is None else incomplete_defs,
        stackvars=stackvars,
        fail_fast=True,
    )
    engine.process(state, block=block)
    assert engine.out_block is not None
    return engine.out_block


def _make_codegen_stubs(project, handle):
    c_codegen = cast(Any, object.__new__(CStructuredCodeGenerator))
    c_codegen.kb = project.kb
    c_codegen.show_demangled_name = False
    c_codegen.show_disambiguated_name = False
    c_codegen.ident_counters = {}
    c_codegen._next_node_idx = 1
    c_codegen._handle = handle

    rust_codegen = cast(Any, object.__new__(RustStructuredCodeGenerator))
    rust_codegen.kb = project.kb
    rust_codegen._variable_map = SimpleNamespace(prototype=lambda _: None)
    rust_codegen.show_demangled_name = False
    rust_codegen._handle = handle
    return c_codegen, rust_codegen


def _simplify_single_block(project, block, *, unify_variables, fold_expressions=False):
    function = project.kb.functions.function(addr=block.addr, create=True)
    simplifier = project.analyses[AILSimplifier].prep()(
        function,
        _single_block_graph(block),
        ailment.Manager(arch=project.arch),
        fold_expressions=fold_expressions,
        narrow_expressions=False,
        rewrite_ccalls=False,
        rewrite_dirty=False,
        unify_variables=unify_variables,
        use_callee_saved_regs_at_return=False,
    )
    assert len(simplifier.func_graph) == 1
    return next(iter(simplifier.func_graph))


def test_generic_block_rewriter_visits_both_call_return_candidates():
    class ReturnCandidateRewriter(ailment.AILBlockRewriter):
        """Give each provisional call-return definition a distinct virtual-variable ID."""

        def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
            new_varids = {1: 11, 2: 12}
            if expr.varid not in new_varids:
                return expr
            return ailment.Expr.VirtualVariable(
                expr.idx,
                new_varids[expr.varid],
                expr.bits,
                expr.category,
                expr.oident,
                **expr.tags,
            )

    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, _, _ = _make_dual_vvar_call(project)

    rewritten = ReturnCandidateRewriter().walk_statement(call_stmt)

    assert isinstance(rewritten, SideEffectStatement)
    assert isinstance(rewritten.ret_expr, ailment.Expr.VirtualVariable)
    assert isinstance(rewritten.fp_ret_expr, ailment.Expr.VirtualVariable)
    assert rewritten.ret_expr.varid == 11
    assert rewritten.fp_ret_expr.varid == 12


@pytest.mark.parametrize("selected_return", ("integer", "floating_point"))
def test_ssa_rewriting_preserves_integer_and_floating_point_call_returns(selected_return):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    manager = ailment.Manager(arch=project.arch)
    function = project.kb.functions.function(addr=0x1000, create=True)

    ret_expr = ailment.Expr.Register(0, project.arch.registers["rax"][0], 64, ins_addr=0x1000)
    fp_ret_expr = ailment.Expr.Register(1, project.arch.registers["xmm0"][0], 64, ins_addr=0x1000)
    selected_expr = ret_expr if selected_return == "integer" else fp_ret_expr
    selected_use = ailment.Expr.Register(2, selected_expr.reg_offset, 64, ins_addr=0x1005)
    dst = ailment.Expr.Register(3, project.arch.registers["rbx"][0], 64, ins_addr=0x1005)
    call = ailment.Expr.Call(4, "callee", args=[], bits=64, ins_addr=0x1000)
    block = ailment.Block(
        0x1000,
        6,
        statements=[
            ailment.Stmt.SideEffectStatement(
                5,
                call,
                ret_expr=ret_expr,
                fp_ret_expr=fp_ret_expr,
                ins_addr=0x1000,
            ),
            ailment.Stmt.Assignment(6, dst, selected_use, ins_addr=0x1005),
        ],
    )
    def_to_udef: dict[Def, UDef] = {
        ret_expr: ("reg", ret_expr.reg_offset, ret_expr.size),
        fp_ret_expr: ("reg", fp_ret_expr.reg_offset, fp_ret_expr.size),
        dst: ("reg", dst.reg_offset, dst.size),
    }
    state = RewritingState(
        AILCodeLocation(block.addr, block.idx, 0, block.addr),
        project.arch,
        function,
        block,
    )
    engine = SimEngineSSARewriting(
        project,
        ail_manager=manager,
        def_to_udef=def_to_udef,
        incomplete_defs=set(),
        fail_fast=True,
    )

    call_outputs = BlockIOFinder(block, project).outputs_by_stmt[0]
    assert {output.reg_offset for output in call_outputs if isinstance(output, RegisterAtom)} == {
        ret_expr.reg_offset,
        fp_ret_expr.reg_offset,
    }

    engine.process(state, block=block)

    assert engine.out_block is not None
    call_stmt, use_stmt = engine.out_block.statements
    assert isinstance(call_stmt, ailment.Stmt.SideEffectStatement)
    assert isinstance(call_stmt.ret_expr, ailment.Expr.VirtualVariable)
    assert isinstance(call_stmt.fp_ret_expr, ailment.Expr.VirtualVariable)
    assert call_stmt.ret_expr.varid != call_stmt.fp_ret_expr.varid
    assert isinstance(use_stmt, ailment.Stmt.Assignment)
    assert isinstance(use_stmt.src, ailment.Expr.VirtualVariable)
    selected_vvar = call_stmt.ret_expr if selected_return == "integer" else call_stmt.fp_ret_expr
    assert use_stmt.src.varid == selected_vvar.varid


@pytest.mark.parametrize("selected_return", ("integer", "floating_point"))
def test_ssa_rewriting_preserves_selected_vvar_call_return_on_later_pass(selected_return):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    ret_expr = ailment.Expr.VirtualVariable(
        0,
        1,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["rax"][0],
        ins_addr=0x1000,
    )
    fp_ret_expr = ailment.Expr.VirtualVariable(
        1,
        2,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["xmm0"][0],
        ins_addr=0x1000,
    )
    selected_expr = ret_expr if selected_return == "integer" else fp_ret_expr
    call = ailment.Expr.Call(2, "callee", args=[], bits=64, ins_addr=0x1000)
    call_stmt = ailment.Stmt.SideEffectStatement(
        3,
        call,
        ret_expr=selected_expr if selected_return == "integer" else None,
        fp_ret_expr=selected_expr if selected_return == "floating_point" else None,
        ins_addr=0x1000,
    )
    use_stmt = ailment.Stmt.Return(4, [selected_expr], ins_addr=0x1001)
    block = ailment.Block(0x1000, 2, statements=[call_stmt, use_stmt])

    rewritten = _rewrite_ssa_block(project, block, {})

    rewritten_call, rewritten_use = rewritten.statements
    assert isinstance(rewritten_call, SideEffectStatement)
    rewritten_result = rewritten_call.ret_expr if selected_return == "integer" else rewritten_call.fp_ret_expr
    assert isinstance(rewritten_result, ailment.Expr.VirtualVariable)
    assert rewritten_result.varid == selected_expr.varid
    assert isinstance(rewritten_use, Return)
    assert isinstance(rewritten_use.ret_exprs[0], ailment.Expr.VirtualVariable)
    assert rewritten_use.ret_exprs[0].varid == rewritten_result.varid


def test_ssa_dual_call_return_preserves_widened_xmm_definition():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    rax_offset = project.arch.registers["rax"][0]
    xmm0_offset = project.arch.registers["xmm0"][0]
    xmm1_offset = project.arch.registers["xmm1"][0]

    prior_fp_def = ailment.Expr.Register(0, xmm0_offset, 128, ins_addr=0x1000)
    ret_expr = ailment.Expr.Register(1, rax_offset, 64, ins_addr=0x1001)
    fp_ret_expr = ailment.Expr.Register(2, xmm0_offset, 64, ins_addr=0x1001)
    fp_use = ailment.Expr.Register(3, xmm0_offset, 128, ins_addr=0x1005)
    use_dst = ailment.Expr.Register(4, xmm1_offset, 128, ins_addr=0x1005)
    stack_ptr = ailment.Expr.StackBaseOffset(5, 64, -0x20, ins_addr=0x1001)
    call = ailment.Expr.Call(6, "callee", args=[stack_ptr], bits=64, ins_addr=0x1001)
    block = ailment.Block(
        0x1000,
        6,
        statements=[
            ailment.Stmt.Assignment(
                7,
                prior_fp_def,
                ailment.Expr.Const(8, 0x112233445566778899AABBCCDDEEFF00, 128),
                ins_addr=0x1000,
            ),
            ailment.Stmt.SideEffectStatement(
                9,
                call,
                ret_expr=ret_expr,
                fp_ret_expr=fp_ret_expr,
                ins_addr=0x1001,
            ),
            ailment.Stmt.Assignment(10, use_dst, fp_use, ins_addr=0x1005),
        ],
    )
    def_to_udef: dict[Def, UDef] = {
        prior_fp_def: ("reg", xmm0_offset, 16),
        ret_expr: ("reg", rax_offset, 8),
        fp_ret_expr: ("reg", xmm0_offset, 16),
        use_dst: ("reg", xmm1_offset, 16),
        stack_ptr: ("stack", -0x20, 8),
    }

    rewritten = _rewrite_ssa_block(
        project,
        block,
        def_to_udef,
        incomplete_defs={fp_ret_expr},
        stackvars=True,
    )

    assert len(rewritten.statements) == 4
    prior_stmt, call_stmt, fp_fixup, use_stmt = rewritten.statements
    assert isinstance(prior_stmt, ailment.Stmt.Assignment)
    assert isinstance(prior_stmt.dst, ailment.Expr.VirtualVariable)
    assert isinstance(call_stmt, SideEffectStatement)
    assert isinstance(call_stmt.ret_expr, ailment.Expr.VirtualVariable)
    assert isinstance(call_stmt.fp_ret_expr, ailment.Expr.VirtualVariable)
    assert call_stmt.ret_expr.bits == 64
    assert call_stmt.ret_expr.category == ailment.Expr.VirtualVariableCategory.REGISTER
    assert call_stmt.ret_expr.oident == rax_offset
    assert call_stmt.fp_ret_expr.bits == 64
    assert call_stmt.fp_ret_expr.category == ailment.Expr.VirtualVariableCategory.REGISTER
    assert call_stmt.fp_ret_expr.oident == xmm0_offset

    assert isinstance(fp_fixup, ailment.Stmt.Assignment)
    assert isinstance(fp_fixup.dst, ailment.Expr.VirtualVariable)
    assert fp_fixup.dst.bits == 128
    assert fp_fixup.dst.category == ailment.Expr.VirtualVariableCategory.REGISTER
    assert fp_fixup.dst.oident == xmm0_offset
    assert isinstance(fp_fixup.src, ailment.Expr.Insert)
    assert isinstance(fp_fixup.src.base, ailment.Expr.VirtualVariable)
    assert fp_fixup.src.base.varid == prior_stmt.dst.varid
    assert isinstance(fp_fixup.src.value, ailment.Expr.VirtualVariable)
    assert fp_fixup.src.value.varid == call_stmt.fp_ret_expr.varid
    assert fp_fixup.tags.get(CALL_RESULT_FIXUP_TAG) is True

    assert isinstance(use_stmt, ailment.Stmt.Assignment)
    assert isinstance(use_stmt.src, ailment.Expr.VirtualVariable)
    assert use_stmt.src.varid == fp_fixup.dst.varid
    assert _count_calls(rewritten) == 1

    assert call_stmt.tags.get("extra_defs")
    assert isinstance(call_stmt.expr, ailment.Expr.Call)
    rewritten_arg = call_stmt.expr.args[0]
    assert isinstance(rewritten_arg, ailment.Expr.UnaryOp)
    assert rewritten_arg.tags.get("extra_def") is True
    assert isinstance(rewritten_arg.operand, ailment.Expr.VirtualVariable)
    assert call_stmt.tags["extra_defs"] == [rewritten_arg.operand.varid]
    assert "extra_defs" not in fp_fixup.tags


def test_ssa_dual_call_return_splits_both_widened_definitions():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    rax_offset = project.arch.registers["rax"][0]
    xmm0_offset = project.arch.registers["xmm0"][0]

    prior_ret_def = ailment.Expr.Register(0, rax_offset, 64, ins_addr=0x1000)
    prior_fp_def = ailment.Expr.Register(1, xmm0_offset, 128, ins_addr=0x1000)
    ret_expr = ailment.Expr.Register(2, rax_offset, 32, ins_addr=0x1001)
    fp_ret_expr = ailment.Expr.Register(3, xmm0_offset, 32, ins_addr=0x1001)
    call = ailment.Expr.Call(4, "callee", args=[], bits=32, ins_addr=0x1001)
    block = ailment.Block(
        0x1000,
        2,
        statements=[
            ailment.Stmt.Assignment(
                5,
                prior_ret_def,
                ailment.Expr.Const(6, 0x1122334455667788, 64),
                ins_addr=0x1000,
            ),
            ailment.Stmt.Assignment(
                7,
                prior_fp_def,
                ailment.Expr.Const(8, 0x112233445566778899AABBCCDDEEFF00, 128),
                ins_addr=0x1000,
            ),
            ailment.Stmt.SideEffectStatement(
                9,
                call,
                ret_expr=ret_expr,
                fp_ret_expr=fp_ret_expr,
                ins_addr=0x1001,
            ),
        ],
    )
    def_to_udef: dict[Def, UDef] = {
        prior_ret_def: ("reg", rax_offset, 8),
        prior_fp_def: ("reg", xmm0_offset, 16),
        ret_expr: ("reg", rax_offset, 8),
        fp_ret_expr: ("reg", xmm0_offset, 16),
    }

    rewritten = _rewrite_ssa_block(
        project,
        block,
        def_to_udef,
        incomplete_defs={ret_expr, fp_ret_expr},
    )

    assert len(rewritten.statements) == 5
    prior_ret_stmt, prior_fp_stmt, call_stmt, ret_fixup, fp_fixup = rewritten.statements
    assert isinstance(prior_ret_stmt, ailment.Stmt.Assignment)
    assert isinstance(prior_fp_stmt, ailment.Stmt.Assignment)
    assert isinstance(call_stmt, SideEffectStatement)
    assert isinstance(call_stmt.ret_expr, ailment.Expr.VirtualVariable)
    assert isinstance(call_stmt.fp_ret_expr, ailment.Expr.VirtualVariable)
    assert call_stmt.ret_expr.varid != call_stmt.fp_ret_expr.varid
    for result_vvar, reg_offset in (
        (call_stmt.ret_expr, rax_offset),
        (call_stmt.fp_ret_expr, xmm0_offset),
    ):
        assert result_vvar.bits == 32
        assert result_vvar.category == ailment.Expr.VirtualVariableCategory.REGISTER
        assert result_vvar.oident == reg_offset

    assert isinstance(ret_fixup, ailment.Stmt.Assignment)
    assert isinstance(ret_fixup.dst, ailment.Expr.VirtualVariable)
    assert ret_fixup.dst.bits == 64
    assert ret_fixup.dst.oident == rax_offset
    assert isinstance(ret_fixup.src, ailment.Expr.Insert)
    assert isinstance(ret_fixup.src.base, ailment.Expr.Const)
    assert ret_fixup.src.base.bits == 64
    assert isinstance(ret_fixup.src.value, ailment.Expr.VirtualVariable)
    assert ret_fixup.src.value.varid == call_stmt.ret_expr.varid
    assert ret_fixup.tags.get(CALL_RESULT_FIXUP_TAG) is True

    assert isinstance(fp_fixup, ailment.Stmt.Assignment)
    assert isinstance(fp_fixup.dst, ailment.Expr.VirtualVariable)
    assert fp_fixup.dst.bits == 128
    assert fp_fixup.dst.oident == xmm0_offset
    assert isinstance(fp_fixup.src, ailment.Expr.Insert)
    assert isinstance(fp_fixup.src.base, ailment.Expr.VirtualVariable)
    assert isinstance(prior_fp_stmt.dst, ailment.Expr.VirtualVariable)
    assert fp_fixup.src.base.varid == prior_fp_stmt.dst.varid
    assert isinstance(fp_fixup.src.value, ailment.Expr.VirtualVariable)
    assert fp_fixup.src.value.varid == call_stmt.fp_ret_expr.varid
    assert fp_fixup.tags.get(CALL_RESULT_FIXUP_TAG) is True

    assert _count_calls(rewritten) == 1
    assert "extra_defs" not in call_stmt.tags
    assert "extra_defs" not in ret_fixup.tags
    assert "extra_defs" not in fp_fixup.tags


def test_semantic_terminal_call_skips_only_tagged_result_fixups():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, _, fp_ret_expr = _make_dual_vvar_call(project)
    fp_final = ailment.Expr.VirtualVariable(
        4,
        3,
        128,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["xmm0"][0],
    )
    fixup = ailment.Stmt.Assignment(
        5,
        fp_final,
        ailment.Expr.Insert(
            6,
            ailment.Expr.Const(7, 0, 128),
            ailment.Expr.Const(8, 0, 64),
            fp_ret_expr,
            project.arch.register_endness,
        ),
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    block = ailment.Block(0x1000, 1, statements=[call_stmt, fixup])

    terminal_call = find_semantic_terminal_call(block)

    assert terminal_call is not None
    assert terminal_call[0] == 0
    assert terminal_call[1].likes(call_stmt)
    assert terminal_call[2].likes(call_stmt.expr)

    ordinary_tail = ailment.Stmt.Assignment(9, fp_final, ailment.Expr.Const(10, 0, 128))
    assert find_semantic_terminal_call(block.copy(statements=[call_stmt, fixup, ordinary_tail])) is None


def test_semantic_terminal_call_finds_call_folded_into_tagged_fixup():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call = ailment.Expr.Call(0, "callee", args=[], bits=64)
    final = ailment.Expr.VirtualVariable(
        1,
        1,
        128,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["xmm0"][0],
    )
    folded_fixup = ailment.Stmt.Assignment(
        2,
        final,
        ailment.Expr.Insert(
            3,
            ailment.Expr.Const(4, 0, 128),
            ailment.Expr.Const(5, 0, 64),
            call,
            project.arch.register_endness,
        ),
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    trailing_fixup = ailment.Stmt.Assignment(
        6,
        final,
        ailment.Expr.Const(7, 0, 128),
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    block = ailment.Block(0x1000, 1, statements=[folded_fixup, trailing_fixup])

    terminal_call = find_semantic_terminal_call(block)

    assert terminal_call is not None
    assert terminal_call[0] == 0
    assert terminal_call[1].likes(folded_fixup)
    assert terminal_call[2].likes(call)


def test_ail_simplifier_call_barrier_is_limited_to_side_effects_and_tagged_fixups():
    call = ailment.Expr.Call(0, "callee", args=[], bits=64)
    result = ailment.Expr.VirtualVariable(
        1,
        1,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=0,
    )
    target = ailment.Block(0x2000, 1, statements=[])
    simplifier = object.__new__(AILSimplifier)

    ordinary_call = ailment.Stmt.Assignment(2, result, call)
    ordinary_start = ailment.Block(0x1000, 1, statements=[ordinary_call])
    simplifier.func_graph = networkx.DiGraph([(ordinary_start, target)])
    assert simplifier._loc_within_superblock(
        ordinary_start,
        target.addr,
        target.idx,
        terminate_with_calls=True,
    )

    folded_fixup = ailment.Stmt.Assignment(
        3,
        result,
        call,
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    fixup_start = ailment.Block(0x1100, 1, statements=[folded_fixup])
    simplifier.func_graph = networkx.DiGraph([(fixup_start, target)])
    assert not simplifier._loc_within_superblock(
        fixup_start,
        target.addr,
        target.idx,
        terminate_with_calls=True,
    )

    side_effect = ailment.Stmt.SideEffectStatement(4, call, ret_expr=result)
    side_effect_start = ailment.Block(0x1200, 1, statements=[side_effect])
    simplifier.func_graph = networkx.DiGraph([(side_effect_start, target)])
    assert not simplifier._loc_within_superblock(
        side_effect_start,
        target.addr,
        target.idx,
        terminate_with_calls=True,
    )


@pytest.mark.parametrize("folded_call", (False, True))
@pytest.mark.parametrize("probe_kind", ("rust", "windows"))
def test_clinic_removes_probe_call_and_tagged_result_suffix(folded_call, probe_kind):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    if probe_kind == "windows":
        assert project.simos is not None
        project.simos.name = "Win32"
    target = 0x2000
    callee = project.kb.functions.function(addr=target, create=True)
    assert callee is not None
    if probe_kind == "rust":
        callee.info["is_rust_probestack"] = True
    else:
        callee.name = "__chkstk"

    setup_dst = ailment.Expr.VirtualVariable(
        0,
        1,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["rcx"][0],
    )
    setup = ailment.Stmt.Assignment(1, setup_dst, ailment.Expr.Const(2, 1, 64))
    call = ailment.Expr.Call(3, ailment.Expr.Const(4, target, 64), args=[], bits=64)
    result = ailment.Expr.VirtualVariable(
        5,
        2,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["rax"][0],
    )
    final = ailment.Expr.VirtualVariable(
        6,
        3,
        128,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["rax"][0],
    )
    fixup = ailment.Stmt.Assignment(
        7,
        final,
        ailment.Expr.Insert(
            8,
            ailment.Expr.Const(9, 0, 128),
            ailment.Expr.Const(10, 0, 64),
            call if folded_call else result,
            project.arch.register_endness,
        ),
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    if folded_call:
        call_and_suffix = [
            fixup,
            ailment.Stmt.Assignment(
                11,
                final,
                ailment.Expr.Const(12, 0, 128),
                **{CALL_RESULT_FIXUP_TAG: True},
            ),
        ]
    else:
        call_and_suffix = [ailment.Stmt.SideEffectStatement(11, call, ret_expr=result), fixup]
    block = ailment.Block(0x1000, 1, statements=[setup, *call_and_suffix])
    successor = ailment.Block(0x1010, 1, statements=[])
    graph = networkx.DiGraph([(block, successor)])
    clinic = cast(Clinic, SimpleNamespace(project=project))

    if probe_kind == "rust":
        Clinic._rewrite_rust_probestack_call(clinic, graph)
    else:
        Clinic._rewrite_windows_chkstk_call(clinic, graph)

    assert len(block.statements) == 1
    assert block.statements[0].likes(setup)


def test_callsite_maker_preserves_insert_when_call_was_folded_into_tagged_fixup():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    manager = ailment.Manager(arch=project.arch)
    target = 0x2000
    callee = project.kb.functions.function(addr=target, create=True)
    assert callee is not None
    callee.calling_convention = project.factory.cc()
    callee.prototype = SimTypeFunction([], SimTypeDouble()).with_arch(project.arch)

    call = ailment.Expr.Call(
        0,
        ailment.Expr.Const(1, target, 64),
        args=[],
        bits=64,
        ins_addr=0x1000,
    )
    final = ailment.Expr.VirtualVariable(
        2,
        1,
        128,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["xmm0"][0],
        ins_addr=0x1000,
    )
    folded_fixup = ailment.Stmt.Assignment(
        3,
        final,
        ailment.Expr.Insert(
            4,
            ailment.Expr.Const(5, 0, 128),
            ailment.Expr.Const(6, 0, 64),
            call,
            project.arch.register_endness,
        ),
        ins_addr=0x1000,
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    block = ailment.Block(0x1000, 4, idx=0, statements=[folded_fixup])

    result = project.analyses[CallSiteMaker].prep()(block, ail_manager=manager).result_block

    assert result is not None
    assert len(result.statements) == 1
    rewritten_fixup = result.statements[0]
    assert isinstance(rewritten_fixup, ailment.Stmt.Assignment)
    assert rewritten_fixup.tags.get(CALL_RESULT_FIXUP_TAG) is True
    assert rewritten_fixup.dst.bits == 128
    assert isinstance(rewritten_fixup.src, ailment.Expr.Insert)
    assert rewritten_fixup.src.bits == 128
    assert isinstance(rewritten_fixup.src.value, ailment.Expr.Call)
    assert rewritten_fixup.src.value.bits == call.bits
    assert rewritten_fixup.src.value.target.likes(call.target)


@pytest.mark.parametrize(
    ("return_type", "select_fp"),
    [(SimTypeDouble(), True), (SimTypeLongLong(), False)],
)
def test_callsite_maker_selects_typed_result_and_observes_fp_arg_before_tagged_fixup(
    monkeypatch, return_type, select_fp
):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    manager = ailment.Manager(arch=project.arch)
    target = 0x2000
    callee = project.kb.functions.function(addr=target, create=True)
    assert callee is not None
    callee.calling_convention = project.factory.cc()
    callee.prototype = SimTypeFunction([SimTypeDouble()], return_type).with_arch(project.arch)

    rax_offset = project.arch.registers["rax"][0]
    xmm0_offset = project.arch.registers["xmm0"][0]
    fp_arg = ailment.Expr.VirtualVariable(
        0,
        10,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=xmm0_offset,
        ins_addr=0x1000,
    )
    arg_def = ailment.Stmt.Assignment(1, fp_arg, ailment.Expr.Const(2, 0x3FF0000000000000, 64), ins_addr=0x1000)
    ret_expr = ailment.Expr.VirtualVariable(
        3,
        11,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=rax_offset,
        ins_addr=0x1001,
    )
    fp_ret_expr = ailment.Expr.VirtualVariable(
        4,
        12,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=xmm0_offset,
        ins_addr=0x1001,
    )
    call = ailment.Expr.Call(
        5,
        ailment.Expr.Const(6, target, 64),
        args=[],
        bits=64,
        ins_addr=0x1001,
    )
    call_stmt = ailment.Stmt.SideEffectStatement(
        7,
        call,
        ret_expr=ret_expr,
        fp_ret_expr=fp_ret_expr,
        ins_addr=0x1001,
    )
    ret_final = ailment.Expr.VirtualVariable(
        8,
        13,
        128,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=rax_offset,
        ins_addr=0x1001,
    )
    ret_fixup = ailment.Stmt.Assignment(
        9,
        ret_final,
        ailment.Expr.Insert(
            10,
            ailment.Expr.Const(11, 0, 128),
            ailment.Expr.Const(12, 0, 64),
            ret_expr,
            project.arch.register_endness,
        ),
        ins_addr=0x1001,
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    fp_final = ailment.Expr.VirtualVariable(
        13,
        14,
        128,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=xmm0_offset,
        ins_addr=0x1001,
    )
    fp_fixup = ailment.Stmt.Assignment(
        14,
        fp_final,
        ailment.Expr.Insert(
            15,
            ailment.Expr.Const(16, 0, 128),
            ailment.Expr.Const(17, 0, 64),
            fp_ret_expr,
            project.arch.register_endness,
        ),
        ins_addr=0x1001,
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    block = ailment.Block(0x1000, 4, idx=0, statements=[arg_def, call_stmt, ret_fixup, fp_fixup])

    observations = []

    def get_reg_vvar_by_stmt(
        _view,
        reg_offset,
        min_size,
        block_addr,
        block_idx,
        stmt_idx,
        op_type,
    ):
        observations.append((reg_offset, min_size, block_addr, block_idx, stmt_idx, op_type))
        return fp_arg

    monkeypatch.setattr(SRDAView, "get_reg_vvar_by_stmt", get_reg_vvar_by_stmt)
    monkeypatch.setattr(SRDAView, "get_vvar_value", lambda _view, _vvar: None)

    result = (
        project.analyses[CallSiteMaker]
        .prep()(
            block,
            ail_manager=manager,
            reaching_definitions=cast(SRDAModel, SimpleNamespace()),
        )
        .result_block
    )

    assert result is not None
    assert len(result.statements) == 3
    rewritten_call = result.statements[1]
    assert isinstance(rewritten_call, SideEffectStatement)
    if select_fp:
        assert rewritten_call.ret_expr is None
        assert isinstance(rewritten_call.fp_ret_expr, ailment.Expr.VirtualVariable)
        assert rewritten_call.fp_ret_expr.varid == fp_ret_expr.varid
        kept_fixup, discarded_fixup = fp_fixup, ret_fixup
    else:
        assert isinstance(rewritten_call.ret_expr, ailment.Expr.VirtualVariable)
        assert rewritten_call.ret_expr.varid == ret_expr.varid
        assert rewritten_call.fp_ret_expr is None
        kept_fixup, discarded_fixup = ret_fixup, fp_fixup
    assert result.statements[2].likes(kept_fixup)
    assert result.statements[2].tags.get(CALL_RESULT_FIXUP_TAG) is True
    assert all(not stmt.likes(discarded_fixup) for stmt in result.statements)

    assert isinstance(rewritten_call.expr, ailment.Expr.Call)
    assert rewritten_call.expr.args is not None and len(rewritten_call.expr.args) == 1
    rewritten_arg = rewritten_call.expr.args[0]
    assert isinstance(rewritten_arg, ailment.Expr.VirtualVariable)
    assert rewritten_arg.varid == fp_arg.varid
    assert observations == [
        (
            xmm0_offset,
            8,
            block.addr,
            block.idx,
            1,
            ObservationPointType.OP_BEFORE,
        )
    ]


def test_srda_records_implicit_register_uses_for_call_folded_into_result_fixup():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    function = project.kb.functions.function(addr=0x1000, create=True)
    assert function is not None
    rdi_offset = project.arch.registers["rdi"][0]
    arg = ailment.Expr.VirtualVariable(
        0,
        1,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=rdi_offset,
        ins_addr=0x1000,
    )
    result = ailment.Expr.VirtualVariable(
        1,
        2,
        128,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["xmm0"][0],
        ins_addr=0x1001,
    )
    call = ailment.Expr.Call(2, "callee", args=None, bits=64, ins_addr=0x1001)
    folded_fixup = ailment.Stmt.Assignment(
        3,
        result,
        ailment.Expr.Insert(
            4,
            ailment.Expr.Const(5, 0, 128),
            ailment.Expr.Const(6, 0, 64),
            call,
            project.arch.register_endness,
        ),
        ins_addr=0x1001,
        **{CALL_RESULT_FIXUP_TAG: True},
    )
    block = ailment.Block(
        0x1000,
        2,
        statements=[
            ailment.Stmt.Assignment(7, arg, ailment.Expr.Const(8, 1, 64), ins_addr=0x1000),
            folded_fixup,
        ],
    )

    model = project.analyses.SReachingDefinitions(
        subject=function,
        func_graph=_single_block_graph(block),
        func_args=set(),
    ).model

    assert any(
        used_expr is None and use_loc.block_addr == block.addr and use_loc.stmt_idx == 1
        for used_expr, use_loc in model.all_vvar_uses[arg.varid]
    )


def test_classic_reaching_definitions_records_both_call_return_candidates():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    ret_expr = ailment.Expr.Register(0, project.arch.registers["rax"][0], 32, ins_addr=0x1000)
    fp_ret_expr = ailment.Expr.Register(1, project.arch.registers["xmm0"][0], 64, ins_addr=0x1000)
    call_expr = ailment.Expr.Call(3, "callee", args=[], bits=64, ins_addr=0x1000)
    block = ailment.Block(
        0x1000,
        1,
        idx=0,
        statements=[
            ailment.Stmt.SideEffectStatement(
                2,
                call_expr,
                ret_expr=ret_expr,
                fp_ret_expr=fp_ret_expr,
                ins_addr=0x1000,
            )
        ],
    )
    assert block.idx is not None
    observation = ("stmt", (block.addr, block.idx, 0), ObservationPointType.OP_AFTER)
    variable_map = variable_map_of(ailment.Manager(arch=project.arch))
    variable_map.set_prototype(
        call_expr,
        SimTypeFunction((), SimTypeLongLong()).with_arch(project.arch),
    )

    rda = project.analyses.ReachingDefinitions(
        subject=block,
        observation_points=[observation],
        variable_map=variable_map,
    )

    call_relationship = next(iter(rda.function_calls.values()))
    return_register_offsets = {
        definition.atom.reg_offset
        for definition in call_relationship.ret_defns
        if isinstance(definition.atom, RegisterAtom)
    }
    assert {ret_expr.reg_offset, fp_ret_expr.reg_offset} <= return_register_offsets

    live_definitions = rda.one_result
    for return_expr in (ret_expr, fp_ret_expr):
        values = live_definitions.get_values(RegisterAtom(return_expr.reg_offset, return_expr.size))
        assert values is not None
        value = values.one_value()
        assert value is not None
        assert len(value) == return_expr.bits
        assert live_definitions.is_top(value)

    upper_rax = live_definitions.get_values(RegisterAtom(ret_expr.reg_offset + ret_expr.size, ret_expr.size))
    assert upper_rax is not None
    upper_rax_value = upper_rax.one_value()
    assert upper_rax_value is not None
    assert upper_rax_value.concrete_value == 0


@pytest.mark.parametrize("selected_return", ("integer", "floating_point"))
def test_dead_return_candidate_is_removed_without_removing_call(selected_return):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    selected_expr = ret_expr if selected_return == "integer" else fp_ret_expr
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            call_stmt,
            ailment.Stmt.Return(4, [selected_expr], ins_addr=0x1001),
        ],
    )

    result_block = _simplify_single_block(project, block, unify_variables=False)

    calls = [stmt for stmt in result_block.statements if isinstance(stmt, ailment.Stmt.SideEffectStatement)]
    assert len(calls) == 1
    simplified_call = calls[0]
    if selected_return == "integer":
        assert simplified_call.ret_expr is not None
        assert simplified_call.fp_ret_expr is None
    else:
        assert simplified_call.ret_expr is None
        assert simplified_call.fp_ret_expr is not None


def test_both_live_return_candidates_do_not_fold_or_remove_call():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            call_stmt,
            ailment.Stmt.Return(4, [ret_expr, fp_ret_expr], ins_addr=0x1001),
        ],
    )

    result_block = _simplify_single_block(project, block, unify_variables=True, fold_expressions=True)

    calls = [stmt for stmt in result_block.statements if isinstance(stmt, ailment.Stmt.SideEffectStatement)]
    assert len(calls) == 1
    assert calls[0].ret_expr is not None
    assert calls[0].fp_ret_expr is not None


@pytest.mark.parametrize("selected_return", ("integer", "floating_point"))
def test_ail_simplifier_folds_exactly_one_return_candidate(selected_return):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    selected_expr = ret_expr if selected_return == "integer" else fp_ret_expr
    if selected_return == "integer":
        call_stmt = _rebuild_call_stmt(call_stmt, keep_fp_ret_expr=False)
    else:
        call_stmt = _rebuild_call_stmt(call_stmt, keep_ret_expr=False)
    # Ensure folding takes its result width from the selected candidate, not the provisional inner Call.
    assert isinstance(call_stmt.expr, Call)
    call_stmt = _rebuild_call_stmt(call_stmt, expr=_rebuild_call_expr(call_stmt.expr, bits=32))
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            call_stmt,
            ailment.Stmt.Return(4, [selected_expr], ins_addr=0x1001),
        ],
    )

    result_block = _simplify_single_block(project, block, unify_variables=True)

    assert not any(isinstance(stmt, ailment.Stmt.SideEffectStatement) for stmt in result_block.statements)
    return_stmt = next(stmt for stmt in result_block.statements if isinstance(stmt, ailment.Stmt.Return))
    assert isinstance(return_stmt.ret_exprs[0], ailment.Expr.Call)
    assert return_stmt.ret_exprs[0].bits == selected_expr.bits


@pytest.mark.parametrize("selected_return", ("integer", "floating_point"))
def test_call_statement_rewriter_handles_exactly_one_return_candidate(selected_return):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    expected_dst = ret_expr if selected_return == "integer" else fp_ret_expr
    if selected_return == "integer":
        call_stmt = _rebuild_call_stmt(call_stmt, keep_fp_ret_expr=False)
    else:
        call_stmt = _rebuild_call_stmt(call_stmt, keep_ret_expr=False)
    block = ailment.Block(0x1000, 1, statements=[call_stmt])
    graph = _single_block_graph(block)
    rewriter = object.__new__(CallStatementRewriter)
    rewriter._graph = graph
    rewriter.out_graph = None

    rewriter._analyze()

    rewritten = block.statements[0]
    assert isinstance(rewritten, ailment.Stmt.Assignment)
    assert rewritten.dst.likes(expected_dst)
    assert isinstance(rewritten.src, ailment.Expr.Call)
    assert rewriter.out_graph is graph


def test_call_statement_rewriter_preserves_unresolved_dual_return():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, _, _ = _make_dual_vvar_call(project)
    block = ailment.Block(0x1000, 1, statements=[call_stmt])
    graph = _single_block_graph(block)
    rewriter = object.__new__(CallStatementRewriter)
    rewriter._graph = graph
    rewriter.out_graph = None

    rewriter._analyze()

    assert block.statements[0] is call_stmt
    assert rewriter.out_graph is None


def test_string_obfuscation_rewriter_preserves_both_return_candidates():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    manager = ailment.Manager(arch=project.arch)
    _, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    call_stmt = ailment.Stmt.SideEffectStatement(
        3,
        ailment.Expr.Call(
            2,
            "decode",
            args=[ailment.Expr.Const(4, 0x2000, 64)],
            bits=64,
            ins_addr=0x1000,
        ),
        ret_expr=ret_expr,
        fp_ret_expr=fp_ret_expr,
        ins_addr=0x1000,
    )
    block = ailment.Block(0x1000, 1, statements=[call_stmt])
    rewriter = object.__new__(StringObfType3Rewriter)
    function = project.kb.functions.function(addr=block.addr, create=True)
    assert function is not None
    rewriter._func = function
    rewriter.manager = manager
    variable_map_of(manager)

    rewritten_block = rewriter._process_block(block, b"xy")
    rewritten_call = rewritten_block.statements[-1]

    assert isinstance(rewritten_call, ailment.Stmt.SideEffectStatement)
    assert rewritten_call.ret_expr is not None
    assert rewritten_call.fp_ret_expr is not None
    assert rewritten_call.ret_expr.likes(ret_expr)
    assert rewritten_call.fp_ret_expr.likes(fp_ret_expr)


def test_cxx_operator_scalar_rewriter_skips_unresolved_dual_return():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    manager = ailment.Manager(arch=project.arch)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    referenced = ailment.Expr.VirtualVariable(
        5,
        3,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["rbx"][0],
    )
    assert isinstance(call_stmt.expr, Call)
    call_stmt = _rebuild_call_stmt(
        call_stmt,
        expr=_rebuild_call_expr(
            call_stmt.expr,
            args=[
                ailment.Expr.Const(6, 0, 64),
                ailment.Expr.UnaryOp(7, "Reference", referenced, bits=64),
                ailment.Expr.Const(8, 0x2000, 64),
            ],
        ),
    )
    rewriter = RewriteCxxOperatorCalls(project, project.kb, manager)

    assert rewriter._optimize_operator_add(call_stmt) is None

    resolved_call = _rebuild_call_stmt(call_stmt, keep_fp_ret_expr=False)
    rewritten = rewriter._optimize_operator_add(resolved_call)
    assert isinstance(rewritten, ailment.Stmt.WeakAssignment)
    assert rewritten.dst.likes(ret_expr)

    fp_resolved_call = _rebuild_call_stmt(call_stmt, keep_ret_expr=False)
    fp_rewritten = rewriter._optimize_operator_add(fp_resolved_call)
    assert isinstance(fp_rewritten, ailment.Stmt.WeakAssignment)
    assert fp_rewritten.dst.likes(fp_ret_expr)


def test_semantic_naming_selects_only_one_return_candidate():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    dual_call, _, fp_ret_expr = _make_dual_vvar_call(project)
    linked_var = SimRegisterVariable(project.arch.registers["rax"][0], 8)
    result_namer = object.__new__(CallResultNaming)
    result_namer._result_vars = {}
    result_namer._get_function_name = lambda call: "malloc"
    result_namer._get_linked_variable = lambda expr: linked_var

    result_namer._analyze_call(dual_call)
    assert not result_namer._result_vars

    fp_only_call = _rebuild_call_stmt(dual_call, keep_ret_expr=False)
    result_namer._analyze_call(fp_only_call)
    assert result_namer._result_vars == {linked_var: "ptr"}

    pointer_namer = object.__new__(PointerNaming)
    pointer_namer._graph = networkx.DiGraph()
    pointer_namer._graph.add_nodes_from(
        [
            ailment.Block(0x1000, 1, statements=[dual_call]),
            ailment.Block(0x1001, 1, statements=[fp_only_call]),
        ]
    )
    selected_returns = []
    pointer_namer._analyze_call_for_pointers = lambda call, ret_expr=None: selected_returns.append(ret_expr)
    pointer_namer._find_function_pointer_params()
    assert selected_returns == [None, fp_ret_expr]


def test_block_io_preserves_void_call_unknown_output():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call = ailment.Stmt.SideEffectStatement(
        0,
        ailment.Expr.Call(1, "callee", args=[], bits=64, ins_addr=0x1000),
        ins_addr=0x1000,
    )
    src = ailment.Expr.VirtualVariable(
        2,
        1,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["rax"][0],
        ins_addr=0x1001,
    )
    dst = ailment.Expr.VirtualVariable(
        3,
        2,
        64,
        ailment.Expr.VirtualVariableCategory.REGISTER,
        oident=project.arch.registers["rbx"][0],
        ins_addr=0x1001,
    )
    assignment = ailment.Stmt.Assignment(4, dst, src, ins_addr=0x1001)
    statements = [call, assignment]

    io_finder = BlockIOFinder(statements, project)

    assert io_finder.outputs_by_stmt[0] == {None}
    assert not io_finder.can_swap(call, statements, 1)


@pytest.mark.parametrize("return_mode", ("dual", "integer", "floating_point"))
def test_return_candidates_are_definitions_for_liveness_srda_and_variable_recovery(return_mode):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    function = project.kb.functions.function(addr=0x1000, create=True)
    assert function is not None
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    if return_mode == "integer":
        call_stmt = _rebuild_call_stmt(call_stmt, keep_fp_ret_expr=False)
        return_exprs = (ret_expr,)
    elif return_mode == "floating_point":
        call_stmt = _rebuild_call_stmt(call_stmt, keep_ret_expr=False)
        return_exprs = (fp_ret_expr,)
    else:
        return_exprs = (ret_expr, fp_ret_expr)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            call_stmt,
            ailment.Stmt.Return(4, list(return_exprs), ins_addr=0x1001),
        ],
    )
    graph = _single_block_graph(block)

    liveness = project.analyses.SLiveness(function, graph)
    for return_expr in return_exprs:
        assert return_expr.varid not in liveness.model.live_ins[(block.addr, block.idx)]

    srda_model = project.analyses.SReachingDefinitions(
        subject=function,
        func_graph=graph,
        func_args=set(),
    ).model
    srda_view = SRDAView(srda_model)
    for return_expr in return_exprs:
        assert (
            srda_view.get_reg_vvar_by_stmt(
                return_expr.reg_offset,
                return_expr.size,
                block.addr,
                block.idx,
                1,
                ObservationPointType.OP_BEFORE,
            )
            == return_expr
        )

    # SRDA's statement observation keys retain their historical nested block-key shape.
    observation = cast(Any, ("stmt", ((block.addr, block.idx), 0), ObservationPointType.OP_AFTER))
    reg_map = srda_view.observe([observation], entry=block)[observation]
    for return_expr in return_exprs:
        assert reg_map[return_expr.reg_offset][return_expr.size] == return_expr.varid

    variable_recovery = project.analyses.VariableRecoveryFast(
        function,
        func_graph=graph,
        unify_variables=False,
    )
    variable_manager = variable_recovery.variable_manager[function.addr]
    for return_expr in return_exprs:
        assert variable_manager.find_variables_by_atom(
            block.addr,
            0,
            return_expr,
            block_idx=block.idx,
        )


def test_clinic_links_both_return_candidates():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    block = ailment.Block(0x1000, 1, statements=[call_stmt])
    clinic = cast(Any, object.__new__(Clinic))
    clinic.function = SimpleNamespace(addr=block.addr)
    linked_exprs = []
    clinic._link_variables_on_expr = lambda *args: linked_exprs.append(args[-1])
    kb = SimpleNamespace(variables={block.addr: object(), "global": object()})

    clinic._link_variables_on_block(block, kb)

    assert call_stmt.expr in linked_exprs
    assert ret_expr in linked_exprs
    assert fp_ret_expr in linked_exprs


def test_expression_narrowing_visits_and_rewrites_both_return_candidates():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    manager = ailment.Manager(arch=project.arch)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    block = ailment.Block(0x1000, 1, statements=[call_stmt])

    extractor = EffectiveSizeExtractor()
    extractor.walk_statement(call_stmt)
    assert ret_expr.varid in extractor.vvar_effective_bits
    assert fp_ret_expr.varid in extractor.vvar_effective_bits

    narrower = ExpressionNarrower(project, None, manager, [], {}, {})
    narrower.new_vvar_sizes = {
        ret_expr.varid: 4,
        fp_ret_expr.varid: 4,
    }
    rewritten_block = narrower.walk(block)
    rewritten_call = rewritten_block.statements[0]

    assert isinstance(rewritten_call, SideEffectStatement)
    assert rewritten_call.ret_expr is not None
    assert rewritten_call.fp_ret_expr is not None
    assert rewritten_call.ret_expr.size == 4
    assert rewritten_call.fp_ret_expr.size == 4


def test_expression_narrowing_copies_an_fp_only_return_definition():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    manager = ailment.Manager(arch=project.arch)
    call_stmt, _, fp_ret_expr = _make_dual_vvar_call(project)
    call_stmt = _rebuild_call_stmt(call_stmt, keep_ret_expr=False)
    block = ailment.Block(0x1000, 1, statements=[call_stmt])
    narrower = ExpressionNarrower(project, None, manager, [], {}, {})
    narrower.new_vvar_sizes = {fp_ret_expr.varid: 4}

    rewritten_block = narrower.walk(block)
    rewritten_call = rewritten_block.statements[0]

    assert rewritten_call is not call_stmt
    assert isinstance(rewritten_call, SideEffectStatement)
    assert rewritten_call.fp_ret_expr is not None
    assert call_stmt.fp_ret_expr is not None
    assert rewritten_call.fp_ret_expr.size == 4
    assert call_stmt.fp_ret_expr.likes(fp_ret_expr)
    assert fp_ret_expr.size == 8


def test_region_folding_and_ite_conversion_reject_unresolved_dual_return():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            call_stmt,
            ailment.Stmt.Return(4, [ret_expr, fp_ret_expr], ins_addr=0x1001),
        ],
    )

    expression_counter = ExpressionCounter(block)

    assert ret_expr.varid not in expression_counter.assignments
    assert fp_ret_expr.varid not in expression_counter.assignments
    assert not ITERegionConverter._is_assigning_to_vvar(call_stmt)

    fp_only_call = _rebuild_call_stmt(call_stmt, keep_ret_expr=False)
    fp_only_counter = ExpressionCounter(ailment.Block(0x1000, 1, statements=[fp_only_call]))
    assert fp_ret_expr.varid in fp_only_counter.assignments
    assert ITERegionConverter._is_assigning_to_vvar(fp_only_call)


def test_return_duplicator_freshens_both_return_definitions_and_uses():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            call_stmt,
            ailment.Stmt.Return(4, [ret_expr, fp_ret_expr], ins_addr=0x1001),
        ],
    )
    rewriter = FreshVirtualVariableRewriter(10, {})

    rewritten_block = rewriter.walk(block)
    rewritten_call, rewritten_return = rewritten_block.statements

    assert isinstance(rewritten_call, SideEffectStatement)
    assert isinstance(rewritten_call.ret_expr, ailment.Expr.VirtualVariable)
    assert isinstance(rewritten_call.fp_ret_expr, ailment.Expr.VirtualVariable)
    assert isinstance(rewritten_return, Return)
    assert rewritten_call.ret_expr.varid == 10
    assert rewritten_call.fp_ret_expr.varid == 11
    assert [expr.varid for expr in rewritten_return.ret_exprs] == [10, 11]


@pytest.mark.parametrize("selected_return", ("integer", "floating_point"))
def test_codegen_assigns_exactly_one_return_candidate(selected_return):
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, ret_expr, fp_ret_expr = _make_dual_vvar_call(project)
    if selected_return == "integer":
        call_stmt = _rebuild_call_stmt(call_stmt, keep_fp_ret_expr=False)
        selected_expr = ret_expr
    else:
        call_stmt = _rebuild_call_stmt(call_stmt, keep_ret_expr=False)
        selected_expr = fp_ret_expr
    handled_return = object()

    def handle(expr, **_kwargs):
        return (
            handled_return
            if isinstance(expr, ailment.Expr.VirtualVariable) and expr.varid == selected_expr.varid
            else expr
        )

    c_codegen, rust_codegen = _make_codegen_stubs(project, handle)
    c_result = c_codegen._handle_Stmt_SideEffectStatement(call_stmt)
    rust_result = rust_codegen._handle_Stmt_SideEffectStatement(call_stmt)

    assert isinstance(c_result, CAssignment)
    assert c_result.lhs is handled_return
    assert isinstance(rust_result, RustFunctionCall)
    assert rust_result.ret_expr is handled_return


def test_codegen_emits_unresolved_dual_return_as_one_standalone_call():
    project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
    call_stmt, _, _ = _make_dual_vvar_call(project)

    c_codegen, rust_codegen = _make_codegen_stubs(project, lambda expr, **kwargs: expr)
    c_result = c_codegen._handle_Stmt_SideEffectStatement(call_stmt)
    rust_result = rust_codegen._handle_Stmt_SideEffectStatement(call_stmt)

    assert isinstance(c_result, CExpressionStatement)
    assert isinstance(c_result.expr, CFunctionCall)
    assert c_result.expr.callee_target == "callee"
    assert isinstance(rust_result, RustFunctionCall)
    assert rust_result.callee_target == "callee"
    assert rust_result.ret_expr is None

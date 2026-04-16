from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use

import os
import unittest
from functools import cache
from types import SimpleNamespace

import claripy

import angr
from angr import ailment
from angr.engines.ail.callstack import AILCallStack
from angr.engines.ail.engine_light import SimEngineAILSimState
from angr.engines.successors import SimSuccessors
from angr.procedures.libc.snprintf import snprintf
from angr.storage import DefaultMemory


from angr.analyses.decompiler.clinic import Clinic
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestAILExec(unittest.TestCase):
    def test_smoketest(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)

        @cache
        def lift_function(addr):
            func = p.kb.functions[addr]
            passes = angr.analyses.decompiler.DECOMPILATION_PRESETS["full"].get_optimization_passes(
                p.arch, p.simos.name
            )
            return p.analyses[Clinic].prep(kb=p.kb)(func, optimization_passes=passes)

        def lifter(addr):
            node = cfg.model.get_any_node(addr, anyaddr=True)
            assert node is not None
            return lift_function(node.function_address)

        argc = claripy.BVS("argc", 64)
        state = angr.engines.ail.ail_call_state(
            p,
            "main",
            [argc, claripy.BVV(0, 64)],
            lifter,
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.RUN_HOOKS_AT_PLT,
                angr.options.CALLLESS,
            },
        )
        simgr = p.factory.simgr(state)
        simgr.run(n=20)
        # there should be 4 deadended states, and all of them should have argc in the constraints
        assert len(simgr.active) == 0
        assert len(simgr.errored) == 0
        assert len(simgr.deadended) == 4
        assert all(
            any(argc.variables & constraint.variables for constraint in state.solver.constraints)
            for state in simgr.deadended
        )

    def test_vexccall_expression(self):
        p = angr.load_shellcode(b"\x00", arch="ARMEL", load_address=0x400000)
        state = p.factory.blank_state()
        state.addr = (0x400000, None)

        bottom_frame = AILCallStack()
        top_frame = AILCallStack(func_addr=0x400000)
        top_frame.passed_args = None
        state.register_plugin("callstack", bottom_frame)
        state.callstack.push(top_frame)

        # armg_calculate_condition(state, cond_n_op, cc_dep1, cc_dep2, cc_dep3) -> I32
        # Use ARMCondAL so the result should be 1.
        cond_n_op = ailment.expression.Const(None, None, 0xE0, 32)  # (AL<<4) | 0
        cc_dep1 = ailment.expression.Const(None, None, 0, 32)
        cc_dep2 = ailment.expression.Const(None, None, 0, 32)
        cc_dep3 = ailment.expression.Const(None, None, 0, 32)
        ccall_expr = ailment.expression.VEXCCallExpression(
            idx=0,
            callee="armg_calculate_condition",
            operands=(cond_n_op, cc_dep1, cc_dep2, cc_dep3),
            bits=32,
        )
        r0_offset = p.arch.registers["r0"][0]
        assign_stmt = ailment.statement.Assignment(
            idx=0,
            dst=ailment.expression.Register(None, None, r0_offset, 32),
            src=ccall_expr,
        )
        assign_stmt.tags["ins_addr"] = 0x400000
        jump_stmt = ailment.statement.Jump(idx=1, target=ailment.expression.Const(None, None, 0x400004, 32))
        jump_stmt.tags["ins_addr"] = 0x400000
        block = ailment.Block(0x400000, 0, statements=[assign_stmt, jump_stmt])

        successors = SimSuccessors(state.addr, state)
        engine = SimEngineAILSimState(p, successors)
        engine.process(state, block=block)

        assert len(successors.successors) == 1
        succ = successors.successors[0]
        assert succ.addr == (0x400004, None)

        out = succ.registers.load(r0_offset, 4)
        assert isinstance(out, claripy.ast.BV)
        assert out.concrete and out.concrete_value == 1

    def test_conditional_jump_accepts_bv1_condition(self):
        # Regression test for SimEngineAILSimState._expr_bool:
        # some conditions may evaluate to BV1 (0/1) instead of Bool.
        p = angr.load_shellcode(b"\x90", arch="AMD64", load_address=0x400000)
        state = p.factory.blank_state()
        state.addr = (0x400000, None)

        bottom_frame = AILCallStack()
        top_frame = AILCallStack(func_addr=0x400000)
        top_frame.passed_args = None
        state.register_plugin("callstack", bottom_frame)
        state.callstack.push(top_frame)

        cond_bv1 = ailment.expression.Const(None, None, 1, 1)  # BV1(1)
        true_tgt = ailment.expression.Const(None, None, 0x400004, 64)
        false_tgt = ailment.expression.Const(None, None, 0x400008, 64)
        cjmp = ailment.statement.ConditionalJump(0, cond_bv1, true_tgt, false_tgt)
        cjmp.tags["ins_addr"] = 0x400000
        block = ailment.Block(0x400000, 0, statements=[cjmp])

        succ = SimSuccessors(state.addr, state)
        engine = SimEngineAILSimState(p, succ)
        engine.process(state, block=block)

        assert len(succ.all_successors) == 2
        assert len(succ.successors) == 1
        assert len(succ.unsat_successors) == 1
        assert len(succ.unconstrained_successors) == 0

        true_succ = succ.successors[0]
        assert true_succ.addr == (0x400004, None)
        assert true_succ.history.jumpkind == "Ijk_Boring"
        assert true_succ.scratch.exit_stmt_idx == 0
        assert true_succ.solver.is_true(true_succ.scratch.guard)

        false_succ = succ.unsat_successors[0]
        assert false_succ.addr == (0x400008, None)
        assert false_succ.history.jumpkind == "Ijk_Boring"
        assert false_succ.scratch.exit_stmt_idx == 0
        assert false_succ.solver.is_false(false_succ.scratch.guard)

    def test_phi_with_none_vvar_does_not_crash(self):
        # Regression test for SimEngineAILSimState._handle_expr_Phi:
        # Some AIL passes may produce Phi nodes with a None vvar for a predecessor.
        # The engine should not assert; it should return a conservative top value instead.
        p = angr.load_shellcode(b"\x90", arch="AMD64", load_address=0x400000)
        state = p.factory.blank_state()
        state.addr = (0x400000, None)

        bottom_frame = AILCallStack()
        top_frame = AILCallStack(func_addr=0x400000)
        top_frame.passed_args = None
        state.register_plugin("callstack", bottom_frame)
        state.callstack.push(top_frame)

        # predecessor block: jump to successor
        pred_jump = ailment.statement.Jump(idx=0, target=ailment.expression.Const(None, None, 0x400004, 64))
        pred_jump.tags["ins_addr"] = 0x400000
        pred_block = ailment.Block(0x400000, 0, statements=[pred_jump])

        pred_succ = SimSuccessors(state.addr, state)
        engine = SimEngineAILSimState(p, pred_succ)
        engine.process(state, block=pred_block)
        assert len(pred_succ.successors) == 1
        s1 = pred_succ.successors[0]
        assert s1.addr == (0x400004, None)

        # Emulate the history linkage normally created by SimSuccessors.process():
        # SimEngineAILSimState._handle_expr_Phi consults state.history.parent.recent_bbl_addrs[-1] to pick the
        # predecessor edge for the phi.
        from angr.state_plugins.history import SimStateHistory  # pylint:disable=import-outside-toplevel

        h_parent = SimStateHistory()
        h_parent.recent_bbl_addrs.append((0x400000, None))
        s1.history.parent = h_parent

        # successor block: rax = Phi(pred -> None), then jump out
        phi = ailment.expression.Phi(idx=0, bits=64, src_and_vvars=[((0x400000, None), None)])
        rax_offset = p.arch.registers["rax"][0]
        assign = ailment.statement.Assignment(
            idx=0,
            dst=ailment.expression.Register(None, None, rax_offset, 64),
            src=phi,
        )
        assign.tags["ins_addr"] = 0x400004
        succ_jump = ailment.statement.Jump(idx=1, target=ailment.expression.Const(None, None, 0x400008, 64))
        succ_jump.tags["ins_addr"] = 0x400004
        succ_block = ailment.Block(0x400004, 0, statements=[assign, succ_jump])

        succ_succ = SimSuccessors(s1.addr, s1)
        engine2 = SimEngineAILSimState(p, succ_succ)
        engine2.process(s1, block=succ_block)

        assert len(succ_succ.successors) == 1
        s2 = succ_succ.successors[0]
        out = s2.registers.load(rax_offset, 8)
        assert isinstance(out, claripy.ast.BV)
        assert out.op == "BVS"
        # claripy's BVS name is stored as a plain string in args[0] in newer versions.
        bvs_name = out.args[0].name if hasattr(out.args[0], "name") else out.args[0]
        assert isinstance(bvs_name, str)
        assert bvs_name.startswith("ail_engine_top")

    def test_callless_call_evaluates_reference_args(self):
        # Regression test: even under CALLLESS, call arguments should be evaluated so that side-effecting expressions
        # (notably Reference(vvar_*)) materialize stack vvars into the AIL callstack frame.
        p = angr.load_shellcode(b"\x00", arch="ARMEL", load_address=0x400000)
        state = p.factory.blank_state(add_options={angr.options.CALLLESS})
        state.addr = (0x400000, None)

        bottom_frame = AILCallStack()
        top_frame = AILCallStack(func_addr=0x400000)
        top_frame.passed_args = None
        state.register_plugin("callstack", bottom_frame)
        state.callstack.push(top_frame)

        # Minimal globals required by SimEngineAILSimState._handle_unop_Reference.
        state.globals["ail_var_memory_cls"] = DefaultMemory
        state.globals["ail_lifter"] = lambda _addr: SimpleNamespace(function=SimpleNamespace(name="f"))

        # &vvar_217 (8-bit stack local), returned as a 32-bit pointer.
        vvar = ailment.expression.VirtualVariable(
            idx=0,
            varid=217,
            bits=8,
            category=ailment.expression.VirtualVariableCategory.STACK,
            oident="s-212",
        )
        ref = ailment.expression.UnaryOp(idx=0, op="Reference", operand=vvar, bits=p.arch.bits)

        call_tgt = ailment.expression.Const(None, None, 0xDEADBEEF, p.arch.bits)
        call_expr = ailment.expression.Call(idx=0, target=call_tgt, args=[ref], bits=p.arch.bits)
        call = ailment.statement.SideEffectStatement(idx=0, expr=call_expr)
        call.tags["ins_addr"] = 0x400000

        jmp = ailment.statement.Jump(idx=1, target=ailment.expression.Const(None, None, 0x400004, p.arch.bits))
        jmp.tags["ins_addr"] = 0x400000

        block = ailment.Block(0x400000, 0, statements=[call, jmp])

        successors = SimSuccessors(state.addr, state)
        engine = SimEngineAILSimState(p, successors)
        engine.process(state, block=block)

        # Ensure the Reference(vvar) was evaluated and materialized in the current frame, even though the call was
        # callless.
        frame = state.callstack
        assert 217 in frame.vars
        assert 217 in frame.var_refs_rev

    def test_statement_call_unused_return_is_ignored(self):
        # Regression test for SimEngineAILSimState._handle_stmt_Call: a Call statement may have no ret_expr even if the
        # callee returns a value (e.g., `memset(...)` used only for side effects). The engine should discard the return.
        p = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)

        state = p.factory.blank_state()
        state.addr = (0x400000, None)
        state.globals["ail_var_memory_cls"] = DefaultMemory
        state.globals["ail_lifter"] = lambda _addr: None

        bottom_frame = AILCallStack()
        top_frame = AILCallStack(func_addr=0x400000)
        top_frame.passed_args = None
        state.register_plugin("callstack", bottom_frame)
        state.callstack.push(top_frame)

        # Simulate that the call target already returned a value (as if we just came back from a callee).
        state.callstack.passed_rets = ((claripy.BVV(0x1234, 32),),)

        # A Call expression wrapped in SideEffectStatement with no return assignment (unused return value).
        call_expr = ailment.expression.Call(
            idx=0,
            target=ailment.expression.Const(None, None, 0x5000, 32),
            args=[],
            bits=32,
        )
        call_stmt = ailment.statement.SideEffectStatement(
            idx=0,
            expr=call_expr,
            ret_expr=None,
            fp_ret_expr=None,
        )
        # The light AIL engine expects statements to carry an instruction address tag.
        call_stmt.tags["ins_addr"] = 0x400000
        # Add a diverging statement afterwards to avoid requiring a real lifter/graph in _process_block_end().
        jump_stmt = ailment.statement.Jump(idx=1, target=ailment.expression.Const(None, None, 0x400004, 32))
        jump_stmt.tags["ins_addr"] = 0x400000
        block = ailment.Block(0x400000, 0, statements=[call_stmt, jump_stmt])

        successors = SimSuccessors(state.addr, state)
        engine = SimEngineAILSimState(p, successors)

        # Should not raise AngrRuntimeError due to mismatched return arity.
        engine.process(state, block=block)

        # The unused return value should be consumed/cleared and execution should continue normally.
        assert state.callstack.passed_rets == ()

        # The block ends in a Jump, so we should get exactly one normal successor to the jump target.
        assert len(successors.successors) == 1
        assert len(successors.unsat_successors) == 0
        assert len(successors.unconstrained_successors) == 0

        succ = successors.successors[0]
        assert succ.addr == (0x400004, None)
        assert succ.history.jumpkind == "Ijk_Boring"
        assert succ.scratch.exit_stmt_idx == 1

    def test_ail_passed_args_supports_varargs_simprocedures(self):
        # Regression test for SimProcedure.execute() when using AILCallStack.passed_args:
        # passed_args may include varargs (e.g., snprintf).
        # We should pass only fixed args to run(), but keep all args for va_arg().
        p = angr.load_shellcode(b"\x90", arch="AMD64", load_address=0x400000)
        state = p.factory.blank_state()
        state.addr = (0x400000, None)

        bottom_frame = AILCallStack()
        state.register_plugin("callstack", bottom_frame)
        state.callstack.push(AILCallStack(func_addr=0xDEADBEEF))
        top_frame = AILCallStack(func_addr=0x400000)
        top_frame.return_addr = (0x400001, None)
        state.callstack.push(top_frame)
        assert len(state.callstack) >= 2

        dst_ptr = claripy.BVV(0x500000, 64)
        fmt_ptr = claripy.BVV(0x500100, 64)
        size = claripy.BVV(0x40, 64)
        arg1 = claripy.BVV(3, 64)
        state.memory.store(fmt_ptr, b"Num: %d\n\x00")
        state.callstack.passed_args = (dst_ptr, size, fmt_ptr, arg1)

        succ = SimSuccessors(state.addr, state)
        proc = snprintf(project=p)
        proc.execute(state, successors=succ)

        out = state.solver.eval(state.memory.load(dst_ptr, 8), cast_to=bytes)
        assert out.startswith(b"Num: 3\n")

    def test_function_entry_arg_handoff_tolerates_extra_passed_args(self):
        # Regression test: AILCallStack.passed_args can include varargs
        # Engine should assign the first N fixed args and ignore extras without raising.
        p = angr.load_shellcode(b"\x90", arch="AMD64", load_address=0x400000)
        state = p.factory.blank_state()
        state.addr = (0x400000, None)

        bottom_frame = AILCallStack()
        state.register_plugin("callstack", bottom_frame)
        top_frame = AILCallStack(func_addr=0x400000)
        top_frame.passed_args = (
            claripy.BVV(1, 64),
            claripy.BVV(2, 64),
            claripy.BVV(3, 64),
            claripy.BVV(4, 64),  # extra
        )
        state.callstack.push(top_frame)
        assert len(state.callstack) == 2

        v0 = ailment.expression.VirtualVariable(0, 100, 64, ailment.expression.VirtualVariableCategory.PARAMETER)
        v1 = ailment.expression.VirtualVariable(0, 101, 64, ailment.expression.VirtualVariableCategory.PARAMETER)
        v2 = ailment.expression.VirtualVariable(0, 102, 64, ailment.expression.VirtualVariableCategory.PARAMETER)

        class _FakeClinic:
            arg_vvars = [(v0, None), (v1, None), (v2, None)]
            cc_graph = None

        state.globals["ail_lifter"] = lambda _addr: _FakeClinic()  # type: ignore

        jump = ailment.statement.Jump(0, ailment.expression.Const(None, None, 0x400004, 64))
        jump.tags["ins_addr"] = 0x400000
        block = ailment.Block(0x400000, 0, statements=[jump])

        succ = SimSuccessors(state.addr, state)
        engine = SimEngineAILSimState(p, succ)
        engine.process(state, block=block)

        assert state.callstack.vars[v0.varid].concrete_value == 1
        assert state.callstack.vars[v1.varid].concrete_value == 2
        assert state.callstack.vars[v2.varid].concrete_value == 3

from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use

import os
import unittest
from functools import cache

import claripy

import angr
from angr import ailment
from angr.engines.ail.callstack import AILCallStack
from angr.engines.ail.engine_light import SimEngineAILSimState
from angr.engines.successors import SimSuccessors

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

    def test_statement_call_unused_return_is_ignored(self):
        # Regression test for SimEngineAILSimState._handle_stmt_Call: a Call statement may have no ret_expr even if the
        # callee returns a value (e.g., `memset(...)` used only for side effects). The engine should discard the return.
        p = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)

        from angr.storage import DefaultMemory

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

        # A Call statement with no return assignment (unused return value).
        call_stmt = ailment.statement.Call(
            idx=0,
            target=ailment.expression.Const(None, None, 0x5000, 32),
            args=[],
            ret_expr=None,
            fp_ret_expr=None,
            bits=32,
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

from __future__ import annotations

import os

# pylint: disable=missing-class-docstring,no-self-use,protected-access
import unittest

import angr
from angr import ailment
from angr.analyses.purity import AILPurityAnalysis, AILPurityDataSource, AILPurityDataUsage, AILPurityResultType
from angr.analyses.purity.engine import PurityEngineAIL
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestAILPurityAnalysis(unittest.TestCase):
    def test_smoketest(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "test_purity"), auto_load_libs=False)
        p.analyses.CFGFast(normalize=True)

        desired_results = {
            "a": AILPurityResultType(),
            "b": AILPurityResultType(uses={AILPurityDataSource(function_arg=0): AILPurityDataUsage(ptr_load=True)}),
            "c": AILPurityResultType(uses={AILPurityDataSource(function_arg=0): AILPurityDataUsage(ptr_store=True)}),
            # global funcs
            "d": AILPurityResultType(
                uses={AILPurityDataSource(constant_value=4210772): AILPurityDataUsage(ptr_load=True)}
            ),
            # malloc - no flow from arg0 to malloc since it is a pointer-destroying op
            "e": AILPurityResultType(
                uses={AILPurityDataSource(callee_return=p.kb.functions[4198448]): AILPurityDataUsage(ptr_store=True)},
                call_args={(4199008, None, 2, p.kb.functions[4198448], 0): frozenset()},
            ),
        }

        for name, desired_result in desired_results.items():
            func = p.kb.functions[name]
            clinic = p.analyses.Clinic(func)
            pure = p.analyses[AILPurityAnalysis].prep()(clinic)
            pure.result.ret_vals = {}
            pure.result.other_storage = {}
            assert pure.result == desired_result

    def test_compare_and_swap_records_both_uses_of_its_pointer(self):
        # CASIntrinsics rewrites only a couple of lock-prefixed shapes, so plenty of AIL CAS statements reach the
        # analyses downstream of it. sub_453190 compare-and-swaps through its first argument three times.
        p = angr.Project(os.path.join(test_location, "x86_64", "bbbq"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True, data_references=True)
        clinic = p.analyses.Clinic(cfg.functions.get_by_addr(0x453190))
        engine = PurityEngineAIL(p, clinic, lambda _: AILPurityResultType())
        graph = clinic.graph
        assert graph is not None

        measured = 0
        for block in graph:
            whitelist = {i for i, stmt in enumerate(block.statements) if isinstance(stmt, ailment.statement.CAS)}
            if not whitelist:
                continue
            result = engine.process(engine.initial_state(block), block=block, whitelist=whitelist)
            # the swap goes through argument 0, which the statement reads and conditionally writes
            assert result.uses == {
                AILPurityDataSource(function_arg=0): AILPurityDataUsage(ptr_load=True, ptr_store=True)
            }
            measured += len(whitelist)

        assert measured == 3, "the fixture no longer reaches the analysis with CAS statements; this test tests nothing"

    def test_call_with_fewer_arguments_than_callee_summary(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "test_purity"), auto_load_libs=False)
        p.analyses.CFGFast(normalize=True)

        caller_clinic = p.analyses.Clinic(p.kb.functions["a"])
        callee = p.kb.functions["b"]
        callee_clinic = p.analyses.Clinic(callee)
        callee_result = p.analyses[AILPurityAnalysis].prep()(callee_clinic).result
        engine = PurityEngineAIL(p, caller_clinic, lambda _: callee_result)
        call = ailment.Expr.Call(
            None,
            ailment.Expr.Const(None, callee.addr, p.arch.bits),
            args=[],
            bits=p.arch.bits,
        )

        assert engine._handle_expr_Call(call) == frozenset((AILPurityDataSource(constant_value=0),))
        assert engine.result == AILPurityResultType()


if __name__ == "__main__":
    unittest.main()

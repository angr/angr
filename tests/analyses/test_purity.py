from __future__ import annotations
import unittest
import os

import angr
from angr.analyses.purity import AILPurityAnalysis, AILPurityResultType, AILPurityDataSource, AILPurityDataUsage

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
            # malloc
            "e": AILPurityResultType(
                uses={AILPurityDataSource(callee_return=4198448): AILPurityDataUsage(ptr_store=True)},
                call_args={(4199008, None, 2, 4198448, 0): frozenset({AILPurityDataSource(function_arg=0)})},
            ),
        }

        for name, desired_result in desired_results.items():
            func = p.kb.functions[name]
            clinic = p.analyses.Clinic(func)
            pure = p.analyses[AILPurityAnalysis].prep()(clinic)
            assert pure.result == desired_result


if __name__ == "__main__":
    unittest.main()

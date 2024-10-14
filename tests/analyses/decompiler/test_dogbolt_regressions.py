from __future__ import annotations

import os
import unittest

import angr

from tests.common import bin_location


BIN_PATH = os.path.join(bin_location, "tests", "dogbolt")


class TestDogboltRegressions(unittest.TestCase):
    def _run_dogbolt_test(self, binary_name: str):
        p = angr.Project(os.path.join(BIN_PATH, binary_name), auto_load_libs=False, load_debug_info=False)

        cfg = p.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            data_references=True,
        )
        p.analyses.CompleteCallingConventions(cfg=cfg.model, recover_variables=True, analyze_callsites=True)

        funcs_to_decompile = [
            func
            for func in cfg.functions.values()
            if not func.is_plt and not func.is_simprocedure and not func.alignment
        ]

        for func in funcs_to_decompile:
            decompiler = p.analyses.Decompiler(func, cfg=cfg.model)
            self.assertIsNotNone(decompiler.codegen, f"No decompilation output for function {func.name}")

    def test_megatest_arm64_freebsd(self):
        """
        This binary is used as a sample output on dogbolt as of October 2024,
        and angr verstion 9.2.122 would time out when decompiling the __start
        function due to an infinite loop in LoweredSwitchSimplifier. This test
        case is used to verify that this does not regress.

        See: https://github.com/angr/angr/pull/4953
        """
        self._run_dogbolt_test("megatest-arm64-freebsd")

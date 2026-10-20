from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from collections.abc import Sequence

import angr
from angr.analyses.decompiler.optimization_passes.lowered_switch_simplifier import LoweredSwitchSimplifier
from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS
from tests.common import bin_location

BIN_PATH = os.path.join(bin_location, "tests", "dogbolt")


class TestDogboltRegressions(unittest.TestCase):
    """
    Tests to verify regressions do not occur on bugs found on dogbolt.
    """

    def _run_dogbolt_test(
        self, binary_name: str, func_names: Sequence[str] | None = None, extra_passes: Sequence[type] = ()
    ):
        p = angr.Project(os.path.join(BIN_PATH, binary_name), auto_load_libs=False, load_debug_info=False)

        cfg = p.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            data_references=True,
        )
        p.analyses.CompleteCallingConventions(cfg=cfg.model, recover_variables=True, analyze_callsites=True)

        if func_names is None:
            funcs_to_decompile = [
                func
                for func in cfg.functions.values()
                if not func.is_plt and not func.is_simprocedure and not func.is_alignment
            ]
        else:
            funcs_to_decompile = [cfg.functions[name] for name in func_names]

        # extra_passes is appended after the preset has filtered by arch and platform, so a pass that the platform
        # gate would drop still runs
        passes = DECOMPILATION_PRESETS["default"].get_optimization_passes(p.arch, p.simos.name)
        passes += [pass_ for pass_ in extra_passes if pass_ not in passes]

        for func in funcs_to_decompile:
            decompiler = p.analyses.Decompiler(func, cfg=cfg.model, optimization_passes=passes)
            self.assertIsNotNone(decompiler.codegen, f"No decompilation output for function {func.name}")

    def test_megatest_arm64_freebsd(self):
        """
        This binary is used as a sample output on dogbolt as of October 2024,
        and angr verstion 9.2.122 would time out when decompiling the __start
        function due to an infinite loop in LoweredSwitchSimplifier. This test
        case is used to verify that this does not regress.

        See: https://github.com/angr/angr/pull/4953

        __start is the only function that loops, so it is the only one decompiled. LoweredSwitchSimplifier is
        requested explicitly because it is gated to ``PLATFORMS = ["linux"]`` and #7444 gave FreeBSD ELFs their own
        SimOS, which dropped the pass -- and with it this test's whole subject -- from the default pass list.
        """
        self._run_dogbolt_test("megatest-arm64-freebsd", ["__start"], [LoweredSwitchSimplifier])


if __name__ == "__main__":
    unittest.main()

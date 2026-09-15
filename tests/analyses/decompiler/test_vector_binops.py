from __future__ import annotations

import os
import unittest

import angr
from angr.ailment.block_walker import AILBlockViewer
from angr.analyses.purity import AILPurityAnalysis
from angr.engines.ail.engine_light import SimEngineAILSimState
from angr.engines.successors import SimSuccessors
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class _OperatorCollector(AILBlockViewer):
    """Collect one expression for each operator in a lifted function."""

    def __init__(self):
        super().__init__()
        self.operators = {}

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        self.operators.setdefault(expr.op, expr)
        super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        self.operators.setdefault(expr.op, expr)
        super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)


class TestVectorBinops(unittest.TestCase):
    """Test vector operations throughout the decompiler pipeline."""

    def test_haddv_survives_decompilation(self):
        bin_path = os.path.join(test_location, "armel", "libc-2.31.so")

        for function_name in ("strlen", "strcmp"):
            with self.subTest(function_name=function_name):
                project = angr.Project(bin_path, auto_load_libs=False)
                symbol = project.loader.find_symbol(function_name)
                assert symbol is not None

                function_addr = symbol.rebased_addr
                cfg = project.analyses.CFGFast(
                    function_starts=[function_addr],
                    regions=[(function_addr & ~1, (function_addr & ~1) + symbol.size)],
                    force_complete_scan=False,
                    normalize=True,
                )
                function = cfg.functions[function_addr]

                decompilation = project.analyses.Decompiler(function, cfg=cfg.model)
                assert decompilation.codegen is not None
                assert decompilation.codegen.text is not None
                assert "HAddV(" in decompilation.codegen.text

    def test_operators_without_a_handler_survive_decompilation(self):
        # These helpers lift to operators absent from the engines' dispatch tables.
        cases = [
            # A Thumb NEON byte-search helper, built out of vdup, veor and vtst.
            ("armel", "libc-2.31.so", 0x463FE3, 0xD0, ("GetElemV", "Dup", "CmpNEZ")),
            # An AArch64 NEON byte-search helper, whose addp lifts through CatEvenLanes and
            # CatOddLanes.
            ("aarch64", "langdetect_go", 0x18690, 0xDC, ("CatEvenLanesV", "CatOddLanesV")),
        ]

        for arch, name, function_addr, size, operators in cases:
            with self.subTest(binary=name):
                project = angr.Project(os.path.join(test_location, arch, name), auto_load_libs=False)
                cfg = project.analyses.CFGFast(
                    function_starts=[function_addr],
                    regions=[(function_addr & ~1, (function_addr & ~1) + size)],
                    force_complete_scan=False,
                    normalize=True,
                )
                function = cfg.functions[function_addr]

                decompilation = project.analyses.Decompiler(function, cfg=cfg.model)
                assert decompilation.codegen is not None
                text = decompilation.codegen.text
                assert text is not None
                with self.subTest(stage="rendering"):
                    for operator in operators:
                        self.assertIn(f"{operator}(", text)

                clinic = decompilation.clinic
                assert clinic is not None
                if arch == "aarch64":
                    with self.subTest(stage="purity"):
                        purity = project.analyses[AILPurityAnalysis].prep()(clinic)
                        self.assertIn(0, purity.result.ret_vals)

                collector = _OperatorCollector()
                assert clinic.graph is not None
                for block in clinic.graph:
                    collector.walk(block)
                state = project.factory.blank_state()
                engine = SimEngineAILSimState(project, SimSuccessors(state.addr, state))
                engine.state = state
                for operator in operators:
                    with self.subTest(stage="execution", operator=operator):
                        expr = collector.operators[operator]
                        with self.assertRaises(NotImplementedError):
                            engine._expr(expr)  # pylint: disable=protected-access


if __name__ == "__main__":
    unittest.main()

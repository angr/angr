from __future__ import annotations

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


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
        # The AIL operator name comes from the VEX op, so the engines' dispatch tables cannot
        # enumerate it. Each case below names an operator no table lists.
        cases = [
            # A Thumb NEON byte-search helper, built out of vdup, veor and vtst.
            ("armel", "libc-2.31.so", 0x463FE3, 0xD0, ("GetElemV(", "Dup(", "CmpNEZ(")),
            # A MIPS32 rounding conversion, reached through cvt.w.d.
            ("mipsel", "darpa_ping", 0x404208, 0xD4, ("Round(",)),
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
                for operator in operators:
                    self.assertIn(operator, text)


if __name__ == "__main__":
    unittest.main()

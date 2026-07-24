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


if __name__ == "__main__":
    unittest.main()

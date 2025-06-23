from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestDecompilationWorkflows(unittest.TestCase):
    """
    Tests for decompilation workflows in angr management (or any other GUI if anyone cares enough to create).
    """

    def test_decompiling_a_function_multiple_times(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_access")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions["main"]
        dec = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec.codegen is not None and dec.codegen.text is not None
        print(dec.codegen.text)

        # decompile again, using decompilation cache
        dec_2 = proj.analyses.Decompiler(func, cfg=proj.kb.cfgs["CFGFast"])
        assert dec_2.codegen is not None and dec_2.codegen.text is not None
        print(dec_2.codegen.text)

        assert dec.codegen.text == dec_2.codegen.text, "Decompilation results should be identical on multiple runs."


if __name__ == "__main__":
    unittest.main()

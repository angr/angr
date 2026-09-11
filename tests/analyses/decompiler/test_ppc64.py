# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest

import angr
from angr.analyses import CFGFast
from angr.analyses.decompiler import Decompiler
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDecompilerPPC64(unittest.TestCase):
    def test_function_whose_calling_convention_is_recovered_from_its_callsites(self):
        # Recovering this function's calling convention runs ReachingDefinitionsAnalysis over its
        # callers. That used to raise on PowerPC64, and the decompiler swallowed the exception and
        # returned nothing at all.
        bin_path = os.path.join(test_location, "ppc64", "fauxware")
        func_addr = 0x10000698

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True)

        d = proj.analyses[Decompiler].prep()(proj.kb.functions[func_addr], cfg=cfg.model)

        assert d.codegen is not None and d.codegen.text, f"decompilation produced nothing: {d.errors}"
        print_decompilation_result(d)


if __name__ == "__main__":
    unittest.main()

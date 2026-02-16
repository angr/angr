# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
import unittest
import os

import angr
from angr.analyses.decompiler import Decompiler
from angr.sim_type import SimTypeFunction, SimTypeFd
from tests.common import print_decompilation_result, bin_location, is_testing

test_location = os.path.join(bin_location, "tests")


class TestDecompilerMIPS(unittest.TestCase):
    def test_function_with_syscall_arguments(self):
        bin_path = os.path.join(test_location, "mipsel", "mips_syscall_demo")
        proj = angr.Project(bin_path)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=is_testing)
        f = proj.kb.functions[0x41C0FC]
        d = proj.analyses[Decompiler].prep(fail_fast=True)(
            f,
            cfg=cfg.model,
        )
        assert d.codegen is not None and d.codegen.text is not None
        print_decompilation_result(d)

        assert isinstance(f.prototype, SimTypeFunction)
        assert len(f.prototype.args) == 4
        assert isinstance(f.prototype.returnty, SimTypeFd)


if __name__ == "__main__":
    unittest.main()

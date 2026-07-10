# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest

from angr.analyses.decompiler import Decompiler
from angr.sim_type import SimTypeFd, SimTypeFunction
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDecompilerMIPS(unittest.TestCase):
    def test_function_with_syscall_arguments(self):
        bin_path = os.path.join(test_location, "mipsel", "mips_syscall_demo")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x41C0FC, run_ccc=False)
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

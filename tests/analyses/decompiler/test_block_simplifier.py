#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestBlockSimplifier(unittest.TestCase):
    """How many simplification passes a block is allowed before the loop gives up on it."""

    def test_a_long_stack_pointer_chain_reaches_a_fixed_point(self):
        proj = angr.Project(os.path.join(test_location, "i386", "deep_sp_chain"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions["caller100"]

        with self.assertNoLogs("angr.analyses.decompiler.block_simplifier", level="ERROR"):
            decompilation = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert decompilation.codegen is not None


if __name__ == "__main__":
    unittest.main()

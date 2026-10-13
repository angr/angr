#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestRedundantJumpEntryBlock(unittest.TestCase):
    def test_entry_block_that_only_jumps_is_kept(self):
        # The first block of drain_retry is only a branch, and the conditional branch at the end of the function
        # jumps back to it. Clinic._remove_redundant_jump_blocks must keep that block, because it is the entry.
        bin_path = os.path.join(test_location, "aarch64", "decompiler", "entry_jump_reentered.o")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        func = proj.kb.functions["drain_retry"]
        assert len(list(func.graph.predecessors(func.startpoint))) == 1

        d = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert d.codegen is not None
        print_decompilation_result(d)
        text = d.codegen.text
        assert text is not None

        # the outer loop goes back to the entry and runs the inner loop again
        assert re.search(r"do\s*\{\s*for \(.*\}\s*while \(", text, re.DOTALL) is not None


if __name__ == "__main__":
    unittest.main()

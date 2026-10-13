#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64", "decbench")


class TestDeadblockRemoverJumptableBoundsCheck(unittest.TestCase):
    def test_redundant_bounds_check_of_a_jump_table_is_kept(self):
        # do_mbyte in libedit (vis.c) at -O0: gcc splits the switch into a jump table and a bit test, and the
        # jump table's own bounds check repeats the outer one, so DeadblockRemover folded it into a goto. The
        # jump-table schema needs that conditional jump to recover the switch.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "libedit_O0_stripped.so"), 0x431335, window=0x800, expand_call_tree=False
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x431335], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "switch (" in text
        for value in (0, 7, 8, 9, 10, 11, 12, 13, 32):
            assert f"case {value}:" in text


if __name__ == "__main__":
    unittest.main()

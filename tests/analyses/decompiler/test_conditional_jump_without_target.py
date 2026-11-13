#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location, complete_calling_conventions_for

test_location = os.path.join(bin_location, "tests")


class TestConditionalJumpWithoutTarget(unittest.TestCase):
    """
    Structuring drops the target of a conditional jump that falls through to the next node. It can
    reach the same statement twice, and then the statement names no target at all. The code generator
    cannot render that, so the branch used to reach the output as raw AIL instead of as C.
    """

    def test_a_conditional_jump_with_no_target_left_is_dropped(self):
        func_addr = 0x408B90
        proj = angr.Project(os.path.join(test_location, "i386", "windows", "rain32.upx"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        complete_calling_conventions_for(proj, [func_addr], recover_variables=True)
        dec = proj.analyses.Decompiler(cfg.functions[func_addr], cfg=cfg.model)

        assert dec.codegen is not None and dec.codegen.text is not None
        # a target-less conditional jump reaches the output as raw AIL through CUnsupportedStatement
        assert "Goto None" not in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

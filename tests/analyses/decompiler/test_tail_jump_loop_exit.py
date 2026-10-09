#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestTailJumpLoopExit(unittest.TestCase):
    def test_mips_conditional_tail_jump_keeps_loop_exit(self):
        # sub_417b50 is a code fragment whose loop exits through a conditional jump into a sibling fragment
        # (0x417954). Clinic rewrites that jump into a tail call; splicing the intermediate call block out of the
        # graph must retarget the ConditionalJump, or the structurer loses the loop exit and emits while (1).
        bin_path = os.path.join(test_location, "mips", "dir")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            fail_fast=True,
            normalize=True,
            data_references=True,
            start_at_entry=False,
            function_starts=[0x417B50, 0x417954],
            regions=[(0x417954, 0x417B94)],
        )
        func = cfg.functions[0x417B50]
        assert len(func.block_addrs_set) == 5
        proj.analyses.CompleteCallingConventions(recover_variables=False)

        d = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert d.codegen is not None
        text = d.codegen.text
        print_decompilation_result(d)

        assert "while (1)" not in text
        assert re.search(r"do\s*\{.*?\}\s*while \(.*v0.*\);", text, re.DOTALL) is not None
        # the tail call to the sibling fragment must follow the loop (returning or not, depending on CFG scope)
        assert re.search(r"\}\s*while \(.*\);\s*(return )?sub_417954\(", text, re.DOTALL) is not None


if __name__ == "__main__":
    unittest.main()

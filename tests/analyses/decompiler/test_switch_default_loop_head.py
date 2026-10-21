#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64", "decompiler")


class TestSwitchDefaultLoopHead(unittest.TestCase):
    def test_switch_default_is_the_loop_head(self):
        # binary_operator() from bash (-O2 -fno-inline). the error call does not return in reality; the scoped CFG
        # stops short of the callee, so the CFG sees a loop whose head is the error block, and inside it a lowered
        # switch-case (a `cmp al` chain) whose default branch jumps back to the loop head. the switch matcher used to
        # absorb the region head as the default node, which left the region without a head.
        bin_path = os.path.join(test_location, "decbench_bash_O2_noinline")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x4840A0, window=0x200, expand_call_tree=False, project_kwargs={"auto_load_libs": False}
        )
        dec = proj.analyses.Decompiler(proj.kb.functions[0x4840A0], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert not dec.errors
        assert not dec.structuring_failures
        text = dec.codegen.text
        assert "switch (" in text, text
        assert "case 33:" in text and "case 45:" in text, text
        # the default case goes back to the loop head
        assert "default:\n" in text and "continue;" in text, text


if __name__ == "__main__":
    unittest.main()

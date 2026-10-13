#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64", "decbench")


class TestLoweredSwitchUnstructurableRewrite(unittest.TestCase):
    def test_if_chain_with_hoisted_assignment_is_kept(self):
        # get_next_format_from_precision in libbsd (fmtcheck.c) at -O2: the c/p/C/s/S else-if chain on *f after the
        # jump-table switch looks like a lowered switch, but its last comparison carries a hoisted assignment and its
        # else path leaves into a shared return tail. The copied comparison node would be a case body ending in a
        # goto, which no switch schema can hold; the pass must keep the if-chain. The two-case chains on *f inside
        # the 'h' and 'l' cases are genuine lowered switches.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "libbsd_O2_stripped.so"), 0x406920, window=0x800, call_tree_depth=1
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x406920], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "case 108:" in text
        assert "case 99:" not in text and "case 112:" not in text


if __name__ == "__main__":
    unittest.main()

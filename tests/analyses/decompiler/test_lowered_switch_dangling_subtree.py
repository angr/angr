#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64", "decbench")


class TestLoweredSwitchDanglingSubtree(unittest.TestCase):
    """
    gcc -O0 lowers a switch into a binary search tree whose walk can stop at a comparison node it cannot
    consume. That node must become the default (or reject the cluster), not a conditionless head successor.
    """

    def test_unconsumed_subtree_rejects_the_cluster(self):
        # avc_update_node in libselinux: the eq-chain reaches a gt node whose sides are a return block and a
        # jump table. a second default candidate rejects the lowered-switch cluster; the if-tree stays.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "libselinux_O0_stripped.so"), 0x40B48A, window=0x400, expand_call_tree=False
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x40B48A], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "switch (" in text
        assert "case 32:" in text
        assert re.search(r"a0 [!=]= 64", text) is not None

    def test_negative_case_range_check(self):
        # ct_visual_char in libedit: the chain ends in (v + 3) <=u 2, the range check for case labels -3..-1,
        # whose body starts with a comparison on another variable.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "libedit_O0_stripped.so"), 0x414E88, window=0x400, expand_call_tree=False
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x414E88], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert text.count("switch (") == 1
        assert "case 4294967292:" in text
        assert "case 4294967293: case 4294967294: case 4294967295:" in text
        assert "default:" in text


if __name__ == "__main__":
    unittest.main()

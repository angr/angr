#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64", "decbench")


class TestLoweredSwitchUnstructurableRewrite(unittest.TestCase):
    def test_rewrite_that_breaks_structuring_is_dropped(self):
        # get_next_format_from_precision in libbsd (fmtcheck.c) at -O2: inside the 'l' case of the jump-table
        # switch, "if (!*f) return; if (*f == 'l') ... else ..." looks like a lowered switch on *f, but its case
        # bodies never converge, so the rewritten graph cannot be structured. The pass must keep the if-chain.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "libbsd_O2_stripped.so"), 0x406920, window=0x800, call_tree_depth=1
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x406920], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert text.count("switch (") == 1
        assert "case 108:" in text


if __name__ == "__main__":
    unittest.main()

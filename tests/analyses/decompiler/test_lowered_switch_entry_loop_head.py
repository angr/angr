#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


class TestLoweredSwitchEntryLoopHead(unittest.TestCase):
    """
    LoweredSwitchSimplifier builds a dominator tree rooted at the function entry. When the entry block is a loop head,
    no node has in-degree 0, and an eagerly evaluated fallback raised StopIteration.
    """

    # fastA2F from cleanflight_DALRCF405 (DecBench, O0); the whitespace-skipping loop starts at the entry block.
    FUNC_ADDR = 0x800F0F8 | 1  # Thumb

    def test_entry_block_with_back_edge(self):
        bin_path = os.path.join(test_location, "armel", "decbench_cleanflight_DALRCF405_O0_stripped.elf")
        proj, cfg = load_project_with_scoped_cfg(bin_path, self.FUNC_ADDR, run_ccc=False)
        func = cfg.functions[self.FUNC_ADDR]
        assert func.graph.in_degree(func.startpoint) > 0

        dec = proj.analyses.Decompiler(func, cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert text.count("switch (") == 1
        assert "case 45:" in text
        assert "case 43:" in text


if __name__ == "__main__":
    unittest.main()

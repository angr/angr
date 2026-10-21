#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64", "decbench")


class TestReturnDuplicatorBlockIdxAlias(unittest.TestCase):
    def test_copies_do_not_alias_ssa_edge_split_blocks(self):
        # tok_wline in libedit at -O2: the return block has four SSA edge-split predecessors at the same address
        # (idx 0..3). ReturnDuplicatorLow numbered its copies from 1, so a copy aliased split block .3 and the
        # merged node had two successors but an unconditional jump; the structurer could not place it.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "libedit_O2_stripped.so"), 0x41AC30, window=0x800, expand_call_tree=False
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x41AC30], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "while (" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

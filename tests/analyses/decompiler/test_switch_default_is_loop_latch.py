#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64", "decbench")


class TestSwitchDefaultIsLoopLatch(unittest.TestCase):
    def test_zlib_gz_decomp_o0(self):
        # gz_decomp (gzread.c) at -O0: the lowered switch on inflate()'s return value sits in a do-while loop whose
        # latch is the switch's default node. The latch's only successors are the loop head and the loop exit, so
        # it can never be structured on its own; the switch must absorb it as it is.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "zlib_minigzip_O0_stripped"), 0x403212, window=0x200, expand_call_tree=False
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x403212], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "do\n" in text
        assert "switch (" in text
        assert "default:" in text
        assert text.count("return 0xffffffff;") == 4


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestVirtualizedEdgeNoDuplicateGoto(unittest.TestCase):
    def test_no_goto_after_a_region_whose_paths_all_transfer_control(self):
        # xattr_decode_keyword() (tar, O2 -fno-inline). The virtualized edge leaves a region that ends with
        # `if (!v) break; else goto L;`. get_last_statement() only reports the break, so a second `goto L` used to
        # be appended after the if, unreachable.
        bin_path = os.path.join(test_location, "x86_64", "decbench_tar_O2_noinline_stripped")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x419FF0, window=0x400, expand_call_tree=False)

        dec = proj.analyses.Decompiler(cfg.functions[0x419FF0], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert re.search(r"(goto LABEL_\w+;)\s*\n\s*\1", text) is None
        assert text.count("goto LABEL_41a007;") == 1
        assert "break;" in text

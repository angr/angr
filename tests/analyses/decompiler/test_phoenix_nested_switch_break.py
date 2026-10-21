#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64", "decbench")


class TestPhoenixNestedSwitchBreak(unittest.TestCase):
    def test_nested_switch_with_the_same_end_breaks_out_of_the_enclosing_case(self):
        # get_next_format_from_precision in libbsd (fmtcheck.c) at -O2: the 'h' and 'l' cases of the jump-table
        # switch each hold a two-case lowered switch on *f whose end is the end of the enclosing switch. A break of
        # the inner switch alone would fall through into the next outer case, so the case must break again after it.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "libbsd_O2_stripped.so"), 0x406920, window=0x800, call_tree_depth=1
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x406920], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert re.search(r"case 104:.*?switch \(.*?\n\s*\}\n\s*break;\n\s*case 106:", text, re.DOTALL)
        assert re.search(r"case 108:.*?switch \(.*?\n\s*\}\n\s*break;\n\s*case 113:", text, re.DOTALL)


if __name__ == "__main__":
    unittest.main()

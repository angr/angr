#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestSwitchEndInsideCase(unittest.TestCase):
    def test_switch_end_is_never_a_block_inside_a_case(self):
        # unary_operator() (coreutils `[`, O0). Every case returns, so the only gotos left when the switch is
        # built are the two that join case 'O' (79) to its own `return v & 1` block. That block used to win the
        # switch-end vote, turning the gotos into breaks and leaving the return unreachable.
        bin_path = os.path.join(test_location, "x86_64", "decbench_coreutils_bracket_O0_stripped")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x403CCB, window=0xA00, call_tree_depth=1)

        dec = proj.analyses.Decompiler(cfg.functions[0x403CCB], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        m = re.search(r"case 79:(.*?)case 83:", text, re.DOTALL)
        assert m is not None
        case_79 = m.group(1)
        assert "break;" not in case_79
        assert re.search(r"return v\d+ & 1;", case_79) is not None
        assert "geteuid()" in case_79

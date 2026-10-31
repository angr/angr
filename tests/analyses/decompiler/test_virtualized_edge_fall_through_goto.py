#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

import angr
from angr.analyses import Decompiler
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestVirtualizedEdgeFallThroughGoto(unittest.TestCase):
    def test_goto_for_the_arm_that_falls_through_to_a_virtualized_edge(self):
        # d_expression_1() in binutils 2.43 ld.bfd (-O2), with libiberty's d_unresolved_name() inlined:
        #     if (di->unresolved_name_state && (IS_DIGIT (peek) || ...))
        #       {
        #         di->unresolved_name_state = -1;
        #         type = d_prefix (di, 0);
        #         if (d_peek_char (di) == 'E')
        #           d_advance (di, 1);
        #       }
        #     else
        #       type = cplus_demangle_type (di);
        #     name = d_unqualified_name (di, type, NULL);
        # In the decompilation, sub_878290 is d_prefix and sub_871680 is cplus_demangle_type. Both outcomes of the 'E'
        # test at 0x87604e continue at 0x876060. When the edge to 0x876060 is virtualized, its source ends with a
        # one-armed `if (... == 69)` whose arm jumps to 0x876060. get_last_statement() only reports that jump, so the
        # false arm used to fall into the else branch's cplus_demangle_type() call instead of reaching a
        # `goto LABEL_876060;` after the if.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "binutils_ld_bfd_O2")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x875D90, window=0xA00, expand_call_tree=False)

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[0x875D90], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert re.search(r"sub_878290\(a0, 0\);\s*if \([^\n]*== 69\)\s*(\{[^{}]*\}|[^\n]*;)\s*goto LABEL_876060;", text)

    def test_no_goto_left_beside_the_trailing_goto_when_the_target_comes_next(self):
        # dd_copy() (coreutils dd). The progress-report arm `if (next_time <= t) { print_xfer_stats(t); ... }` and its
        # untaken path both continue at the read loop at 0x403195. The goto appended after the if is removed because
        # the loop comes next, and the arm's own goto to 0x403195 must be removed with it.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "dd.o")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(proj.kb.functions["dd_copy"], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert "print_xfer_stats(" in text
        assert "LABEL_403195" not in text

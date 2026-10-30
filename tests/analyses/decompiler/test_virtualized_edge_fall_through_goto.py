#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

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

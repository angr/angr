#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest
import re

import networkx

import angr

from tests.common import bin_location, print_decompilation_result, WORKER

test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestPartialRegReads(unittest.TestCase):
    def test_partial_reg_read_after_full_reg_write(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "03fb29dab8ab848f15852a37a1c04aa65289c0160d9200dceff64d890b3290dd"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        func = cfg.functions[0x132B0]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # the variable used in the condition `if (v28 > 4)` (within the do-while loop) must be properly assigned before
        # the loop; so we should expect two assignments to this variable in the decompilation
        cond = re.search(r"if \((?P<var>v\d+) > 4\)", dec.codegen.text)
        assert cond is not None
        var_name = cond.group("var")

        # also find the unicode variable on the stack
        unicode_var = re.search(r"UNICODE_STRING (?P<var>v\d+);", dec.codegen.text)
        assert unicode_var is not None
        unicode_var_name = unicode_var.group("var")

        # let's build a graph of assignments
        g = networkx.DiGraph()
        for match in re.finditer(r"(?P<dst>\S+) = (?P<src>\S+)[;,]", dec.codegen.text):
            dst = match.group("dst")
            src = match.group("src")
            g.add_edge(dst, src)

        assert var_name in g
        assert f"{unicode_var_name}.Length" in g

        # there should be two paths from var_name to unicode_var_name.Length, which represents two different
        # assignments (one before the do-while loop, one at the end of the do-while loop).
        simple_paths = list(networkx.all_simple_paths(g, var_name, f"{unicode_var_name}.Length"))
        assert (
            len(simple_paths) == 2
        ), f"Expect two assignments to {var_name} from {unicode_var_name}.Length; found {len(simple_paths)}"


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest
import re

import angr

from tests.common import bin_location, print_decompilation_result, set_decompiler_option, WORKER


test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestHeadControlledLoops(unittest.TestCase):
    def test_head_controlled_loop_xchg_false_positive(self):
        # a bug in ssailification.RewritingEngine causes us to misinterpret an xchg (where VEX generates a conditional
        # jump to mimic CAS effects) as a head-controlled loop (e.g., for rep stosb). as a result of this bug, we will
        # see "12" or "0xc" in the decompilation result (for the instruction at 0x140003767), which is what we are
        # testing here. Note that "v3 + 12" is intended, but "0 + 12" or "12" is not.
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "9c75d43ec531c76caa65de86dcac0269d6727ba4ec74fe1cac1fda0e176fd2ab"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        func = cfg.functions[0x1400036C0]
        assert func is not None
        dec = proj.analyses.Decompiler(
            func, cfg=cfg, options=set_decompiler_option(None, [("show_local_types", False)])
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        t = dec.codegen.text
        m = re.search(r"v\d+ \+ 12", t)
        if m is not None:
            t = dec.codegen.text.replace(m.group(0), "--REPLACED--")
        assert "12" not in t and "0xc" not in t


if __name__ == "__main__":
    unittest.main()

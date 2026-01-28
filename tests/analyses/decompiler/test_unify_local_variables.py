#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr

from tests.common import bin_location, print_decompilation_result, WORKER

test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestUnifyLocalVariables(unittest.TestCase):
    def test_unify_local_variables_skip_outdated_eqs(self):
        bin_path = os.path.join(test_location, "x86_64", "split-rust")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER, fail_fast=True, normalize=True, regions=[(0x503FC0, 0x504200)]
        )
        proj.analyses.CompleteCallingConventions()
        func = cfg.functions[0x503FC0]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg, options=[("semvar_naming", False)])
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert "a0[1]" in dec.codegen.text
        assert "a0[2]" in dec.codegen.text
        assert "a0[0]" in dec.codegen.text or "*(a0)" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

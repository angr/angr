#!/usr/bin/env python3
from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

from angr.analyses.decompiler.decompiler import Decompiler
from tests.common import bin_location, load_project_with_scoped_cfg

# sub_401d30 has a duplicate candidate below a block that ends in a call whose callee may or may not return, so the
# block has two successors without a conditional jump; listing the candidate's blocks read true_target off the call.
TRUE_BIN = os.path.join(bin_location, "tests", "x86_64", "true")
TRUE_FUNC = 0x401D30


class TestDuplicationReverter(TestCase):
    def test_a_call_that_forks_the_flow_is_an_unsupported_candidate(self):
        proj, cfg = load_project_with_scoped_cfg(TRUE_BIN, TRUE_FUNC)
        func = cfg.functions[TRUE_FUNC]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert dec.codegen is not None and dec.codegen.text is not None


if __name__ == "__main__":
    unittest.main()

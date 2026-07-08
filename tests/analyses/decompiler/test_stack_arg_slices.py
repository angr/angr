#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestStackArgSlices(unittest.TestCase):
    def test_2ac79168_stack_arg_accessed_as_two_slices(self):
        # the function reads the 8-byte stack argument slot at sp+40 as two 4-byte slices (sp+40 and
        # sp+44). ssailification used to seed the initial rewriting state with the resized argument vvar
        # for both extern defs, leaving bytes 44-47 undefined and crashing with KeyError(44) when
        # rewriting the load at sp+44. the argument must stay full-width (both slices extract from it),
        # and expression narrowing must not shrink it back to 4 bytes (Extract offsets are in bytes, not
        # bits), which would collapse the high-half read into the low half.
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "2ac79168ca17bfdbf70b591dc681114afc29f09aba0df978c3a7db6ed69a3b59"
        )
        proj = angr.Project(bin_path)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        proj.analyses.CompleteCallingConventions()
        func = cfg.functions[0x1800722C4]
        assert func is not None
        dec = proj.analyses.Decompiler(func, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # the high half of the stack argument must be read at offset +4 from the argument, not as the
        # argument itself
        assert re.search(r"\(void\s*\*\)\s*&a\d+ \+ 4", dec.codegen.text) is not None


if __name__ == "__main__":
    unittest.main()

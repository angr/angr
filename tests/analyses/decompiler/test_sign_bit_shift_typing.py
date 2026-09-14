#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestSignBitShiftTyping(unittest.TestCase):
    def test_sign_bit_extraction_does_not_force_unsigned(self):
        # long absval(long x) { if (x < 0) return -x; return x + 1; } at O0: the cmp/jns condition is rewritten
        # to (x >> 63) & 1, and the logical shift must not type x (and the return value) as unsigned
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "signbit_shr_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name="absval")
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text

        assert ">> 63" in text
        assert "unsigned long long absval(" not in text
        assert "long long absval(" in text


if __name__ == "__main__":
    unittest.main()

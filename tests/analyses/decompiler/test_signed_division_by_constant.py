#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestSignedDivisionByConstant(unittest.TestCase):
    def test_gzip_o0_fprint_off_signed_div_and_mod_by_10(self):
        # off_t / 10 and off_t % 10 compiled as imul 0x6666666666666667, sar 2 of the high half, minus sar 63
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "decbench_gzip_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name="fprint_off")
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text

        assert "7378697629483820647" not in text
        assert "int128_t" not in text
        assert text.count("i /= 10;") == 2
        assert text.count("(i % 10)") == 2
        # the 8-bit store must not narrow the modulo operand
        assert "& 0xff) % 10" not in text


if __name__ == "__main__":
    unittest.main()

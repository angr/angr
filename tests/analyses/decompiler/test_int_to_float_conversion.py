#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestIntToFloatConversion(unittest.TestCase):
    def test_vcvt_from_int_keeps_the_conversion(self):
        # compare_floats(int delta, float a, float b): if ((a - b) >= 0 && (a - b) < delta) return 1; ...
        # `delta` is converted with vcvt.f32.s32, which VEX lifts as F64toF32(I32StoF64(x)). Folding that to x dropped
        # the conversion, reinterpreted the integer bits as a float, and typed `delta` as float.
        bin_path = os.path.join(test_location, "armhf", "float_int_conversion.elf")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x8317, window=0x100)

        func = cfg.functions[0x8317]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert "__int_as_float" not in text
        assert re.search(r"compare_floats\(int a0, float a1, float a2\)", text) is not None
        assert re.search(r"(\w+) - (\w+) >= 0\.0f && \1 - \2 < \(float\)a0", text) is not None


if __name__ == "__main__":
    unittest.main()

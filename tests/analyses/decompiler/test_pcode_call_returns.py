#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestPcodeCallReturns(unittest.TestCase):
    def test_two_calls_in_one_function_decompile(self):
        bin_path = os.path.join(test_location, "m68k", "mul_add_sub_xor_m68k_be")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x80000138)

        dec = proj.analyses.Decompiler(cfg.functions[0x80000138], cfg=cfg.model)
        assert [str(error.exc_value) for error in dec.errors] == []
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "frame_dummy(" in dec.codegen.text
        assert "__do_global_ctors_aux(" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest
from unittest import mock

from angr.analyses.calling_convention.calling_convention import CallingConventionAnalysis
from angr.sim_type import SimTypeBottom
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")

CADET_SAMPLE = os.path.join(test_location, "cgc", "CADET_SAMPLE")
CHECKSUM_ADDR = 0x8048735


class TestPartialRegReturn(unittest.TestCase):
    def test_push_pop_caller_saved_reg_is_not_an_argument(self):
        # sub_8048735 saves ecx with push/pop and xors a2 with every byte of [a1, a0), returning it in eax
        proj, cfg = load_project_with_scoped_cfg(CADET_SAMPLE, CHECKSUM_ADDR, window=0x200, expand_call_tree=False)
        func = proj.kb.functions[CHECKSUM_ADDR]
        assert func.prototype is not None and len(func.prototype.args) == 3
        assert not isinstance(func.prototype.returnty, SimTypeBottom)

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None
        text = dec.codegen.text
        assert "_INSERT" not in text
        assert re.search(r"return v\d+;", text), text
        assert re.search(r"\*\(char \*\)&v\d+ = \(char\)v\d+ \^ \*v\d+;", text), text

    def test_return_carries_default_return_register_without_prototype(self):
        proj, cfg = load_project_with_scoped_cfg(
            CADET_SAMPLE, CHECKSUM_ADDR, window=0x200, expand_call_tree=False, run_ccc=False
        )
        func = proj.kb.functions[CHECKSUM_ADDR]

        def no_cc(self):
            self.cc = None
            self.prototype = None

        # the body xors eax; without a return value it would be dead and removed
        with mock.patch.object(CallingConventionAnalysis, "_analyze", no_cc):
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None
        assert re.search(r"return v\d+;", dec.codegen.text), dec.codegen.text
        assert "^" in dec.codegen.text, dec.codegen.text


if __name__ == "__main__":
    unittest.main()

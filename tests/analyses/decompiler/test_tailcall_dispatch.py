# pylint:disable=missing-class-docstring,missing-function-docstring,no-self-use
"""
A switch whose cases tail-call other functions must decompile to calls, not to the inlined bodies of the targets.
See tests/analyses/cfg/test_cfgfast_eh_frame_boundaries.py for the binaries.
"""

from __future__ import annotations

import os
import re
import unittest

import angr
from angr.analyses import CFGFast, CompleteCallingConventionsAnalysis, Decompiler
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests", "x86_64")


class TestTailcallDispatch(unittest.TestCase):
    def _decompile(self, binary: str, func_addr: int) -> str:
        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
        proj.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.kb.functions[func_addr], cfg=cfg.model)
        assert dec.codegen is not None
        return dec.codegen.text

    def _check(self, text: str, targets: set[int]):
        calls = {int(m, 16) for m in re.findall(r"\bsub_([0-9a-f]+)\(", text)}
        assert targets <= calls, f"missing calls to {[hex(a) for a in targets - calls]}"
        # the bodies of the targets call printf; the dispatcher itself does not
        assert "printf" not in text
        assert "switch" in text

    def test_fde_only(self):
        text = self._decompile("tailcall_dispatch_nocet", 0x401530)
        self._check(text, {0x4011C0, 0x401250, 0x4012E0, 0x401380, 0x401410, 0x4014A0})

    def test_endbr_only(self):
        text = self._decompile("tailcall_dispatch_cet_nofde", 0x401540)
        self._check(text, {0x4011C0, 0x401250, 0x4012E0, 0x401390, 0x401420, 0x4014B0})


if __name__ == "__main__":
    unittest.main()

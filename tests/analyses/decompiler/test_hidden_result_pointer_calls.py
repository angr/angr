#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from angr.calling_conventions import SimCCMicrosoftAMD64
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestHiddenResultPointerCalls(unittest.TestCase):
    def test_win64_result_stored_through_the_hidden_pointer(self):
        # sub_180042640 returns its result through a hidden pointer in rcx. the caller passes a stack buffer there and
        # reads it after the call, so the call must show the buffer instead of dropping it with rcx
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "bed50bc879465dbc83a3baec5b005a526216e5d4ce9afce9684fdb17fbf7816a"
        )
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x1800413DE, extra_func_addrs=[0x180042640], window=0x1000, expand_call_tree=False
        )
        callee = proj.kb.functions[0x180042640]
        assert type(callee.calling_convention) is SimCCMicrosoftAMD64
        dec = proj.analyses.Decompiler(proj.kb.functions[0x1800413DE], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        calls = re.findall(r"^\s*(.*)sub_180042640\(([^()]*)\);$", dec.codegen.text, re.MULTILINE)
        assert len(calls) == 2, dec.codegen.text
        for lhs, args in calls:
            assert re.fullmatch(r"\*\(int128_t \*\)&(\w+)\[\d+\] = ", lhs), dec.codegen.text
            assert "," not in args, dec.codegen.text


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from angr.calling_conventions import SimCCMicrosoftAMD64, SimCCMicrosoftAMD64NoStructReturn
from angr.sim_type import SimStruct, TypeRef
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestHiddenResultPointerCalls(unittest.TestCase):
    def test_win64_hidden_result_pointer_upgrade(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "bed50bc879465dbc83a3baec5b005a526216e5d4ce9afce9684fdb17fbf7816a"
        )
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x180042640, extra_func_addrs=[0x1800413DE], window=0x1000, expand_call_tree=False
        )
        options = [("upgrade_hidden_ptrarg_to_retval", True)]
        callee = proj.kb.functions[0x180042640]
        assert isinstance(callee.calling_convention, SimCCMicrosoftAMD64NoStructReturn)

        dec = proj.analyses.Decompiler(callee, cfg=cfg.model, options=options)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert re.search(r"\* sub_180042640\(\w+ \*a0, \w+ \*a1\)", dec.codegen.text), dec.codegen.text
        assert type(callee.calling_convention) is SimCCMicrosoftAMD64
        assert callee.prototype is not None
        returnty = callee.prototype.returnty
        if isinstance(returnty, TypeRef):
            returnty = returnty.type
        assert isinstance(returnty, SimStruct)
        assert [loc.reg_name for loc in callee.calling_convention.arg_locs(callee.prototype)] == ["rdx"]

        dec = proj.analyses.Decompiler(proj.kb.functions[0x1800413DE], cfg=cfg.model, options=options)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        calls = re.findall(r"^\s*(.*)sub_180042640\(([^()]*)\);$", dec.codegen.text, re.MULTILINE)
        assert len(calls) == 2, dec.codegen.text
        for lhs, args in calls:
            assert re.fullmatch(r"\*\(struct \w+ \*\)&\w+\[\d+\] = ", lhs), dec.codegen.text
            assert "," not in args, dec.codegen.text


if __name__ == "__main__":
    unittest.main()

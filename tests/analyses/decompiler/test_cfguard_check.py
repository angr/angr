# pylint:disable=missing-class-docstring,no-self-use
"""
Windows Control-Flow-Guard (CFG) check mode instruments every indirect call as
``mov rcx, <target>; call [__guard_check_icall_fptr]; call <target>``. The check pointer statically points to a `ret`
stub (_guard_check_icall_nop), so the check must be removed instead of being decompiled as a call to the stub.
"""

from __future__ import annotations

import os
import unittest

import angr
from angr.analyses import Decompiler
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _decompile(bin_path: str, func_addr: int) -> str:
    # the CFG covers the whole binary: a region-scoped CFG resolves some calls after a check to the check stub
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses[angr.analyses.CFGFast].prep()(normalize=True)
    d = proj.analyses[Decompiler].prep(fail_fast=True)(func_addr, cfg=cfg.model)
    assert d.codegen is not None and d.codegen.text is not None
    return d.codegen.text


class TestCFGuardCheck(unittest.TestCase):
    def test_amd64_check_calls_are_removed(self):
        # notepad.exe; the check stub is sub_140014890
        text = _decompile(
            os.path.join(
                test_location, "x86_64", "windows", "534530cf9e140bf637950070e3f9b73220a3ac2cc394cb8f9ba5003096e33583"
            ),
            0x140001290,
        )
        assert "sub_140014890(" not in text
        # the three checked indirect calls remain
        assert "->field_70(a1, &v2)" in text
        assert "(v2, 0x80058000, &v1)" in text
        assert "->field_10(v2)" in text

    def test_amd64_check_calls_through_a_register_are_removed(self):
        # CRT code loads the check pointer into rax first: mov rax, [__guard_check_icall_fptr]; call rax
        text = _decompile(
            os.path.join(
                test_location, "x86_64", "windows", "534530cf9e140bf637950070e3f9b73220a3ac2cc394cb8f9ba5003096e33583"
            ),
            0x140014030,
        )
        assert "sub_140014890(" not in text
        assert "g_14001c6d0(0, 2, 0);" in text

    def test_x86_check_calls_are_removed(self):
        # the check stub is sub_407eb0
        text = _decompile(
            os.path.join(
                test_location, "i386", "windows", "9888704382abfb694984c1c7a7707a45b4ebc406fc98d35622461077553aa797"
            ),
            0x407E6D,
        )
        assert "sub_407eb0(" not in text
        assert "g_417d14(a0);" in text


if __name__ == "__main__":
    unittest.main()

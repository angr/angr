#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import re
import unittest

import angr


class TestFloatArgumentTypes(unittest.TestCase):
    def test_register_copy_passed_as_double_vararg(self):
        # Win64: v = a0->field_8 (movsd xmm6); poke(); printf("%d%d%d%g", 0, 0, 0, v) with v stored to [rsp+0x20].
        # The %g bound on the copy must override the default integer bound the load's type variable gets.
        code = bytes.fromhex(
            "534883ec400f29742430f20f107108e827000000f20f11742420488d0d1c00000031d24531c04531c9e80e0000000f2874"
            "243031c04883c4405bc3c3c3256425642564256700"
        )
        proj = angr.load_shellcode(code, "AMD64", load_address=0x400000, start_offset=0, simos="windows")
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000], fail_fast=True, show_progressbar=False)
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        printf = proj.kb.functions[0x40003C]
        printf.name = "printf"
        printf.prototype = angr.types.parse_signature("int printf(const char *fmt, ...);").with_arch(proj.arch)

        dec = proj.analyses.Decompiler(cfg.functions[0x400000], cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        m = re.search(r"(\w+) = a0->field_8;\s+sub_40003b\(\);\s+printf\(\"%d%d%d%g\", 0, 0, 0, \1\);", text)
        assert m is not None, text
        assert re.search(r"double field_8;", text), text
        assert re.search(r"double " + m.group(1) + ";", text), text


if __name__ == "__main__":
    unittest.main()

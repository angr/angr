#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr


class TestSSAOverlappingStackWrites(unittest.TestCase):
    def test_partial_write_into_slot_overlapping_another(self):
        # a VMProtect NOR on 4-byte-offset 8-byte slots: the dword store at rsp-0x34 keeps rsp-0x30..-0x2c, which
        # belongs to the slot at rsp-0x30, not to the 8-byte slot at rsp-0x38 that covers rsp-0x34
        code = bytes.fromhex(
            "894c24d0"  # mov [rsp-0x30], ecx
            "48897c24c8"  # mov [rsp-0x38], rdi
            "c74424cc11111111"  # mov dword [rsp-0x34], 0x11111111
            "897424c8"  # mov [rsp-0x38], esi
            "48f75424c8"  # not qword [rsp-0x38]
            "8b4424c8"  # mov eax, [rsp-0x38]
            "250f0f0f0f"  # and eax, 0x0f0f0f0f
            "894424cc"  # mov [rsp-0x34], eax
            "48895424c4"  # mov [rsp-0x3c], rdx
            "48f75424cc"  # not qword [rsp-0x34]
            "8b4424cc"  # mov eax, [rsp-0x34]
            "214424d0"  # and [rsp-0x30], eax
            "488b4424d0"  # mov rax, [rsp-0x30]
            "c3"
        )
        proj = angr.load_shellcode(code, arch="amd64")
        proj.vm_deobfuscation = True
        cfg = proj.analyses.CFGFast(normalize=True)
        dec = proj.analyses.Decompiler(cfg.functions[0], cfg=cfg.model, fail_fast=True, vm_deobfuscation=True)
        assert dec.codegen is not None
        text = dec.codegen.text
        # 0x11111111 is overwritten before it is read; 0xeeeeeeee is the stale high half of the 8-byte not at rsp-0x38
        assert "0x11111111" not in text and "1111111100000000" not in text
        assert "0xeeeeeeee" not in text
        assert "0xf0f0f0f" in text


if __name__ == "__main__":
    unittest.main()

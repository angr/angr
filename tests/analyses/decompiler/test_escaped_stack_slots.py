#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import re
import unittest

import angr


def _decompile(code: bytes):
    proj = angr.load_shellcode(code, "AMD64", load_address=0x400000, start_offset=0)
    cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000], fail_fast=True, show_progressbar=False)
    proj.analyses.CompleteCallingConventions(recover_variables=False)
    dec = proj.analyses.Decompiler(cfg.functions[0x400000], cfg=cfg, fail_fast=True)
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec


class TestEscapedStackSlots(unittest.TestCase):
    """
    A callee may write a stack variable whose address it was given. A read of the variable after the call must not
    resolve to the definition before the call.
    """

    def test_read_after_call_through_escaped_address(self):
        # _start(n): lz = n - 4; helper(&lz); if (lz != n - 4) warn(3);    helper(p): *p = 7; return 1
        #   push rbx; sub rsp, 0x10; lea ebx, [rdi-4]; mov [rsp+0xc], ebx; lea rdi, [rsp+0xc]; call helper
        #   cmp [rsp+0xc], ebx; je L; mov edi, 3; call warn; L: add rsp, 0x10; pop rbx; ret
        # helper: mov dword [rdi], 7; mov eax, 1; ret      warn: mov eax, edi; ret
        code = bytes.fromhex(
            "534883ec108d5ffc895c240c488d7c240ce816000000395c240c740abf03000000e8120000004883c4105bc3"
            "c70707000000b801000000c389f8c3"
        )
        dec = _decompile(code)
        text = dec.codegen.text
        # the comparison is not folded away, so the second call stays
        assert "sub_400038(3)" in text, text
        assert not re.search(r"\b(v\d+) [!=]= \1\b", text), text


if __name__ == "__main__":
    unittest.main()

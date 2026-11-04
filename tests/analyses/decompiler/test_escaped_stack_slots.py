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

    def test_load_not_moved_across_call_after_escape(self):
        # _start(n): x = n; escape(&x); before = x; poke(); return before - x;
        #   push rbx; sub rsp, 0x10; mov [rsp+0xc], edi; lea rdi, [rsp+0xc]; call escape; mov ebx, [rsp+0xc]
        #   call poke; mov eax, ebx; sub eax, [rsp+0xc]; add rsp, 0x10; pop rbx; ret
        # escape: mov dword [rdi], 7; ret      poke: mov eax, 1; ret
        code = bytes.fromhex(
            "534883ec10897c240c488d7c240ce8150000008b5c240ce81300000089d82b44240c4883c4105bc3c70707000000c3"
            "b801000000c3"
        )
        text = _decompile(code).codegen.text
        assert not re.search(r"\b(v\d+) - \1\b", text), text

    def test_load_moved_across_call_before_escape(self):
        # _start(n): x = n; before = x; poke(); use(before); escape(&x); return x;
        # poke cannot write x yet, so `before` is still x at use()
        code = bytes.fromhex(
            "534883ec10897c240c8b5c240ce82200000089dfe821000000488d7c240ce80a0000008b44240c4883c4105bc3c707"
            "07000000c3b801000000c389f8c3"
        )
        text = _decompile(code).codegen.text
        assert re.search(r"sub_400034\(\);\s+sub_40003a\(v0\);", text), text

    def test_load_not_moved_across_call_after_escape_in_loop(self):
        # _start(n): x = n; do { before = x; poke(); use(before); } while (escape(&x)); return x;
        # from the second iteration on poke() runs after escape(&x)
        code = bytes.fromhex(
            "534883ec10897c240c8b5c240ce82800000089dfe827000000488d7c240ce80e00000085c075e28b44240c4883c410"
            "5bc3c7070700000031c0c3b801000000c389f8c3"
        )
        text = _decompile(code).codegen.text
        assert not re.search(r"sub_40003a\(\);\s+sub_400040\(v0\);", text), text


if __name__ == "__main__":
    unittest.main()

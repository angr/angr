#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import re
import unittest

import angr


def _decompile(code: bytes, names: dict[int, str] | None = None) -> str:
    names = names or {}
    proj = angr.load_shellcode(code, "AMD64", load_address=0x400000, start_offset=0)
    cfg = proj.analyses.CFGFast(
        normalize=True, function_starts=[0x400000, *names], fail_fast=True, show_progressbar=False
    )
    for addr, name in names.items():
        cfg.functions[addr].name = name
    proj.analyses.CompleteCallingConventions(recover_variables=False)
    dec = proj.analyses.Decompiler(cfg.functions[0x400000], cfg=cfg, fail_fast=True)
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec.codegen.text


class TestGlobalReadsAcrossStores(unittest.TestCase):
    """
    A read of a global must not be moved past a store that may write it.
    """

    def test_global_read_not_moved_across_store_through_pointer(self):
        # _start(p): x = g; *p = 1; return x - g;      p may be &g
        #   mov eax, [rip+g]; mov dword [rdi], 1; sub eax, [rip+g]; ret      g: .long 0
        code = bytes.fromhex("8b050e000000c707010000002b0502000000c39000000000")
        text = _decompile(code)
        assert not re.search(r"\b(g_\w+) - \1\b", text), text

    def test_global_read_not_moved_into_loop_that_writes_it(self):
        # _start(): x = g; s = 0; for (i = 3; i; i--) { s = (s + x) * x - x; g = i; } return s;
        code = bytes.fromhex("8b0d1a00000031c0ba0300000001c80fafc129c8891506000000ffca75efc39000000000")
        text = _decompile(code)
        body = text[text.index("{") :]
        reads = re.findall(r"\bg_400020\b(?! = )", body)
        assert len(reads) == 1, text

    def test_single_use_global_read_not_moved_into_loop_that_writes_it(self):
        # _start(): x = g; s = 0; for (i = 3; i; i--) { s += x; g = i; } return s;
        # the loop is one block: the store follows the use in the use's own block
        code = bytes.fromhex("8b0d1600000031c0ba0300000001c8891507000000ffca75f4c3909000000000")
        text = _decompile(code)
        body = text[text.index("{") :]
        reads = re.findall(r"\bg_40001c\b(?! = )", body)
        assert len(reads) == 1, text

    def test_global_read_moved_across_store_to_allocation(self):
        # _start(a): p = xmalloc(16); p[0] = a; p[1] = head; head = p;
        # *p cannot be head: p points into memory the allocator returned
        code = bytes.fromhex(
            "534889fbbf10000000e819000000488b1425000060004889184889500848890425000060005bc331c0c3909090909090"
        )
        text = _decompile(code, {0x400027: "xmalloc"})
        assert re.search(r"\[1\] = g_600000;", text), text


if __name__ == "__main__":
    unittest.main()

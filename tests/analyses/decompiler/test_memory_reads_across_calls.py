#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import re
import unittest

import angr


def _decompile(code: bytes) -> str:
    proj = angr.load_shellcode(code, "AMD64", load_address=0x400000, start_offset=0)
    cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000], fail_fast=True, show_progressbar=False)
    proj.analyses.CompleteCallingConventions(recover_variables=False)
    dec = proj.analyses.Decompiler(cfg.functions[0x400000], cfg=cfg, fail_fast=True)
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec.codegen.text


class TestMemoryReadsAcrossCalls(unittest.TestCase):
    """
    A call may write any global or heap location. A read of one before the call must not be moved after it.
    """

    def test_global_read_not_moved_across_call(self):
        # _start(): x = g; poke(); return x - g;      poke(): g = 1;
        #   push rbx; mov ebx, [rip+g]; call poke; mov eax, ebx; sub eax, [rip+g]; pop rbx; ret
        #   poke: mov dword [rip+g], 1; ret      g: .long 0
        code = bytes.fromhex("538b1d1a000000e80a00000089d82b050d0000005bc3c7050100000001000000c300000000")
        text = _decompile(code)
        assert not re.search(r"\b(g_\w+) - \1\b", text), text

    def test_heap_read_not_moved_across_call(self):
        # _start(p): x = *p; poke(p); return x - *p;      poke(p): *p = 1;
        code = bytes.fromhex("53554883ec084889fd8b1f4889efe80c00000089d82b45004883c4085d5bc3c70701000000c3")
        text = _decompile(code)
        assert not re.search(r"(\*a0) - \*a0\b", text), text

    def test_global_read_not_moved_into_loop_with_call(self):
        # _start(): x = g; for (i = 3; i; i--) { use(x); poke(); }
        # from the second iteration on, g has been written by poke()
        code = bytes.fromhex(
            "53554883ec088b1d2a000000bd0300000089dfe810000000e80e000000ffcd75f04883c4085d5bc389f8c3c705010000"
            "0001000000c300000000"
        )
        text = _decompile(code)
        assert not re.search(r"sub_400028\(g_\w+\)", text), text

    def test_global_read_after_call_still_propagated(self):
        # _start(): poke(); return use(g);
        code = bytes.fromhex("4883ec08e8130000008b3d18000000e8050000004883c408c389f8c3c7050100000001000000c300000000")
        text = _decompile(code)
        assert re.search(r"return sub_400019\(g_\w+\);", text), text


if __name__ == "__main__":
    unittest.main()

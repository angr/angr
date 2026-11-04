#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr

# gcc -O1 of
#   int check(const char *s) {
#       if (s[0] != 'a') goto fail; puts("one");
#       if (s[1] != 'b') goto fail; puts("two");
#       if (s[2] != 'c') goto fail; puts("three");
#       if (s[3] != 'd') goto fail; puts("ok"); return 0;
#   fail: puts("bad"); puts("input"); return 1;
#   }
# and check2, the same with two guards.
CHECK = bytes.fromhex(
    "53803f61741f488d3dcf0e0000e8e5feffff488d3dc70e0000e8d9feffffb8010000005bc34889fb488d3d9c0e0000e8c3feffff807b01"
    "6275cc488d3d8e0e0000e8b1feffff807b026375ba488d3d800e0000e89ffeffff807b036475a8488d3d740e0000e88dfeffffb8000000"
    "00ebb2"
)
CHECK2 = bytes.fromhex(
    "53803f617413488d3d5e0e0000e874feffffb8010000005bc34889fb488d3d370e0000e85efeffff807b016275d8488d3d330e0000e84c"
    "feffffb800000000ebd6"
)


def _decompile(code: bytes) -> str:
    proj = angr.load_shellcode(code, arch="AMD64", load_address=0x401139)
    cfg = proj.analyses.CFGFast(normalize=True)
    dec = proj.analyses.Decompiler(proj.kb.functions[0x401139], cfg=cfg.model)
    assert dec.codegen is not None
    return dec.codegen.text


def _max_indent(text: str) -> int:
    return max(len(line) - len(line.lstrip(" ")) for line in text.splitlines() if line.strip())


class TestPhoenixSharedGuardExit(unittest.TestCase):
    def test_guard_chain_to_a_shared_exit_is_flat(self):
        # if-then over each guard's dead-end branch nested the chain one level per guard
        text = _decompile(CHECK)
        assert _max_indent(text) == 8, text
        assert text.count("return 1;") == 4, text

    def test_two_guards_still_nest(self):
        text = _decompile(CHECK2)
        assert _max_indent(text) == 12, text
        assert "goto" not in text, text


if __name__ == "__main__":
    unittest.main()

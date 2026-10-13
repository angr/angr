#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr

# binary_operator() from bash (-O2 -fno-inline). the error call does not return in reality, so the CFG sees a
# loop whose head is the error block, and inside it a lowered switch-case (a `cmp al` chain) whose default
# branch jumps back to the loop head. the switch matcher used to absorb the region head as the default node,
# which left the region without a head.
BINARY_OPERATOR_CODE = bytes.fromhex(
    "486305c5440c00488b35b2440c00554883c001488b2cc64c8d04c5000000000fb645003c3d0f84ad00000089c283e2fd"
    "80fa3c752b807d01007471488d359b4e070031ffba05000000e802d1faff4889ee4889c7e847f3ffff0f1f8000000000"
    "3c21743c3c2d75d3807d030075cd4889efe8bafeffff85c074c14a8b5406084a8b7406f831c9e8e5f6ffff8b0d3b440c"
    "005d8d5103891531440c00c30f1f4000807d013d7595807d0200758f4a8b5406084a8b7406f84889ef31c9e8b0f6ffff"
    "8b3d06440c005d8d57038915fc430c00c30f1f80000000000fb6450184c074cc3c3d0f8553ffffffebbc"
)


class TestSwitchDefaultLoopHead(unittest.TestCase):
    def test_switch_default_is_the_loop_head(self):
        proj = angr.load_shellcode(BINARY_OPERATOR_CODE, "AMD64", load_address=0x4840A0)
        cfg = proj.analyses.CFGFast(normalize=True)
        dec = proj.analyses.Decompiler(cfg.functions[0x4840A0], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert not dec.errors
        text = dec.codegen.text
        assert "switch (" in text, text
        assert "case 33:" in text and "case 45:" in text, text
        # the default case goes back to the loop head
        assert "default:\n" in text and "continue;" in text, text


if __name__ == "__main__":
    unittest.main()

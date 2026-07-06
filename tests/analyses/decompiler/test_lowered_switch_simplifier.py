#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.analyses.decompiler.optimization_passes import LoweredSwitchSimplifier
from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS

# a character-scanning loop carved out of busybox (compiled at -O0). the comparison chain that
# LoweredSwitchSimplifier recognizes contains back edges to the head comparison node, which used to cause
# an exponential state-space explosion in the cascade traversal.
#
# unsigned int check_name(char *s) {  // originally at 0x4a7f32
#     char c, seen_dot = 0;
#     while ((c = *s++)) {
#         if (c == '.') { if (seen_dot) return 0; seen_dot = 1; }
#         else if ((c <= '/' || c > '9') && (c <= '@' || c > 'Z')) return 0;
#     }
#     return 1;
# }
CHAR_SCAN_LOOP_CODE = bytes.fromhex(
    "48897c24e8c64424ff00488b4424e8488d500148895424e80fb600884424fe"
    "807c24fe00743f807c24fe2e7514807c24ff007406b800000000c3c64424ff"
    "01eb22807c24fe2f7e07807c24fe397ebb807c24fe407e07807c24fe5a7ead"
    "b800000000c3eba590b801000000c3"
)


class TestLoweredSwitchSimplifier(unittest.TestCase):
    def test_comparison_chain_with_back_edges_terminates(self):
        proj = angr.load_shellcode(CHAR_SCAN_LOOP_CODE, "AMD64", load_address=0x4A7F32)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.functions[0x4A7F32]
        all_optimization_passes = DECOMPILATION_PRESETS["full"].get_optimization_passes(
            "AMD64", "linux", additional_opts=[LoweredSwitchSimplifier]
        )

        # this decompilation must terminate (it used to take exponential time and memory)
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, optimization_passes=all_optimization_passes)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "while" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

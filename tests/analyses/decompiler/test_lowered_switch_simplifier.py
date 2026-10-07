#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.decompiler.optimization_passes import LoweredSwitchSimplifier
from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")

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

# a switch lowered into a binary search tree: the entry block compares the variable against a pivot and
# each subtree is a "greater-than" node whose two eq-chains share the case bodies and the default.
#
# int f(int v, int *p) {
#     *p = v;
#     int r;
#     switch (v) {
#     case 0x10: case 0x40: case 0xa0: r = 1; break;
#     case 0x20: case 0x70: case 0xb0: r = 2; break;
#     case 0x50: case 0x80: r = 3; break;
#     default: r = 0; break;
#     }
#     return r + *p;
# }
SWITCH_TREE_CODE = bytes.fromhex(
    "893e83ff607f1d83ff307f0c83ff10743c83ff20743eeb4a83ff40743083ff507439eb3e81ff900000007f0f83ff70"
    "742381ff800000007422eb2781ffa0000000740a81ffb00000007409eb15b801000000eb10b802000000eb09b8030000"
    "00eb0231c00306c3"
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

    def test_gt_node_heading_a_cascade_keeps_its_in_edges(self):
        # each subtree of the tree is a cascade headed by a greater-than node. that node is the only entry into
        # the cascade, so it must become the switch head instead of being removed as a redundant comparison,
        # which orphaned the switch head and the case bodies it shared with the other subtree.
        proj = angr.load_shellcode(SWITCH_TREE_CODE, "AMD64", load_address=0x400000)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.functions[0x400000]
        all_optimization_passes = DECOMPILATION_PRESETS["full"].get_optimization_passes(
            "AMD64", "linux", additional_opts=[LoweredSwitchSimplifier]
        )

        dec = proj.analyses.Decompiler(func, cfg=cfg.model, optimization_passes=all_optimization_passes, fail_fast=True)

        assert not dec.errors
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert text.count("switch (") == 2
        for value in (16, 32, 64, 80, 112, 128, 160, 176):
            assert f"case {value}:" in text
        assert text.count("default:") == 2
        assert "goto" not in text

    def test_redundant_comparison_node_removed_by_an_earlier_one(self):
        # doshn() in file(1) built at -O0 has a comparison chain whose redundant comparison nodes point at one
        # another, so removing one of them orphans the next one the same loop still has to visit.
        proj, cfg = load_project_with_scoped_cfg(os.path.join(test_location, "x86_64", "file_gcc17_O0"), 0x423B74)

        dec = proj.analyses.Decompiler(cfg.functions[0x423B74], cfg=cfg)

        assert not dec.errors
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "switch (" in dec.codegen.text

    def test_orphaned_chain_is_removed_entirely(self):
        # the same shape at -O2, where the orphaned chain is long enough that stopping at the immediate
        # successors leaves nodes unreachable from the function entry and the structurer gives up on them.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "x86_64", "file_gcc13.3.0_O2"), 0x4091D0, window=0x3000
        )

        dec = proj.analyses.Decompiler(cfg.functions[0x4091D0], cfg=cfg)

        assert not dec.errors
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "switch (" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

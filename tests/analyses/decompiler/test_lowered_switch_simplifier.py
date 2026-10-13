#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
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

# a sparse switch compiled at -O0: gcc emits one "eq" node and one "gt" node per case, sorted by value, and every
# "gt" node jumps to the default. the "gt" node after a failed test of the largest remaining value is dead, and the
# run of consecutive values makes the walk mistake those dead branches for extra cases.
#
# int fstype(long t) {
#     switch (t) {
#     case 0xff534d42: return 'A'; case 0xf995e849: return 'B'; case 0xcafe4a11: return 'C';
#     case 0x9123683e: return 'D'; case 0x73757245: return 'E'; case 0x5346544e: return 'F';
#     case 0x1badface: return 'G'; case 0x0bad1dea: return 'H';
#     case 0x012ff7b7: return 'M'; case 0x012ff7b6: return 'N'; case 0x012ff7b5: return 'O';
#     case 0x00011954: return 'I'; case 0x0000ef53: return 'J'; case 0x00004d44: return 'K';
#     case 0x00000187: return 'L';
#     default: return 'U';
#     }
# }
SORTED_O0_CHAIN_CODE = bytes.fromhex(
    "554889e548897df8b8424d53ff483945f80f8473010000b8424d53ff483945f80f8fcd010000b849e895f9483945f80f"
    "845c010000b849e895f9483945f80f8faf010000b8114afeca483945f80f8445010000b8114afeca483945f80f8f9101"
    "0000b83e682391483945f80f842e010000b83e682391483945f80f8f7301000048817df8457275730f84180100004881"
    "7df8457275730f8f5701000048817df84e5446530f840301000048817df84e5446530f8f3b01000048817df8cefaad1b"
    "0f84ee00000048817df8cefaad1b0f8f1f01000048817df8ea1dad0b0f84d900000048817df8ea1dad0b0f8f03010000"
    "48817df8b7f72f010f84c400000048817df8b7f72f010f8fe700000048817df8b6f72f010f84af00000048817df8b6f7"
    "2f010f8fcb00000048817df8b5f72f010f849a00000048817df8b5f72f010f8faf00000048817df8541901000f848500"
    "000048817df8541901000f8f9300000048817df853ef0000747448817df853ef00007f7f48817df887010000746e4881"
    "7df8444d0000745deb69b841000000eb67b842000000eb60b843000000eb59b844000000eb52b845000000eb4bb84600"
    "0000eb44b847000000eb3db848000000eb36b84d000000eb2fb84e000000eb28b84f000000eb21b849000000eb1ab84a"
    "000000eb13b84b000000eb0cb84c000000eb05b8550000005dc3"
)


class TestLoweredSwitchSimplifier(unittest.TestCase):
    def test_sorted_o0_chain_with_dead_gt_branches(self):
        proj = angr.load_shellcode(SORTED_O0_CHAIN_CODE, "AMD64", load_address=0x400000)
        cfg = proj.analyses.CFGFast(normalize=True)
        dec = proj.analyses.Decompiler(cfg.functions[0x400000], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert not dec.errors
        assert text.count("case ") == 15, text
        assert "default:" in text, text
        assert "else" not in text, text
        for value, ret in ((0xFF534D42, 65), (0x012FF7B6, 78), (0x012FF7B5, 79), (0x187, 76)):
            assert re.search(rf"case {value}:\n\s+return {ret};", text), text

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

    def test_floating_point_comparisons_are_not_switch_cases(self):
        # each function tests one float against +inf and then -inf, with a distinct body per test. switch case
        # values are integers, so the chain must stay an if-else chain; a switch on inf and -inf could not be
        # rendered and raised a TypeError.
        proj = angr.Project(os.path.join(test_location, "decompiler_fp", "fcmp_inf_aarch64.o"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)

        for name in ("dispatch_inf", "dispatch_inf_f"):
            dec = proj.analyses.Decompiler(cfg.functions[name], cfg=cfg.model)

            assert not dec.errors
            assert dec.codegen is not None and dec.codegen.text is not None
            assert "switch (" not in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

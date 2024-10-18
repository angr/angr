#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


def run_tracker(track_mem, use_bp):
    p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
    p.analyses.CFGFast()
    main = p.kb.functions["main"]
    sp = p.arch.sp_offset
    regs = {sp}
    if use_bp:
        bp = p.arch.bp_offset
        regs.add(bp)
    sptracker = p.analyses.StackPointerTracker(main, regs, track_memory=track_mem)
    sp_result = sptracker.offset_after(0x4007D4, sp)
    if use_bp:
        bp_result = sptracker.offset_after(0x4007D4, bp)
        return sp_result, bp_result
    return sp_result


def init_tracker(p, func_addr: str | int, track_mem, cross_insn_opt: bool = True):
    p.analyses.CFGFast()
    main = p.kb.functions[func_addr]
    sp = p.arch.sp_offset
    regs = {sp}
    sptracker = p.analyses.StackPointerTracker(main, regs, track_memory=track_mem, cross_insn_opt=cross_insn_opt)
    return sptracker, sp


class TestStackPointerTracker(unittest.TestCase):
    def test_stack_pointer_tracker(self):
        sp_result, bp_result = run_tracker(track_mem=True, use_bp=True)
        assert sp_result == 8
        assert bp_result == 0

    def test_stack_pointer_tracker_no_mem(self):
        sp_result, bp_result = run_tracker(track_mem=False, use_bp=True)
        assert sp_result == 8
        assert bp_result is None

    def test_stack_pointer_tracker_just_sp(self):
        sp_result = run_tracker(track_mem=False, use_bp=False)
        assert sp_result is None

    def test_stack_pointer_tracker_offset_block(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        sptracker, sp = init_tracker(p, "main", track_mem=False)
        sp_result = sptracker.offset_after_block(0x40071D, sp)
        assert sp_result is not None
        sp_result = sptracker.offset_after_block(0x400700, sp)
        assert sp_result is None
        sp_result = sptracker.offset_before_block(0x40071D, sp)
        assert sp_result is not None
        sp_result = sptracker.offset_before_block(0x400700, sp)
        assert sp_result is None

    def test_stack_pointer_tracker_offset_mask(self):
        # SPTracker should treat 0xfffffff8 as a bitmask
        proj = angr.Project(
            os.path.join(
                test_location, "i386", "windows", "39ca9900b5a1aaff6a218a56884f8c235263e3eb4e64c325b357fb028295f0a5"
            ),
            auto_load_libs=False,
        )
        sptracker, sp = init_tracker(proj, 0x401F3E, track_mem=False, cross_insn_opt=False)
        off_0 = sptracker.offset_after(0x401F41, sp)
        off_1 = sptracker.offset_before(0x401F47, sp)
        assert off_0 is not None
        print(off_1 - off_0)
        assert off_1 - off_0 == -0xC


if __name__ == "__main__":
    logging.getLogger("angr.analyses.stack_pointer_tracker").setLevel(logging.INFO)
    unittest.main()

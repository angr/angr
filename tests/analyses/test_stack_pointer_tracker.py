#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr

from ..common import bin_location


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


def init_tracker(track_mem):
    p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
    p.analyses.CFGFast()
    main = p.kb.functions["main"]
    sp = p.arch.sp_offset
    regs = {sp}
    sptracker = p.analyses.StackPointerTracker(main, regs, track_memory=track_mem)
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
        sptracker, sp = init_tracker(track_mem=False)
        sp_result = sptracker.offset_after_block(0x40071D, sp)
        assert sp_result is not None
        sp_result = sptracker.offset_after_block(0x400700, sp)
        assert sp_result is None
        sp_result = sptracker.offset_before_block(0x40071D, sp)
        assert sp_result is not None
        sp_result = sptracker.offset_before_block(0x400700, sp)
        assert sp_result is None


if __name__ == "__main__":
    logging.getLogger("angr.analyses.stack_pointer_tracker").setLevel(logging.INFO)
    unittest.main()

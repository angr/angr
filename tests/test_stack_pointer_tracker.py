
import logging
import os
import nose

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def run_tracker(track_mem, use_bp):
    p = angr.Project(os.path.join(test_location, 'x86_64', 'fauxware'), auto_load_libs=False)
    p.analyses.CFGFast()
    main = p.kb.functions['main']
    sp = p.arch.sp_offset
    regs = {sp}
    if use_bp:
        bp = p.arch.bp_offset
        regs.add(bp)
    sptracker = p.analyses.StackPointerTracker(main, regs, track_memory=track_mem)
    sp_result = sptracker.offset_after(0x4007d4, sp)
    if use_bp:
        bp_result = sptracker.offset_after(0x4007d4, bp)
        return sp_result, bp_result
    else:
        return sp_result

def test_stack_pointer_tracker():
    sp_result, bp_result = run_tracker(track_mem=True, use_bp=True)
    nose.tools.assert_equal(sp_result, 8)
    nose.tools.assert_equal(bp_result, 0)

def test_stack_pointer_tracker_no_mem():
    sp_result, bp_result = run_tracker(track_mem=False, use_bp=True)
    nose.tools.assert_equal(sp_result, 8)
    nose.tools.assert_equal(bp_result, None)

def test_stack_pointer_tracker_just_sp():
    sp_result = run_tracker(track_mem=False, use_bp=False)
    nose.tools.assert_equal(sp_result, None)

if __name__ == '__main__':
    logging.getLogger('angr.analyses.stack_pointer_tracker').setLevel(logging.INFO)
    test_stack_pointer_tracker()
    test_stack_pointer_tracker_no_mem()
    test_stack_pointer_tracker_just_sp()

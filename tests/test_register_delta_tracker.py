
import logging
import os
import nose

import angr

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_register_delta_tracker():
    p = angr.Project(test_location + '/x86_64/fauxware', auto_load_libs=False)
    p.analyses.CFGFast()
    main = p.kb.functions['main']
    sp = p.arch.sp_offset
    bp = p.arch.bp_offset
    sptracker = p.analyses.RegisterDeltaTracker(main, {sp, bp})
    result = sptracker.offset_after(0x4007d4).unfreeze()
    nose.tools.assert_equal(result.regs[sp].offset, 8)
    nose.tools.assert_equal(result.regs[bp].offset, 0)

if __name__ == '__main__':
    logging.getLogger('angr.analyses.register_delta_tracker')
    test_register_delta_tracker()


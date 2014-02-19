#!/usr/bin/env python

import nose

import logging
l = logging.getLogger("angr_tests")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr
import simuvex

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
loop_nolibs = None

def setup_module():
    global loop_nolibs
    loop_nolibs = angr.Project(test_location + "/loop/loop", load_libs=False, default_analysis_mode='symbolic')

def test_loop_entry():
    s = loop_nolibs.sim_run(0x4004f4)
    s_loop = loop_nolibs.sim_run(0x40051A, state=s.exits()[0].state)
    nose.tools.assert_equals(len(s_loop.exits()), 2)
    nose.tools.assert_true(s_loop.exits()[0].reachable()) # True
    nose.tools.assert_false(s_loop.exits()[1].reachable()) # False

def test_loop_escape():
    loop_addrs = [ 0x40051A, 0x400512 ]
    s = loop_nolibs.sim_run(0x4004F4)
    results = angr.surveyors.Escaper(loop_nolibs, loop_addrs, start=s.exits()[0], loop_iterations=4).run()
    nose.tools.assert_equal(results.forced[0].last_run.addr, 0x400520)

def test_loop_escape_head():
    loop_addrs = [ 0x40051A, 0x400512 ]
    s = loop_nolibs.sim_run(0x4004F4)
    first_head = angr.surveyors.Explorer(loop_nolibs, start=s.exits()[0], find=0x400512).run().found[0]
    first_head_exit = simuvex.SimExit(addr=first_head.last_run.first_imark.addr, state=first_head.last_run.initial_state)

    results = angr.surveyors.Escaper(loop_nolibs, loop_addrs, start=first_head_exit, loop_iterations=4).run()
    nose.tools.assert_equal(results.forced[0].last_run.addr, 0x400520)

if __name__ == '__main__':
    setup_module()
    test_loop_escape_head()

#!/usr/bin/env python

import logging
l = logging.getLogger(name=__name__)

import nose
import angr

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
loop_nolibs = None

def setup_module():
    global loop_nolibs
    loop_nolibs = angr.Project(test_location + "/blob/x86_64/loop",  default_analysis_mode='symbolic')

def test_loop_entry():
    s = loop_nolibs.sim_run(loop_nolibs.exit_to(0x4004f4))
    s_loop = loop_nolibs.sim_run(loop_nolibs.exit_to(0x40051A, s.exits()[0].state))
    nose.tools.assert_equals(len(s_loop.exits()), 2)
    nose.tools.assert_true(s_loop.exits()[0].reachable()) # True
    nose.tools.assert_false(s_loop.exits()[1].reachable()) # False

def test_loop_escape():
    loop_addrs = [ 0x40051A, 0x400512 ]
    s = loop_nolibs.sim_run(loop_nolibs.exit_to(0x4004F4))
    results = angr.surveyors.Escaper(loop_nolibs, loop_addrs, start=s.exits()[0], loop_iterations=4).run()
    nose.tools.assert_equal(results.forced[0].addr, 0x400520)

def test_loop_escape_head():
    loop_addrs = [ 0x40051A, 0x400512 ]
    s = loop_nolibs.sim_run(loop_nolibs.state_generator.blank_state(address=0x4004F4))
    first_head = loop_nolibs.surveyors.Explorer(start=s.successors[0], find=0x400512).run().found[0]
    results = loop_nolibs.surveyors.Escaper(loop_addrs, start=first_head, loop_iterations=4).run()
    nose.tools.assert_equal(results.forced[0].addr, 0x400520)

if __name__ == '__main__':
    try:
        __import__('standard_logging')
        __import__('angr_debug')
    except ImportError:
        pass
    setup_module()
    test_loop_escape_head()

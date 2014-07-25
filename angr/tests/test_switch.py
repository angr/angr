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

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
switch_nolibs = None


def setup_module():
    global switch_nolibs
    switch_nolibs = angr.Project(
        test_location +
        "/switch/switch",
        load_libs=False,
        default_analysis_mode='symbolic')


def test_switch():
    s = switch_nolibs.sim_run(switch_nolibs.exit_to(0x400566))
    s_switch = switch_nolibs.sim_run(switch_nolibs.exit_to(0x400573, state=s.conditional_exits[0].state))
    nose.tools.assert_equals(len(s_switch.exits()[0].split(100)), 40)

    new_state = switch_nolibs.initial_state()
    #new_state.store_reg(16, 1)
    new_switch = s_switch.reanalyze(new_state=new_state)
    nose.tools.assert_equals(len(new_switch.exits()[0].split(100)), 1)

if __name__ == '__main__':
    setup_module()
    test_switch()

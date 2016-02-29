#!/usr/bin/env python

"""
This is the first of many syscall tests
"""

import logging
l = logging.getLogger("angr.tests")

import angr
import nose

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
p_rw = None
p = None

def setup_rw():
    global p_rw
    p_rw = angr.Project(test_location + "/blob/x86_64/rw",  use_sim_procedures=False)

def setup_orwc():
    global p
    p = angr.Project(test_location + "/blob/x86_64/orwc",  use_sim_procedures=False)

def setup_module():
    setup_rw()
    setup_orwc()

def test_rw():
    explore = angr.surveyors.Explorer(p_rw, find=[0x400100]).run()
    path = explore.found[0]
    state = path.state
    system = state.get_plugin('posix')
    w_len = system.get_file(1).pos
    r_len = system.get_file(0).pos
    r_len = state.se.any_int(r_len)

    nose.tools.assert_equal(r_len, w_len)
    nose.tools.assert_equal(32, r_len)


def test_orwc():
    four_files = angr.surveyors.Explorer(p, find=[0x400120]).run()
    path = four_files.found[0]
    state = path.state
    system = state.get_plugin('posix')
    num_files = len(system.files)
    w_len = system.get_file(3).pos
    r_len = system.get_file(0).pos
    r_len = state.se.any_int(r_len)

    after_close = angr.surveyors.Explorer(p, find=[0x400124]).run()
    path = after_close.found[0]
    state = path.state
    system = state.get_plugin('posix')
    files_ac = len(system.files) #files after close...so we expect one less file :)

    nose.tools.assert_equal(4, num_files)
    nose.tools.assert_equal(3, files_ac)
    nose.tools.assert_equal(r_len, w_len)
    nose.tools.assert_equal(32, r_len)


if __name__ == '__main__':
    try:
        __import__('standard_logging')
        __import__('angr_debug')
    except ImportError:
        pass

    setup_module()
    test_rw()
    test_orwc()

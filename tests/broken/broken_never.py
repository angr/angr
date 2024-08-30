#!/usr/bin/env python
from __future__ import annotations

import nose
import logging

l = logging.getLogger("angr_tests")


import angr

# load the tests
import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
never_nolibs = None


def setup_module():
    global never_nolibs
    never_nolibs = angr.Project(os.path.join(test_location, "x86_64", "never"))


# def test_slicing():
# addresses = [ 0x40050C, 0x40050D, 0x400514, 0x40051B, 0x400521, 0x400534 ]
#    addresses = [ 0x40043C, 0x400440, 0x400447 ]
#    state = angr.SimState(memory_backer=never_nolibs.mem)
#    s = simuvex.SimSlice(state, addresses, never_nolibs.sim_run, mode='symbolic')
#
# TODO: test stuff
#    return s


def test_static():
    # make sure we have two blocks from main
    s = never_nolibs.path_generator.blank_path(address=0x40050C, mode="static")
    nose.tools.assert_equal(len(s.successors), 2)
    num_reachable = sum(x.reachable for x in s.successors)
    nose.tools.assert_equal(num_reachable, 2)
    # nose.tools.assert_equal(len(s.exits(reachable=True)), 2)
    # nose.tools.assert_equal(len(s.refs()[simuvex.SimCodeRef]), 2)
    ## TODO: make these actually have stuff

    ## now that the stack is initialized, these have lots of entries
    # nose.tools.assert_equal(len(s.refs()[simuvex.SimMemRead]), 1)
    # nose.tools.assert_equal(len(s.refs()[simuvex.SimMemWrite]), 2)
    # nose.tools.assert_equal(len(s.refs()[simuvex.SimMemRef]), 15)

    ## now try with a blank state
    # s = never_nolibs.sim_run(never_nolibs.path_generator.blank_path(address=0x40050C, mode='static'))
    # nose.tools.assert_equal(len(s.refs()[simuvex.SimMemRead]), 1)
    # nose.tools.assert_equal(len(s.refs()[simuvex.SimMemWrite]), 2)
    # nose.tools.assert_equal(len(s.refs()[simuvex.SimMemRef]), 15)

    return s


def test_concrete_exits1():
    # make sure we have two blocks from main
    s_main = never_nolibs.path_generator.blank_path(address=0x40050C, mode="concrete")
    nose.tools.assert_equal(s_main.successors, 2)
    num_reachable = sum(x.reachable for x in s_main.successors)
    nose.tools.assert_equal(num_reachable, 1)


def test_static_got_refs():
    s_printf_stub = never_nolibs.path_generator.blank_path(address=0x4003F0, mode="static")
    nose.tools.assert_equal(len(s_printf_stub.successors), 1)


# def test_refs():
#    s = never_nolibs.sim_run(never_nolibs.path_generator.blank_path(address=0x40050C, mode='concrete'))
#    nose.tools.assert_equal(len(s.refs()[simuvex.SimTmpWrite]), 38)
#    t0_ref = s.refs()[simuvex.SimTmpWrite][0]
#    nose.tools.assert_equal(len(t0_ref.data_reg_deps), 1)
#    nose.tools.assert_equal(t0_ref.data_reg_deps[0], 56)
#    t1_ref = s.refs()[simuvex.SimTmpWrite][3]
#    nose.tools.assert_equal(len(t1_ref.data_reg_deps), 0)
#    nose.tools.assert_equal(len(t1_ref.data_tmp_deps), 1)
#    nose.tools.assert_equal(t1_ref.data_tmp_deps[0], 13)

if __name__ == "__main__":
    try:
        __import__("standard_logging")
        __import__("angr_debug")
    except ImportError:
        pass

    setup_module()
    test_static()
    test_static_got_refs()
    test_concrete_exits1()

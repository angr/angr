#!/usr/bin/env python
from __future__ import annotations

import logging

l = logging.getLogger("angr_tests")

import nose
import angr

# load the tests
import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
switch_nolibs = None


def setup_module():
    global switch_nolibs
    switch_nolibs = angr.Project(os.path.join(test_location, "x86_64", "switch"), default_analysis_mode="symbolic")


def test_switch():
    s = switch_nolibs.path_generator.blank_path(address=0x400566)
    s_switch = switch_nolibs.sim_run(
        switch_nolibs.path_generator.blank_path(address=0x400573, state=s.conditional_exits[0])
    )
    nose.tools.assert_equals(len(s_switch.exits()[0].split(100)), 40)

    new_state = switch_nolibs.initial_state()
    # new_state.registers.store(16, 1)
    new_switch = s_switch.reanalyze(new_state=new_state)
    nose.tools.assert_equals(len(new_switch.exits()[0].split(100)), 1)


if __name__ == "__main__":
    try:
        __import__("standard_logging")
        __import__("angr_debug")
    except ImportError:
        pass

    setup_module()
    test_switch()

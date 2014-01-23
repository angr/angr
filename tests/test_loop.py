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
test_location = os.path.dirname(os.path.realpath(__file__))
loop_nolibs = None

def setup_module():
	global loop_nolibs
	loop_nolibs = angr.Project(test_location + "/loop/loop", load_libs=False, default_analysis_mode='symbolic')

def test_loop_entry():
	s = loop_nolibs.sim_run(0x4004f4)
	s_loop = loop_nolibs.sim_run(0x40051A, state=s.state)
	nose.tools.assert_equals(len(s_loop.exits()), 2)
	nose.tools.assert_true(s_loop.exits()[0].reachable()) # True
	nose.tools.assert_false(s_loop.exits()[1].reachable()) # False

def test_loop_escape():
	loop_addrs = [ 0x40051A, 0x400512 ]
	s = loop_nolibs.sim_run(0x4004F4)
	results = loop_nolibs.escape_loop(s.exits()[0], loop_addrs, max_iterations=4)
	nose.tools.assert_equal(results['unconstrained'][0].concretize(), 0x400520)

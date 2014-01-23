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
test_location = os.path.dirname(os.path.realpath(__file__))
never_nolibs = None

def setup_module():
	global never_nolibs
	never_nolibs = angr.Project(test_location + "/never/never", load_libs=False)

def test_slicing():
	#addresses = [ 0x40050C, 0x40050D, 0x400514, 0x40051B, 0x400521, 0x400534 ]
	addresses = [ 0x40043C, 0x400440, 0x400447 ]
	state = simuvex.SimState(memory_backer=never_nolibs.mem)
	s = simuvex.SimSlice(state, addresses, mode='symbolic')

	# TODO: test stuff
	return s

def test_static():
	# make sure we have two blocks from main
	s = never_nolibs.sim_run(0x40050C, mode='static')
	nose.tools.assert_equal(len(s.exits()), 2)
	nose.tools.assert_equal(len(s.refs()[simuvex.SimCodeRef]), 2)
	# TODO: make these actually have stuff

	# now that the stack is initialized, these have lots of entries
	nose.tools.assert_equal(len(s.refs()[simuvex.SimMemRead]), 1)
	nose.tools.assert_equal(len(s.refs()[simuvex.SimMemWrite]), 2)
	nose.tools.assert_equal(len(s.refs()[simuvex.SimMemRef]), 14)

	# now try with a blank state
	s = never_nolibs.sim_run(0x40050C, mode='static', state=simuvex.SimState(memory_backer=never_nolibs.mem))
	nose.tools.assert_equal(len(s.refs()[simuvex.SimMemRead]), 0)
	nose.tools.assert_equal(len(s.refs()[simuvex.SimMemWrite]), 0)
	nose.tools.assert_equal(len(s.refs()[simuvex.SimMemRef]), 2)

	return s

def test_concrete_exits1():
	# make sure we have two blocks from main
	s_main = never_nolibs.sim_run(0x40050C, mode='concrete')
	nose.tools.assert_equal(len(s_main.exits()), 1)
	return s_main

def test_static_got_refs():
	s_printf_stub = never_nolibs.sim_run(0x4003F0, mode="static")
	nose.tools.assert_equal(len(s_printf_stub.exits()), 1)
	return s_printf_stub

def test_p_refs():
	never_nolibs.make_refs()
	nose.tools.assert_equal(never_nolibs.code_refs_from[0x4003F0][0], 0x601038)
	nose.tools.assert_equal(never_nolibs.code_refs_to[0x4003F0][0], 0x400505)

	# TODO: more

def test_refs():
	s = never_nolibs.sim_run(0x40050C, mode='concrete')
	nose.tools.assert_equal(len(s.refs()[simuvex.SimTmpWrite]), 38)
	t0_ref = s.refs()[simuvex.SimTmpWrite][0]
	nose.tools.assert_equal(len(t0_ref.data_reg_deps), 1)
	nose.tools.assert_equal(t0_ref.data_reg_deps[0], 56)
	t1_ref = s.refs()[simuvex.SimTmpWrite][3]
	nose.tools.assert_equal(len(t1_ref.data_reg_deps), 0)
	nose.tools.assert_equal(len(t1_ref.data_tmp_deps), 1)
	nose.tools.assert_equal(t1_ref.data_tmp_deps[0], 13)

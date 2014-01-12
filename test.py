#!/usr/bin/env python

import unittest
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
test_location = os.path.dirname(os.path.realpath(__file__)) + "/tests/"
never_nolibs = angr.Project(test_location + "/never/never", load_libs=False)
loop_nolibs = angr.Project(test_location + "/loop/loop", load_libs=False)
switch_nolibs = angr.Project(test_location + "/switch/switch", load_libs=False)

# pylint: disable=R0904
class AngrTest(unittest.TestCase):
	def __init__(self, *args):
		self.p = never_nolibs
		self.loop_nolibs = loop_nolibs
		self.switch_nolibs = switch_nolibs
		super(AngrTest, self).__init__(*args)

	def test_slicing(self):
		#addresses = [ 0x40050C, 0x40050D, 0x400514, 0x40051B, 0x400521, 0x400534 ]
		addresses = [ 0x40043C, 0x400440, 0x400447 ]
		state = simuvex.SimState(memory_backer=self.p.mem)
		s = simuvex.SimSlice(state, addresses, mode='symbolic')

		# TODO: test stuff
		return s
	
	def test_static(self):
		# make sure we have two blocks from main
		s = self.p.sim_run(0x40050C, mode='static')
		self.assertEqual(len(s.exits()), 2)
		self.assertEqual(len(s.refs()[simuvex.SimCodeRef]), 2)
		# TODO: make these actually have stuff

		# now that the stack is initialized, these have lots of entries
		self.assertEqual(len(s.refs()[simuvex.SimMemRead]), 1)
		self.assertEqual(len(s.refs()[simuvex.SimMemWrite]), 2)
		self.assertEqual(len(s.refs()[simuvex.SimMemRef]), 14)

		# now try with a blank state
		s = self.p.sim_run(0x40050C, mode='static', state=simuvex.SimState(memory_backer=self.p.mem))
		self.assertEqual(len(s.refs()[simuvex.SimMemRead]), 0)
		self.assertEqual(len(s.refs()[simuvex.SimMemWrite]), 0)
		self.assertEqual(len(s.refs()[simuvex.SimMemRef]), 2)
	
		return s
	
	def test_concrete_exits1(self):
		# make sure we have two blocks from main
		s_main = self.p.sim_run(0x40050C, mode='concrete')
		self.assertEqual(len(s_main.exits()), 1)
		return s_main

	def test_static_got_refs(self):
		s_printf_stub = self.p.sim_run(0x4003F0, mode="static")
		self.assertEqual(len(s_printf_stub.exits()), 1)
		return s_printf_stub

	def test_p_refs(self):
		self.p.make_refs()
		self.assertEqual(self.p.code_refs_from[0x4003F0][0], 0x601038)
		self.assertEqual(self.p.code_refs_to[0x4003F0][0], 0x400505)

		# TODO: more

	def test_refs(self):
		s = self.p.sim_run(0x40050C, mode='concrete')
		self.assertEqual(len(s.refs()[simuvex.SimTmpWrite]), 38)
		t0_ref = s.refs()[simuvex.SimTmpWrite][0]
		self.assertEqual(len(t0_ref.data_reg_deps), 1)
		self.assertEqual(t0_ref.data_reg_deps[0], 56)
		t1_ref = s.refs()[simuvex.SimTmpWrite][3]
		self.assertEqual(len(t1_ref.data_reg_deps), 0)
		self.assertEqual(len(t1_ref.data_tmp_deps), 1)
		self.assertEqual(t1_ref.data_tmp_deps[0], 13)

	def test_loop_entry(self):
		s = self.loop_nolibs.sim_run(0x4004f4)
		s_loop = loop_nolibs.sim_run(0x40051A, state=s.state)
		self.assertEquals(len(s_loop.exits()), 2)
		self.assertTrue(s_loop.exits()[0].reachable()) # True
		self.assertFalse(s_loop.exits()[1].reachable()) # False

	def test_switch(self):
		s = self.switch_nolibs.sim_run(0x400566)
		s_switch = self.switch_nolibs.sim_run(0x400573, state=s.conditional_exits[0].state)
		self.assertEquals(len(s_switch.exits()[0].concretize_n(100)), 40)

if __name__ == '__main__':
	unittest.main()

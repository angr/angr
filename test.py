#!/usr/bin/env python

import unittest
import logging
l = logging.getLogger("angr_tests")

try:
	# pylint: disable=W0611
	import standard_logging
	import angr_debug
except ImportError:
	pass

import angr
import simuvex

never_nolibs = angr.Project("test/never/never", load_libs=False)

# pylint: disable=R0904
class AngrTestNever(unittest.TestCase):
	def __init__(self, *args):
		self.p = never_nolibs
		super(AngrTestNever, self).__init__(*args)

	def test_slicing(self):
		#addresses = [ 0x40050C, 0x40050D, 0x400514, 0x40051B, 0x400521, 0x400534 ]
		addresses = [ 0x40043C, 0x400440, 0x400447 ]
		state = simuvex.SimState(memory_backer=self.p.mem)
		s = simuvex.SimSlice(state, addresses, mode='symbolic')

		# TODO: test stuff
		return s
	
	def test_static(self):
		# make sure we have two blocks from main
		s = self.p.sim_block(0x40050C, mode='static')
		self.assertEqual(len(s.exits()), 2)
		self.assertEqual(len(s.refs[simuvex.SimCodeRef]), 2)
		# TODO: make these actually have stuff
		self.assertEqual(len(s.refs[simuvex.SimMemRead]), 0)
		self.assertEqual(len(s.refs[simuvex.SimMemWrite]), 0)
		self.assertEqual(len(s.refs[simuvex.SimMemRef]), 2)
	
		return s
	
	def test_concrete_exits1(self):
		# make sure we have two blocks from main
		s_main = self.p.sim_block(0x40050C, mode='concrete')
		self.assertEqual(len(s_main.exits()), 1)
		return s_main

	def test_static_got_refs(self):
		s_printf_stub = self.p.sim_block(0x4003F0, mode="static")
		self.assertEqual(len(s_printf_stub.exits()), 1)
		return s_printf_stub

	def test_refs(self):
		self.p.make_refs()
		self.assertEqual(self.p.code_refs_from[0x4003F0][0], 0x601038)
		self.assertEqual(self.p.code_refs_to[0x4003F0][0], 0x400505)

		# TODO: more

if __name__ == '__main__':
	unittest.main()

#!/usr/bin/env python

import unittest
import logging
l = logging.getLogger("angr_tests")

try:
	# pylint: disable=W0611
	import standard_logging
except ImportError:
	pass

import symexec
from .s_memory import SimMemory, Vectorizer
from .s_value import SimValue, ConcretizingException

# pylint: disable=R0904
class SimuTEST(unittest.TestCase):
	def test_memory(self):
		initial_memory = { 0: 'A', 1: 'A', 2: 'A', 3: 'A', 10: 'B' }
		vectorized_memory = Vectorizer(initial_memory)
		mem = SimMemory(backer=vectorized_memory)

		# concrete address and concrete result
		addr = SimValue(symexec.BitVecVal(0, 64))
		loaded,_ = mem.load(addr, 32) # Returns: a z3 BitVec representing 0x41414141
		loaded_val = mem.load_val(addr, 32) # Returns: a z3 BitVec representing 0x41414141
		self.assertFalse(loaded_val.is_symbolic())
		self.assertEquals(loaded, loaded_val.expr)
		self.assertEquals(loaded_val.any(), 0x41414141)

		# concrete address and partially symbolic result
		addr = SimValue(symexec.BitVecVal(2, 64))
		loaded_val = mem.load_val(addr, 32)
		self.assertTrue(loaded_val.is_symbolic())
		self.assertGreaterEqual(loaded_val.any(), 0x41410000)
		self.assertLessEqual(loaded_val.any(), 0x41420000)
		self.assertEqual(loaded_val.min(), 0x41410000)
		self.assertEqual(loaded_val.max(), 0x4141ffff)

		# symbolic (but fixed) address and concrete result
		x = symexec.BitVec('x', 64)
		addr = SimValue(x, [ x == 10 ])
		loaded_val = mem.load_val(addr, 8)
		self.assertFalse(loaded_val.is_symbolic())
		self.assertEqual(loaded_val.any(), 0x42)

	def test_symvalue(self):
		# concrete symvalue
		zero = SimValue(symexec.BitVecVal(0, 64))
		self.assertFalse(zero.is_symbolic())
		self.assertEqual(zero.any(), 0)
		self.assertRaises(ConcretizingException, zero.exactly_n, 2)

		# symbolic symvalue
		x = symexec.BitVec('x', 64)
		sym = SimValue(x, [ x > 100, x < 200 ])
		self.assertTrue(sym.is_symbolic())
		self.assertEqual(sym.min(), 101)
		self.assertEqual(sym.max(), 199)
		self.assertItemsEqual(sym.any_n(99), range(101, 200))
		self.assertRaises(ConcretizingException, zero.exactly_n, 102)

if __name__ == '__main__':
	unittest.main()

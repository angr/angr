import pyvex
import unittest

class PyVEXTest(unittest.TestCase):
	def setUp(self):
		pass

	def test_irsb_empty(self):
		irsb = pyvex.IRSB()
		stmts = irsb.statements()
		self.assertEqual(len(stmts), 0)

	def test_empty_irstmt_fail(self):
		self.assertRaises(pyvex.VexException, pyvex.IRStmt, ())

	def test_irsb_popret(self):
		irsb = pyvex.IRSB(bytes='\x5d\xc3')
		stmts = irsb.statements()
		irsb.pp()

		self.assertGreater(len(stmts), 0)

	def test_irsb_deepCopy(self):
		irsb = pyvex.IRSB(bytes='\x5d\xc3')
		stmts = irsb.statements()

		irsb2 = irsb.deepCopy()
		stmts2 = irsb2.statements()
		self.assertEqual(len(stmts), len(stmts2))

	def test_irstmt_pp(self):
		irsb = pyvex.IRSB(bytes='\x5d\xc3')
		stmts = irsb.statements()
		for i in stmts:
			print "STMT: ",
			i.pp()
			print

	def test_irsb_addStmt(self):
		irsb = pyvex.IRSB(bytes='\x5d\xc3')
		stmts = irsb.statements()

		irsb2 = irsb.deepCopyExceptStmts()
		self.assertEqual(len(irsb2.statements()), 0)

		for n, i in enumerate(stmts):
			self.assertEqual(len(irsb2.statements()), n)
			irsb2.addStatement(i.deepCopy())

		irsb2.pp()

	def test_irstmt_flat(self):
		print "TODO"

	def test_irsb_tyenv(self):
		irsb = pyvex.IRSB(bytes='\x5d\xc3')
		print irsb.tyenv
		print "Orig"
		irsb.tyenv.pp()
		print "Copy"
		irsb.tyenv.deepCopy().pp()

		print "Empty"
		irsb2 = pyvex.IRSB()
		irsb2.tyenv.pp()

		print "Unwrapped"
		irsb2.tyenv = irsb.tyenv.deepCopy()
		irsb2.tyenv.pp()

	def test_irstmt_noop(self):
		irsb = pyvex.IRSB(bytes='\x90\x5d\xc3')
		irnop = irsb.statements()[0]
		irnop2 = pyvex.IRStmtNoOp()
		irnop3 = irnop2.deepCopy()

		self.assertEqual(irnop.tag, "Ist_NoOp")
		self.assertEqual(type(irnop), type(irnop2))
		self.assertEqual(type(irnop), type(irnop3))
		
	def test_irstmt_imark(self):
		m = pyvex.IRStmtIMark(1,2,3)
		self.assertEqual(m.tag, "Ist_IMark")
		self.assertEqual(m.addr, 1)
		self.assertEqual(m.len, 2)
		self.assertEqual(m.delta, 3)

		m.addr = 5
		self.assertEqual(m.addr, 5)
		m.len = 5
		self.assertEqual(m.len, 5)
		m.delta = 5
		self.assertEqual(m.delta, 5)

		self.assertRaises(Exception, pyvex.IRStmtIMark, ())

	def test_irexpr_rdtmp(self):
		irsb = pyvex.IRSB(bytes='\x90\x5d\xc3')
		self.assertEqual(irsb.next.tmp, irsb.next.deepCopy().tmp)

		m = pyvex.IRExprRdTmp(123)
		self.assertEqual(m.tag, "Iex_RdTmp")
		self.assertEqual(m.tmp, m.deepCopy().tmp)
		self.assertEqual(m.tmp, 123)

		m.tmp = 1337
		self.assertEqual(m.tmp, 1337)
		self.assertRaises(Exception, pyvex.IRExprRdTmp, ())

	def test_irstmt_abihint(self):
		self.assertRaises(Exception, pyvex.IRStmtAbiHint, ())

		a = pyvex.IRExprRdTmp(123)
		b = pyvex.IRExprRdTmp(456)

		m = pyvex.IRStmtAbiHint(a, 10, b)
		self.assertEqual(m.base.tmp, 123)
		self.assertEqual(m.len, 10)
		self.assertEqual(m.nia.tmp, 456)

	def test_irstmt_put(self):
		self.assertRaises(Exception, pyvex.IRStmtPut, ())

		a = pyvex.IRExprRdTmp(123)
		m = pyvex.IRStmtPut(10, a)
		print "Put stmt:",
		m.pp()
		print ""
		self.assertEqual(m.data.tmp, 123)
		self.assertEqual(m.offset, 10)

	def test_irstmt_wrtmp(self):
		self.assertRaises(Exception, pyvex.IRStmtWrTmp, ())

		a = pyvex.IRExprRdTmp(123)
		m = pyvex.IRStmtWrTmp(10, a)
		self.assertEqual(m.tmp, 10)
		self.assertEqual(m.data.tmp, 123)

if __name__ == '__main__':
	unittest.main()

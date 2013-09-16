import pyvex
import unittest

class TestSequenceFunctions(unittest.TestCase):
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

if __name__ == '__main__':
	unittest.main()

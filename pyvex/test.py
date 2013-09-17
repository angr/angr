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
		self.assertEqual(type(m), type(m.deepCopy()))

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
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_abihint(self):
		self.assertRaises(Exception, pyvex.IRStmtAbiHint, ())

		a = pyvex.IRExprRdTmp(123)
		b = pyvex.IRExprRdTmp(456)

		m = pyvex.IRStmtAbiHint(a, 10, b)
		self.assertEqual(m.base.tmp, 123)
		self.assertEqual(m.len, 10)
		self.assertEqual(m.nia.tmp, 456)
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_put(self):
		self.assertRaises(Exception, pyvex.IRStmtPut, ())

		a = pyvex.IRExprRdTmp(123)
		m = pyvex.IRStmtPut(10, a)
		print "Put stmt:",
		m.pp()
		print ""
		self.assertEqual(m.data.tmp, 123)
		self.assertEqual(m.offset, 10)
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_wrtmp(self):
		self.assertRaises(Exception, pyvex.IRStmtWrTmp, ())

		a = pyvex.IRExprRdTmp(123)
		m = pyvex.IRStmtWrTmp(10, a)
		self.assertEqual(m.tag, "Ist_WrTmp")
		self.assertEqual(m.tmp, 10)
		self.assertEqual(m.data.tmp, 123)
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_store(self):
		self.assertRaises(Exception, pyvex.IRStmtStore, ())

		a = pyvex.IRExprRdTmp(123)
		d = pyvex.IRExprRdTmp(456)
		m = pyvex.IRStmtStore("Iend_LE", a, d)
		self.assertEqual(m.tag, "Ist_Store")
		self.assertEqual(m.endness, "Iend_LE")
		self.assertEqual(m.addr.tmp, a.tmp)
		self.assertEqual(m.data.tmp, d.tmp)

		m.endness = "Iend_BE"
		self.assertEqual(m.endness, "Iend_BE")
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_cas(self):
		self.assertRaises(Exception, pyvex.IRStmtCAS, ())

		a = pyvex.IRExprRdTmp(10)
		eh = pyvex.IRExprRdTmp(11)
		el = pyvex.IRExprRdTmp(12)
		dh = pyvex.IRExprRdTmp(21)
		dl = pyvex.IRExprRdTmp(22)

		args = { "oldHi": 1, "oldLo": 2, "endness": "Iend_LE", "addr": a,
	                 "expdHi": eh, "expdLo": el, "dataHi": dh, "dataLo": dl }

		m = pyvex.IRStmtCAS(**args)
		self.assertEqual(m.tag, "Ist_CAS")
		self.assertEqual(m.endness, "Iend_LE")
		self.assertEqual(m.oldHi, 1)
		self.assertEqual(m.oldLo, 2)
		self.assertEqual(m.addr.tmp, a.tmp)
		self.assertEqual(m.expdHi.tmp, eh.tmp)
		self.assertEqual(m.expdLo.tmp, el.tmp)
		self.assertEqual(m.dataHi.tmp, dh.tmp)
		self.assertEqual(m.dataLo.tmp, dl.tmp)

		m.endness = "Iend_BE"
		self.assertEqual(m.endness, "Iend_BE")
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_llsc(self):
		self.assertRaises(Exception, pyvex.IRStmtLLSC, ())

		a = pyvex.IRExprRdTmp(123)
		d = pyvex.IRExprRdTmp(456)
		m = pyvex.IRStmtLLSC("Iend_LE", 1, a, d)
		self.assertEqual(m.tag, "Ist_LLSC")
		self.assertEqual(m.endness, "Iend_LE")
		self.assertEqual(m.result, 1)
		self.assertEqual(m.addr.tmp, a.tmp)
		self.assertEqual(m.storedata.tmp, d.tmp)

		m.endness = "Iend_BE"
		self.assertEqual(m.endness, "Iend_BE")
		self.assertEqual(type(m), type(m.deepCopy()))

	def helper_const_subtype(self, subtype, tag, value):
		print "Testing %s" % tag
		self.assertRaises(Exception, subtype, ())

		c = subtype(value)
		self.assertEquals(c.tag, tag)
		self.assertEquals(c.value, value)

		d = subtype(value - 1)
		e = subtype(value)
		self.assertTrue(c.equals(e))
		self.assertTrue(e.equals(c))
		self.assertFalse(c.equals(d))
		self.assertFalse(d.equals(c))
		self.assertFalse(c.equals("test"))

	def test_irconst(self):
		self.helper_const_subtype(pyvex.IRConstU1, "Ico_U1", 1)
		self.helper_const_subtype(pyvex.IRConstU8, "Ico_U8", 233)
		self.helper_const_subtype(pyvex.IRConstU16, "Ico_U16", 39852)
		self.helper_const_subtype(pyvex.IRConstU32, "Ico_U32", 3442312356)
		self.helper_const_subtype(pyvex.IRConstU64, "Ico_U64", 823452334523623455)
		self.helper_const_subtype(pyvex.IRConstF32, "Ico_F32", 13453.234375)
		self.helper_const_subtype(pyvex.IRConstF32i, "Ico_F32i", 3442312356)
		self.helper_const_subtype(pyvex.IRConstF64, "Ico_F64", 13453.234525)
		self.helper_const_subtype(pyvex.IRConstF64i, "Ico_F64i", 823457234523623455)
		self.helper_const_subtype(pyvex.IRConstV128, "Ico_V128", 39852)
		self.helper_const_subtype(pyvex.IRConstV256, "Ico_V256", 3442312356)

if __name__ == '__main__':
	unittest.main()

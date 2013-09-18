import pyvex
import unittest

class PyVEXTest(unittest.TestCase):
	def setUp(self):
		pass

	################
	### IRCallee ###
	################

	def test_ircallee(self):
		callee = pyvex.IRCallee(3, "test_name", 1234, 0xFFFFFF)
		self.assertEquals(callee.regparms, 3)
		self.assertEquals(callee.name, "test_name")
		self.assertEquals(callee.addr, 1234)
		self.assertEquals(callee.mcx_mask, 0xFFFFFF)

	############
	### IRSB ###
	############

	def test_irsb_empty(self):
		irsb = pyvex.IRSB()
		stmts = irsb.statements()
		self.assertEqual(len(stmts), 0)

	def test_irsb_popret(self):
		irsb = pyvex.IRSB(bytes='\x5d\xc3')
		stmts = irsb.statements()
		irsb.pp()

		self.assertGreater(len(stmts), 0)
		self.assertEqual(irsb.jumpkind, "Ijk_Ret")
		self.assertEqual(irsb.offsIP, 184)

		cursize = len(irsb.tyenv.types())
		self.assertGreater(cursize, 0)
		new_tmp = irsb.tyenv.newTemp("Ity_I32")
		self.assertEqual(cursize + 1, len(irsb.tyenv.types()))
		self.assertEqual(irsb.tyenv.typeOf(new_tmp), "Ity_I32")


	def test_irsb_deepCopy(self):
		irsb = pyvex.IRSB(bytes='\x5d\xc3')
		stmts = irsb.statements()

		irsb2 = irsb.deepCopy()
		stmts2 = irsb2.statements()
		self.assertEqual(len(stmts), len(stmts2))

	def test_irsb_addStmt(self):
		irsb = pyvex.IRSB(bytes='\x5d\xc3')
		stmts = irsb.statements()

		irsb2 = irsb.deepCopyExceptStmts()
		self.assertEqual(len(irsb2.statements()), 0)

		for n, i in enumerate(stmts):
			self.assertEqual(len(irsb2.statements()), n)
			irsb2.addStatement(i.deepCopy())

		irsb2.pp()

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

	##################
	### Statements ###
	##################

	def test_empty_irstmt_fail(self):
		self.assertRaises(pyvex.VexException, pyvex.IRStmt, ())

	def test_irstmt_pp(self):
		irsb = pyvex.IRSB(bytes='\x5d\xc3')
		stmts = irsb.statements()
		for i in stmts:
			print "STMT: ",
			i.pp()
			print

	def test_irstmt_flat(self):
		print "TODO"

	def test_irstmt_noop(self):
		irsb = pyvex.IRSB(bytes='\x90\x5d\xc3')
		irnop = irsb.statements()[0]
		irnop2 = pyvex.IRStmt.NoOp()
		irnop3 = irnop2.deepCopy()

		self.assertEqual(irnop.tag, "Ist_NoOp")
		self.assertEqual(type(irnop), type(irnop2))
		self.assertEqual(type(irnop), type(irnop3))
		
	def test_irstmt_imark(self):
		m = pyvex.IRStmt.IMark(1,2,3)
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

		self.assertRaises(Exception, pyvex.IRStmt.IMark, ())
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_abihint(self):
		self.assertRaises(Exception, pyvex.IRStmt.AbiHint, ())

		a = pyvex.IRExpr.RdTmp(123)
		b = pyvex.IRExpr.RdTmp(456)

		m = pyvex.IRStmt.AbiHint(a, 10, b)
		self.assertEqual(m.base.tmp, 123)
		self.assertEqual(m.len, 10)
		self.assertEqual(m.nia.tmp, 456)
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_put(self):
		self.assertRaises(Exception, pyvex.IRStmt.Put, ())

		a = pyvex.IRExpr.RdTmp(123)
		m = pyvex.IRStmt.Put(10, a)
		print "Put stmt:",
		m.pp()
		print ""
		self.assertEqual(m.data.tmp, 123)
		self.assertEqual(m.offset, 10)
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irexpr_puti(self):
		r = pyvex.IRRegArray(10, "Ity_I64", 20)
		i = pyvex.IRExpr.RdTmp(5)
		d = pyvex.IRExpr.RdTmp(30)
		m = pyvex.IRStmt.PutI(r, i, 2, d)
		self.assertEqual(m.deepCopy().description.base, 10)
		self.assertEqual(m.index.tmp, 5)
		self.assertEqual(m.bias, 2)
		self.assertEqual(m.deepCopy().data.deepCopy().tmp, d.tmp)

		self.assertRaises(Exception, pyvex.IRStmt.PutI, ())

	def test_irstmt_wrtmp(self):
		self.assertRaises(Exception, pyvex.IRStmt.WrTmp, ())

		a = pyvex.IRExpr.RdTmp(123)
		m = pyvex.IRStmt.WrTmp(10, a)
		self.assertEqual(m.tag, "Ist_WrTmp")
		self.assertEqual(m.tmp, 10)
		self.assertEqual(m.data.tmp, 123)
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_store(self):
		self.assertRaises(Exception, pyvex.IRStmt.Store, ())

		a = pyvex.IRExpr.RdTmp(123)
		d = pyvex.IRExpr.RdTmp(456)
		m = pyvex.IRStmt.Store("Iend_LE", a, d)
		self.assertEqual(m.tag, "Ist_Store")
		self.assertEqual(m.endness, "Iend_LE")
		self.assertEqual(m.addr.tmp, a.tmp)
		self.assertEqual(m.data.tmp, d.tmp)

		m.endness = "Iend_BE"
		self.assertEqual(m.endness, "Iend_BE")
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_cas(self):
		self.assertRaises(Exception, pyvex.IRStmt.CAS, ())

		a = pyvex.IRExpr.RdTmp(10)
		eh = pyvex.IRExpr.RdTmp(11)
		el = pyvex.IRExpr.RdTmp(12)
		dh = pyvex.IRExpr.RdTmp(21)
		dl = pyvex.IRExpr.RdTmp(22)

		args = { "oldHi": 1, "oldLo": 2, "endness": "Iend_LE", "addr": a,
	                 "expdHi": eh, "expdLo": el, "dataHi": dh, "dataLo": dl }

		m = pyvex.IRStmt.CAS(**args)
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
		self.assertRaises(Exception, pyvex.IRStmt.LLSC, ())

		a = pyvex.IRExpr.RdTmp(123)
		d = pyvex.IRExpr.RdTmp(456)
		m = pyvex.IRStmt.LLSC("Iend_LE", 1, a, d)
		self.assertEqual(m.tag, "Ist_LLSC")
		self.assertEqual(m.endness, "Iend_LE")
		self.assertEqual(m.result, 1)
		self.assertEqual(m.addr.tmp, a.tmp)
		self.assertEqual(m.storedata.tmp, d.tmp)

		m.endness = "Iend_BE"
		self.assertEqual(m.endness, "Iend_BE")
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irstmt_mbe(self):
		m = pyvex.IRStmt.MBE("Imbe_CancelReservation")
		self.assertEqual(m.deepCopy().event, "Imbe_CancelReservation")
		m.event = "Imbe_Fence"
		self.assertEqual(m.event, "Imbe_Fence")

	def test_irstmt_dirty(self):
		args = [ pyvex.IRExpr.RdTmp(i) for i in range(10) ]
		m = pyvex.IRStmt.Dirty(3, "test_dirty", 1234, args, tmp=15)
		self.assertEqual(m.cee.name, "test_dirty")
		self.assertEquals(type(m.guard), pyvex.IRExpr.Const)
		self.assertEquals(m.tmp, 15)
		self.assertEquals(m.mFx, "Ifx_None")
		self.assertEquals(m.needsBBP, 0)
		self.assertEquals(m.nFxState, 0)

		for n,a in enumerate(m.args()):
			self.assertEquals(a.tmp, args[n].tmp)

		self.assertEquals(len(m.fxState()), 0)

	def test_irstmt_exit(self):
		self.assertRaises(Exception, pyvex.IRStmt.Exit, ())

		g = pyvex.IRExpr.RdTmp(123)
		d = pyvex.IRConst.U32(456)

		m = pyvex.IRStmt.Exit(g, "Ijk_Ret", d, 10)
		self.assertEqual(m.tag, "Ist_Exit")
		self.assertEqual(m.jumpkind, "Ijk_Ret")
		self.assertEqual(m.offsIP, 10)
		self.assertEqual(m.guard.tmp, g.tmp)
		self.assertEqual(m.dst.value, d.value)

		m.jumpkind = "Ijk_SigSEGV"
		self.assertEqual(m.jumpkind, "Ijk_SigSEGV")
		self.assertEqual(type(m), type(m.deepCopy()))

	##################
	### IRRegArray ###
	##################

	def test_irregarray(self):
		m = pyvex.IRRegArray(10, "Ity_I64", 20)
		n = pyvex.IRRegArray(20, "Ity_I32", 30)
		self.assertTrue(m.equals(m))
		self.assertFalse(m.equals(n))
		self.assertFalse(n.equals(m))

		self.assertEquals(m.num_elements, 20)
		self.assertEquals(m.element_type, "Ity_I64")
		self.assertEquals(m.base, 10)

	################
	### IRConst.s ###
	################

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
		self.helper_const_subtype(pyvex.IRConst.U1, "Ico_U1", 1)
		self.helper_const_subtype(pyvex.IRConst.U8, "Ico_U8", 233)
		self.helper_const_subtype(pyvex.IRConst.U16, "Ico_U16", 39852)
		self.helper_const_subtype(pyvex.IRConst.U32, "Ico_U32", 3442312356)
		self.helper_const_subtype(pyvex.IRConst.U64, "Ico_U64", 823452334523623455)
		self.helper_const_subtype(pyvex.IRConst.F32, "Ico_F32", 13453.234375)
		self.helper_const_subtype(pyvex.IRConst.F32i, "Ico_F32i", 3442312356)
		self.helper_const_subtype(pyvex.IRConst.F64, "Ico_F64", 13453.234525)
		self.helper_const_subtype(pyvex.IRConst.F64i, "Ico_F64i", 823457234523623455)
		self.helper_const_subtype(pyvex.IRConst.V128, "Ico_V128", 39852)
		self.helper_const_subtype(pyvex.IRConst.V256, "Ico_V256", 3442312356)

	###################
	### Expressions ###
	###################

	def test_irexpr_binder(self):
		m = pyvex.IRExpr.Binder(1534252)
		self.assertEqual(m.binder, 1534252)
		self.assertRaises(Exception, m.deepCopy, ())

	def test_irexpr_geti(self):
		r = pyvex.IRRegArray(10, "Ity_I64", 20)
		i = pyvex.IRExpr.RdTmp(5)
		m = pyvex.IRExpr.GetI(r, i, 2)
		self.assertEqual(m.deepCopy().description.base, 10)
		self.assertEqual(m.index.tmp, 5)
		self.assertEqual(m.bias, 2)

		self.assertRaises(Exception, pyvex.IRExpr.GetI, ())

	def test_irexpr_rdtmp(self):
		irsb = pyvex.IRSB(bytes='\x90\x5d\xc3')
		self.assertEqual(irsb.next.tmp, irsb.next.deepCopy().tmp)

		m = pyvex.IRExpr.RdTmp(123)
		self.assertEqual(m.tag, "Iex_RdTmp")
		self.assertEqual(m.tmp, m.deepCopy().tmp)
		self.assertEqual(m.tmp, 123)

		m.tmp = 1337
		self.assertEqual(m.tmp, 1337)
		self.assertRaises(Exception, pyvex.IRExpr.RdTmp, ())
		self.assertEqual(type(m), type(m.deepCopy()))

	def test_irexpr_get(self):
		m = pyvex.IRExpr.Get(0, "Ity_I64")
		self.assertEqual(m.type, "Ity_I64")
		self.assertEqual(m.type, m.deepCopy().type)
		self.assertEqual(type(m), type(m.deepCopy()))

		self.assertRaises(Exception, pyvex.IRExpr.Get, ())

	def test_irexpr_qop(self):
		a = pyvex.IRExpr.Get(0, "Ity_I64")
		b = pyvex.IRExpr.Get(184, "Ity_I64")
		c = pyvex.IRExpr.RdTmp(1)
		d = pyvex.IRExpr.RdTmp(2)
		op = "Iop_QAdd32S"

		m = pyvex.IRExpr.Qop(op, a, b, c, d)

		self.assertEqual(m.op, op)
		self.assertEqual(type(m), type(m.deepCopy()))
		self.assertEqual(m.arg1.type, m.deepCopy().arg1.type)
		self.assertEqual(m.arg2.type, b.type)

		self.assertEqual(len(m.args()), 4)
		self.assertEqual(m.args()[2].tmp, c.tmp)

	def test_irexpr_triop(self):
		a = pyvex.IRExpr.Get(0, "Ity_I64")
		b = pyvex.IRExpr.Get(184, "Ity_I64")
		c = pyvex.IRExpr.RdTmp(1)
		op = "Iop_MAddF64"

		m = pyvex.IRExpr.Triop(op, a, b, c)

		self.assertEqual(m.op, op)
		self.assertEqual(type(m), type(m.deepCopy()))
		self.assertEqual(m.arg1.type, m.deepCopy().arg1.type)
		self.assertEqual(m.arg2.type, b.type)

		self.assertEqual(len(m.args()), 3)
		self.assertEqual(m.args()[2].tmp, c.tmp)

	def test_irexpr_binop(self):
		a = pyvex.IRExpr.Get(0, "Ity_I64")
		c = pyvex.IRExpr.RdTmp(1)
		op = "Iop_Add64"

		m = pyvex.IRExpr.Binop(op, a, c)

		self.assertEqual(m.op, op)
		self.assertEqual(type(m), type(m.deepCopy()))
		self.assertEqual(m.arg1.type, m.deepCopy().arg1.type)
		self.assertEqual(m.arg2.tmp, c.tmp)

		self.assertEqual(len(m.args()), 2)
		self.assertEqual(m.args()[1].tmp, c.tmp)

	def test_irexpr_unop(self):
		a = pyvex.IRExpr.Get(0, "Ity_I64")
		op = "Iop_Add64"

		m = pyvex.IRExpr.Unop(op, a)

		self.assertEqual(m.op, op)
		self.assertEqual(type(m), type(m.deepCopy()))
		self.assertEqual(m.arg1.type, m.deepCopy().arg1.type)
		self.assertEqual(len(m.args()), 1)
		self.assertEqual(m.args()[0].offset, a.offset)

	def test_irexpr_load(self):
		a = pyvex.IRExpr.Get(0, "Ity_I64")
		e = "Iend_LE"
		t = "Ity_I64"

		m = pyvex.IRExpr.Load(e, t, a)

		self.assertEqual(m.endness, e)
		self.assertEqual(type(m), type(m.deepCopy()))
		self.assertEqual(m.addr.type, m.deepCopy().addr.type)
		self.assertEqual(m.type, t)

	def test_irexpr_const(self):
		u1 = pyvex.IRConst.U1(1)
		f64 = pyvex.IRConst.F64(1.123)

		ue = pyvex.IRExpr.Const(u1)
		fe = pyvex.IRExpr.Const(f64)

		self.assertEqual(ue.con.value, u1.value)
		self.assertNotEqual(ue.con.value, f64.value)
		self.assertEqual(type(ue), type(fe.deepCopy()))
		self.assertEqual(fe.con.value, fe.deepCopy().con.value)

	def test_irexpr_triop(self):
		a = pyvex.IRExpr.Get(0, "Ity_I64")
		b = pyvex.IRExpr.Const(pyvex.IRConst.U8(200))
		c = pyvex.IRExpr.RdTmp(1)

		m = pyvex.IRExpr.Mux0X(a, b, c)

		self.assertEqual(type(m), type(m.deepCopy()))
		self.assertEqual(m.cond.type, m.deepCopy().cond.type)
		self.assertEqual(m.expr0.con.value, b.con.value)
		self.assertEqual(m.exprX.tmp, m.deepCopy().exprX.tmp)

	def test_irexpr_ccall(self):
		callee = pyvex.IRCallee(3, "test_name", 1234, 0xFFFFFF)
		args = [ pyvex.IRExpr.RdTmp(i) for i in range(10) ]

		m = pyvex.IRExpr.CCall(callee, "Ity_I64", args)

		self.assertEqual(type(m), type(m.deepCopy()))
		self.assertEqual(len(m.args()), len(args))
		self.assertEqual(m.ret_type, "Ity_I64")
		self.assertEqual(m.callee.addr, 1234)
		self.assertEqual(m.deepCopy().callee.regparms, 3)

		for n,a in enumerate(m.args()):
			self.assertEquals(a.tmp, args[n].tmp)

		m = pyvex.IRExpr.CCall(callee, "Ity_I64", ())
		self.assertEquals(len(m.args()), 0)

if __name__ == '__main__':
	unittest.main()

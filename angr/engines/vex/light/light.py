from __future__ import annotations
import logging

import pyvex

from ...engine import SimEngineBase
from ....utils.constants import DEFAULT_STATEMENT

l = logging.getLogger(name=__name__)

# pylint:disable=arguments-differ,unused-argument,no-self-use


class VEXMixin(SimEngineBase):
    def __init__(self, project, **kwargs):
        super().__init__(project, **kwargs)
        self._vex_expr_handlers = []
        self._vex_stmt_handlers = []
        self.__init_handlers()

        self.irsb = None
        self.stmt_idx = None
        self.tmps = None

    __tls = ("irsb", "stmt_idx", "tmps")

    def __init_handlers(self):
        self._vex_expr_handlers = [None] * pyvex.expr.tag_count
        self._vex_stmt_handlers = [None] * pyvex.stmt.tag_count
        for name, cls in vars(pyvex.expr).items():
            if isinstance(cls, type) and issubclass(cls, pyvex.expr.IRExpr) and cls is not pyvex.expr.IRExpr:
                self._vex_expr_handlers[cls.tag_int] = getattr(self, "_handle_vex_expr_" + name)
        for name, cls in vars(pyvex.stmt).items():
            if isinstance(cls, type) and issubclass(cls, pyvex.stmt.IRStmt) and cls is not pyvex.stmt.IRStmt:
                self._vex_stmt_handlers[cls.tag_int] = getattr(self, "_handle_vex_stmt_" + name)
        assert None not in self._vex_expr_handlers
        assert None not in self._vex_stmt_handlers

    def __getstate__(self):
        return (super().__getstate__(),)  # return unary tuple to not trip special behavior with falsey states

    def __setstate__(self, s):
        self.__init_handlers()
        super().__setstate__(s[0])

    # one size fits all?
    def _ty_to_bytes(self, ty):
        return pyvex.get_type_size(ty) // getattr(getattr(getattr(self, "state", None), "arch", None), "byte_width", 8)

    def _handle_vex_stmt(self, stmt: pyvex.stmt.IRStmt):
        handler = self._vex_stmt_handlers[stmt.tag_int]
        handler(stmt)

    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr):
        handler = self._vex_expr_handlers[expr.tag_int]
        result = handler(expr)
        return self._instrument_vex_expr(result)

    def _instrument_vex_expr(self, result):
        return result

    def _handle_vex_const(self, const: pyvex.const.IRConst):
        return const.value

    #
    # Individual expression handlers go here
    #

    # expressions dependent on the state impl

    def _handle_vex_expr_RdTmp(self, expr: pyvex.expr.RdTmp):
        return self._perform_vex_expr_RdTmp(expr.tmp)

    def _perform_vex_expr_RdTmp(self, tmp):
        return self.tmps[tmp]

    def _handle_vex_expr_Get(self, expr: pyvex.expr.Get):
        return self._perform_vex_expr_Get(self._handle_vex_const(pyvex.const.U32(expr.offset)), expr.ty)

    def _perform_vex_expr_Get(self, offset, ty, **kwargs):
        return NotImplemented

    def _analyze_vex_expr_Load_addr(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_expr_Load(self, expr: pyvex.expr.Load):
        return self._perform_vex_expr_Load(self._analyze_vex_expr_Load_addr(expr.addr), expr.ty, expr.end)

    def _perform_vex_expr_Load(self, addr, ty, endness, **kwargs):
        return NotImplemented

    # expressions dependent on the data domain

    def _analyze_vex_expr_CCall_arg(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_expr_CCall(self, expr: pyvex.expr.CCall):
        return self._perform_vex_expr_CCall(
            expr.cee.name,
            expr.retty,
            [self._analyze_vex_expr_CCall_arg(arg) for arg in expr.args],
        )

    def _perform_vex_expr_CCall(self, func_name, ty, args, func=None):
        return NotImplemented

    def _handle_vex_expr_ITE(self, expr: pyvex.expr.ITE):
        return self._perform_vex_expr_ITE(
            self._handle_vex_expr(expr.cond), self._handle_vex_expr(expr.iftrue), self._handle_vex_expr(expr.iffalse)
        )

    def _perform_vex_expr_ITE(self, cond, ifTrue, ifFalse):
        return NotImplemented

    def _handle_vex_expr_Unop(self, expr: pyvex.expr.Unop):
        return self._handle_vex_expr_Op(expr)

    def _handle_vex_expr_Binop(self, expr: pyvex.expr.Unop):
        return self._handle_vex_expr_Op(expr)

    def _handle_vex_expr_Triop(self, expr: pyvex.expr.Unop):
        return self._handle_vex_expr_Op(expr)

    def _handle_vex_expr_Qop(self, expr: pyvex.expr.Unop):
        return self._handle_vex_expr_Op(expr)

    def _handle_vex_expr_Op(self, expr):
        return self._perform_vex_expr_Op(expr.op, [self._handle_vex_expr(arg) for arg in expr.args])

    def _perform_vex_expr_Op(self, op, args):
        return NotImplemented

    # fully implemented expressions

    def _handle_vex_expr_Const(self, expr: pyvex.expr.Const):
        return self._handle_vex_const(expr.con)

    def _analyze_vex_expr_GetI_ix(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_expr_GetI(self, expr: pyvex.expr.GetI):
        return self._perform_vex_expr_GetI(
            expr.descr.base,
            expr.descr.elemTy,
            expr.bias,
            self._analyze_vex_expr_GetI_ix(expr.ix),
            expr.descr.nElems,
        )

    def _perform_vex_expr_GetI_get(self, *a, **kw):
        return self._perform_vex_expr_Get(*a, **kw)

    def _perform_vex_expr_GetI(self, base, ty, bias, ix, nElems):
        offset = self._perform_vex_stmt_PutI_compute(base, ty, bias, ix, nElems)
        return self._perform_vex_expr_GetI_get(offset, ty)

    # oh boy.

    def _handle_vex_expr_GSPTR(self, expr: pyvex.expr.GSPTR):
        return NotImplemented

    def _handle_vex_expr_VECRET(self, expr: pyvex.expr.VECRET):
        return NotImplemented

    def _handle_vex_expr_Binder(self, expr: pyvex.expr.Binder):
        return NotImplemented

    #
    # Individual statement handlers go here
    #

    # stmt category 1: fluff

    def _handle_vex_stmt_IMark(self, stmt):
        pass

    def _handle_vex_stmt_NoOp(self, stmt):
        pass

    def _handle_vex_stmt_AbiHint(self, stmt):
        pass

    def _handle_vex_stmt_MBE(self, stmt):
        pass

    # stmt category 2: real shit

    def _analyze_vex_stmt_Put_data(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_Put(self, stmt):
        self._perform_vex_stmt_Put(
            self._handle_vex_const(pyvex.const.U32(stmt.offset)), self._analyze_vex_stmt_Put_data(stmt.data)
        )

    def _perform_vex_stmt_Put(self, offset, data, **kwargs):
        pass

    def _analyze_vex_stmt_WrTmp_data(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_WrTmp(self, stmt):
        self._perform_vex_stmt_WrTmp(stmt.tmp, self._analyze_vex_stmt_WrTmp_data(stmt.data))

    def _perform_vex_stmt_WrTmp(self, tmp, data):
        self.tmps[tmp] = data

    def _analyze_vex_stmt_Store_address(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_Store_data(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_Store(self, stmt: pyvex.stmt.Store):
        self._perform_vex_stmt_Store(
            self._analyze_vex_stmt_Store_address(stmt.addr), self._analyze_vex_stmt_Store_data(stmt.data), stmt.end
        )

    def _perform_vex_stmt_Store(self, addr, data, endness, **kwargs):
        pass

    def _analyze_vex_stmt_Exit_guard(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_Exit(self, stmt: pyvex.stmt.Exit):
        self._perform_vex_stmt_Exit(
            self._analyze_vex_stmt_Exit_guard(stmt.guard), self._handle_vex_const(stmt.dst), stmt.jk
        )

    def _perform_vex_stmt_Exit(self, guard, target, jumpkind):
        pass

    def _analyze_vex_stmt_Dirty_arg(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_Dirty(self, stmt: pyvex.stmt.Dirty):
        return self._perform_vex_stmt_Dirty(
            stmt.cee.name,
            self.irsb.tyenv.lookup(stmt.tmp) if stmt.tmp not in (-1, 0xFFFFFFFF) else None,
            stmt.tmp,
            [self._analyze_vex_stmt_Dirty_arg(arg) for arg in stmt.args],
        )

    def _perform_vex_stmt_Dirty_wrtmp(self, *a, **kw):
        return self._perform_vex_stmt_WrTmp(*a, **kw)

    def _perform_vex_stmt_Dirty(self, func_name, ty, tmp, args):
        retval = self._perform_vex_stmt_Dirty_call(func_name, ty, args)
        if tmp not in (-1, 0xFFFFFFFF):
            self._perform_vex_stmt_Dirty_wrtmp(tmp, retval)

    def _perform_vex_stmt_Dirty_call(self, func_name, ty, args, func=None):
        return NotImplemented

    # stmt category 3: weird load/store patterns implemented in terms of above

    def _analyze_vex_stmt_PutI_ix(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_PutI_data(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_PutI(self, stmt: pyvex.stmt.PutI):
        self._perform_vex_stmt_PutI(
            stmt.descr.base,
            stmt.descr.elemTy,
            stmt.bias,
            self._analyze_vex_stmt_PutI_ix(stmt.ix),
            stmt.descr.nElems,
            self._analyze_vex_stmt_PutI_data(stmt.data),
        )

    def _perform_vex_stmt_PutI_compute(self, base, elemTy, bias, ix, nElems):
        # base + ((bias + ix) % nElems) * elemSize
        elemSize = self._ty_to_bytes(elemTy)
        index = self._perform_vex_expr_Op("Iop_Add32", (self._handle_vex_const(pyvex.const.U32(bias)), ix))
        big_index = self._perform_vex_expr_Op("Iop_32HLto64", (self._handle_vex_const(pyvex.const.U32(0)), index))
        divmod_index = self._perform_vex_expr_Op(
            "Iop_DivModU64to32", (big_index, self._handle_vex_const(pyvex.const.U32(nElems)))
        )
        mod_index = self._perform_vex_expr_Op("Iop_64HIto32", (divmod_index,))
        offset = self._perform_vex_expr_Op("Iop_Mul32", (mod_index, self._handle_vex_const(pyvex.const.U32(elemSize))))
        return self._perform_vex_expr_Op("Iop_Add32", (self._handle_vex_const(pyvex.const.U32(base)), offset))

    def _perform_vex_stmt_PutI(self, base, elemSize, bias, ix, nElems, data):
        offset = self._perform_vex_stmt_PutI_compute(base, elemSize, bias, ix, nElems)
        self._perform_vex_stmt_Put(offset, data)

    def _analyze_vex_stmt_LLSC_addr(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_LLSC_storedata(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_LLSC(self, stmt: pyvex.stmt.LLSC):
        self._perform_vex_stmt_LLSC(
            stmt.result,
            self._analyze_vex_stmt_LLSC_addr(stmt.addr),
            stmt.endness,
            self._analyze_vex_stmt_LLSC_storedata(stmt.storedata) if stmt.storedata is not None else None,
            self.irsb.tyenv.lookup(stmt.result),
        )

    def _perform_vex_stmt_LLSC_load(self, *a, **kw):
        return self._perform_vex_expr_Load(*a, **kw)

    def _perform_vex_stmt_LLSC_store(self, *a, **kw):
        return self._perform_vex_stmt_Store(*a, **kw)

    def _perform_vex_stmt_LLSC_wrtmp(self, *a, **kw):
        return self._perform_vex_stmt_WrTmp(*a, **kw)

    def _perform_vex_stmt_LLSC(self, result, addr, endness, storedata, ty):
        if storedata is None:
            load_result = self._perform_vex_stmt_LLSC_load(addr, ty, endness)
            self._perform_vex_stmt_LLSC_wrtmp(result, load_result)
        else:
            self._perform_vex_stmt_LLSC_store(addr, storedata, endness)
            self._perform_vex_stmt_LLSC_wrtmp(result, self._handle_vex_const(pyvex.const.U1(1)))

    def _analyze_vex_stmt_LoadG_addr(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_LoadG_alt(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_LoadG_guard(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_LoadG(self, stmt: pyvex.stmt.LoadG):
        self._perform_vex_stmt_LoadG(
            self._analyze_vex_stmt_LoadG_addr(stmt.addr),
            self._analyze_vex_stmt_LoadG_alt(stmt.alt),
            self._analyze_vex_stmt_LoadG_guard(stmt.guard),
            stmt.dst,
            stmt.cvt,
            stmt.end,
        )

    def _perform_vex_stmt_LoadG_load(self, *a, **kw):
        return self._perform_vex_expr_Load(*a, **kw)

    def _perform_vex_stmt_LoadG_widen(self, *a, **kw):
        return self._perform_vex_expr_Op(*a, **kw)

    def _perform_vex_stmt_LoadG_ite(self, *a, **kw):
        return self._perform_vex_expr_ITE(*a, **kw)

    def _perform_vex_stmt_LoadG_wrtmp(self, *a, **kw):
        return self._perform_vex_stmt_WrTmp(*a, **kw)

    def _perform_vex_stmt_LoadG_guard_condition(self, guard):
        return guard == 1

    def _perform_vex_stmt_LoadG(self, addr, alt, guard, dst, cvt, end):
        cvt_properties = {
            "ILGop_IdentV128": ("Ity_V128", None),  # 128 bit vector, no conversion */
            "ILGop_Ident64": ("Ity_I64", None),  # 64 bit, no conversion */
            "ILGop_Ident32": ("Ity_I32", None),  # 32 bit, no conversion */
            "ILGop_16Uto32": ("Ity_I16", "Iop_16Uto32"),  # 16 bit load, Z-widen to 32 */
            "ILGop_16Sto32": ("Ity_I16", "Iop_16Sto32"),  # 16 bit load, S-widen to 32 */
            "ILGop_8Uto32": ("Ity_I8", "Iop_8Uto32"),  # 8 bit load, Z-widen to 32 */
            "ILGop_8Sto32": ("Ity_I8", "Iop_8Sto32"),  # 8 bit load, S-widen to 32 */
        }

        # Because of how VEX's ARM lifter works, we may introduce non-existent register loads.
        # Here is an example:
        #
        # .text:0800408C ITTTT MI
        # .text:0800408E LDRMI   R2, =0x40020004
        # .text:08004090 LDRMI   R3
        #
        # 116 | ------ IMark(0x800408e, 2, 1) ------
        # 117 | t247 = Or32(t225,0x00000040)
        # 118 | t254 = armg_calculate_condition(t247,t227,t229,t231):Ity_I32
        # 119 | t262 = GET:I32(r2)
        # 120 | t263 = CmpNE32(t254,0x00000000)
        # 121 | t66 = if (t263) ILGop_Ident32(LDle(0x080040bc)) else t262
        # 122 | PUT(r2) = t66
        # 123 | PUT(pc) = 0x08004091
        # 124 | ------ IMark(0x8004090, 2, 1) ------
        # 125 | t280 = t263
        # 126 | t73 = if (t280) ILGop_Ident32(LDle(t66)) else t222
        #
        # t280 == t263 == the condition inside t66. Now t66 looks like this:
        #   <BV32 cond then 0x40020004 else reg_r2_861_32{UNINITIALIZED}>. since t280 is guarding the load from t66,
        # if the load from t66 is not aware of the condition that t280 is True, we will end up reading from r2_861_32,
        # which is not what the original instruction intended.
        # Therefore, the load from t66 should be aware of the condition that t280 is True. Or even better, don't
        # perform the read if the condition is evaluated to False.
        # We can perform another optimization: Let this condition be cond. When cond can be evaluated to either True or
        # False, we don't want to perform the read when the cond is the guard (which is a relatively cheap check) and
        # is False. When the cond is True, we perform the read with only the intended address (instead of the entire
        # guarded address). This way we get rid of the redundant load that should have existed in the first place.

        ty, cvt_op = cvt_properties[cvt]
        if self._is_false(guard):
            self._perform_vex_stmt_LoadG_wrtmp(dst, alt)
            return
        load_result = self._perform_vex_stmt_LoadG_load(
            addr, ty, end, condition=self._perform_vex_stmt_LoadG_guard_condition(guard)
        )
        cvt_result = load_result if cvt_op is None else self._perform_vex_stmt_LoadG_widen(cvt_op, (load_result,))
        ite_result = self._perform_vex_stmt_LoadG_ite(guard, cvt_result, alt)
        self._perform_vex_stmt_LoadG_wrtmp(dst, ite_result)

    def _analyze_vex_stmt_StoreG_addr(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_StoreG_data(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_StoreG_guard(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_StoreG(self, stmt: pyvex.stmt.StoreG):
        self._perform_vex_stmt_StoreG(
            self._analyze_vex_stmt_StoreG_addr(stmt.addr),
            self._analyze_vex_stmt_StoreG_data(stmt.data),
            self._analyze_vex_stmt_StoreG_guard(stmt.guard),
            stmt.data.result_type(self.irsb.tyenv),
            stmt.end,
        )

    def _perform_vex_stmt_StoreG_load(self, *a, **kw):
        return self._perform_vex_expr_Load(*a, **kw)

    def _perform_vex_stmt_StoreG_ite(self, *a, **kw):
        return self._perform_vex_expr_ITE(*a, **kw)

    def _perform_vex_stmt_StoreG_store(self, *a, **kw):
        return self._perform_vex_stmt_Store(*a, **kw)

    def _perform_vex_stmt_StoreG_guard_condition(self, guard):
        return guard == 1

    def _perform_vex_stmt_StoreG(self, addr, data, guard, ty, endness, **kwargs):
        # perform the same optimization as in _perform_vex_stmt_LoadG
        if self._is_false(guard):
            return
        self._perform_vex_stmt_StoreG_store(
            addr, data, endness, condition=self._perform_vex_stmt_StoreG_guard_condition(guard), **kwargs
        )

    def _analyze_vex_stmt_CAS_addr(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_CAS_dataLo(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_CAS_dataHi(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_CAS_expdLo(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _analyze_vex_stmt_CAS_expdHi(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def _handle_vex_stmt_CAS(self, stmt: pyvex.stmt.CAS):
        self._perform_vex_stmt_CAS(
            self._analyze_vex_stmt_CAS_addr(stmt.addr),
            self._analyze_vex_stmt_CAS_dataLo(stmt.dataLo),
            self._analyze_vex_stmt_CAS_dataHi(stmt.dataHi) if stmt.dataHi is not None else None,
            self._analyze_vex_stmt_CAS_expdLo(stmt.expdLo),
            self._analyze_vex_stmt_CAS_expdHi(stmt.expdHi) if stmt.expdHi is not None else None,
            stmt.oldLo,
            stmt.oldHi,
            stmt.endness,
            stmt.expdLo.result_type(self.irsb.tyenv),
        )

    def _perform_vex_stmt_CAS_load(self, *a, **kw):
        return self._perform_vex_expr_Load(*a, **kw)

    def _perform_vex_stmt_CAS_wrtmp(self, *a, **kw):
        return self._perform_vex_stmt_WrTmp(*a, **kw)

    def _perform_vex_stmt_CAS_cmp(self, *a, **kw):
        return self._perform_vex_expr_Op(*a, **kw)

    def _perform_vex_stmt_CAS_narrow(self, *a, **kw):
        return self._perform_vex_expr_Op(*a, **kw)

    def _perform_vex_stmt_CAS_widen(self, *a, **kw):
        return self._perform_vex_expr_Op(*a, **kw)

    def _perform_vex_stmt_CAS_storeg(self, *a, **kw):
        return self._perform_vex_stmt_StoreG(*a, **kw)

    def _perform_vex_stmt_CAS(self, addr, dataLo, dataHi, expdLo, expdHi, oldLo, oldHi, endness, ty):
        # - load mem
        # - compare
        # - store mem conditional
        # - store tmp
        double = dataHi is not None
        if double:
            ty, narrow_lo_op, narrow_hi_op, widen_op = {
                "Ity_I8": ("Ity_I16", "Iop_16to8", "Iop_16Hito8", "Iop_8HLto16"),
                "Ity_I16": ("Ity_I32", "Iop_32to16", "Iop_32HIto16", "Iop_16HLto32"),
                "Ity_I32": ("Ity_I64", "Iop_64to32", "Iop_64HIto32", "Iop_32HLto64"),
                "Ity_I64": ("Ity_V128", "Iop_128to64", "Iop_128HIto64", "Iop_64HLto128"),
            }[ty]
            data = self._perform_vex_stmt_CAS_widen(widen_op, (dataHi, dataLo))
            expd = self._perform_vex_stmt_CAS_widen(widen_op, (expdHi, expdLo))
        else:
            narrow_lo_op = narrow_hi_op = None
            data = dataLo
            expd = expdLo

        cmp_op = {
            "Ity_I8": "Iop_CmpEQ8",
            "Ity_I16": "Iop_CmpEQ16",
            "Ity_I32": "Iop_CmpEQ32",
            "Ity_I64": "Iop_CmpEQ64",
            "Ity_V128": "Iop_CmpEQ128",
        }[ty]

        val = self._perform_vex_stmt_CAS_load(addr, ty, endness)
        cmp = self._perform_vex_stmt_CAS_cmp(cmp_op, (val, expd))
        self._perform_vex_stmt_CAS_storeg(addr, data, cmp, ty, endness)

        if double:
            valHi = self._perform_vex_stmt_CAS_narrow(narrow_hi_op, (val,))
            valLo = self._perform_vex_stmt_CAS_narrow(narrow_lo_op, (val,))

            self._perform_vex_stmt_CAS_wrtmp(oldLo, valLo)
            self._perform_vex_stmt_CAS_wrtmp(oldHi, valHi)
        else:
            self._perform_vex_stmt_CAS_wrtmp(oldLo, val)

    #
    # block level handling
    #

    def _analyze_vex_defaultexit(self, *a, **kw):
        return self._handle_vex_expr(*a, **kw)

    def handle_vex_block(self, irsb: pyvex.IRSB):
        self.irsb = irsb
        self.tmps = [None] * self.irsb.tyenv.types_used

        for stmt_idx, stmt in enumerate(irsb.statements):
            self.stmt_idx = stmt_idx
            self._handle_vex_stmt(stmt)
        self.stmt_idx = DEFAULT_STATEMENT
        self._handle_vex_defaultexit(irsb.next, irsb.jumpkind)

    def _handle_vex_defaultexit(self, expr: pyvex.expr.IRExpr | None, jumpkind: str):
        self._perform_vex_defaultexit(self._analyze_vex_defaultexit(expr) if expr is not None else None, jumpkind)

    def _perform_vex_defaultexit(self, expr, jumpkind):
        pass

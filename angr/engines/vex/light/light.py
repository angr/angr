from __future__ import annotations

import logging

import math
import time

import claripy
import pyvex

from angr.engines.engine import SimEngine
from angr.utils.constants import DEFAULT_STATEMENT

l = logging.getLogger(name=__name__)

# pylint:disable=arguments-differ,unused-argument,no-self-use


class VEXMixin(SimEngine):
    def __init__(self, project, **kwargs):
        super().__init__(project, **kwargs)
        self._vex_expr_handlers = []
        self._vex_stmt_handlers = []
        self.__init_handlers()

        self.irsb = None
        self.stmt_idx = None
        self.tmps = None

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

    def _handle_vex_expr_DataSensitiveRdTmp(self, expr):
        # pyvex's DataSensitiveRdTmp is an RdTmp tagged with its originating block; the tag is only
        # read by the data-sensitive analyses, so evaluation is identical.
        return self._handle_vex_expr_RdTmp(expr)

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
        offset = self._handle_vex_const(pyvex.const.U32(stmt.offset))
        data = self._analyze_vex_stmt_Put_data(stmt.data)
        self._perform_vex_stmt_Put(offset, data)
        self._ctf_observe_put(offset, data, stmt)

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
        addr = self._analyze_vex_stmt_Store_address(stmt.addr)
        data = self._analyze_vex_stmt_Store_data(stmt.data)
        self._perform_vex_stmt_Store(addr, data, stmt.end)
        self._ctf_observe_store(addr, data, stmt)

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
        if self.state.solver.is_true(guard[0] == 0):
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
        if self.state.solver.is_true(guard[0] == 0):
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

    def _ctf_finder_enabled(self):
        state = getattr(self, "state", None)
        if state is None:
            return False

        if not state.globals.get("vm_graph_exploration", False) or \
                not state.globals.get("use_ctf_vpc_finder", False):
            return False

        if getattr(self.project, "ctf_vpc_require_deobfuscation_start", False):
            return state.globals.get("start_deobfuscation", False) is True or \
                getattr(self.project, "start_deobfuscation_immediately", False) is True

        return True

    def _ctf_stack_store_ptr_mode_enabled(self, setting):
        mode = getattr(self.project, "ctf_vpc_stack_store_ptr_mode", None)
        if isinstance(mode, str):
            modes = {mode}
        elif isinstance(mode, (tuple, list, set)):
            modes = set(mode)
        else:
            modes = set()

        implied_settings = {
            "commit_on_store": {"fast", "store_only"},
            "allow_unconfirmed_store": {"store_only"},
            "fast_path": {"fast", "store_only"},
            "block_fast_path": {"block_fast"},
            "allow_unconfirmed_block_fast_path": {"block_fast"},
            "store_only": {"store_only"},
            "allow_unconfirmed_store_only": {"store_only"},
        }

        return bool(getattr(self.project, f"ctf_vpc_stack_store_ptr_{setting}", False)) or \
            bool(modes & implied_settings.get(setting, set()))

    def _ctf_fd_read_pos_mode_enabled(self, setting):
        mode = getattr(self.project, "ctf_vpc_fd_read_pos_mode", None)
        if isinstance(mode, str):
            modes = {mode}
        elif isinstance(mode, (tuple, list, set)):
            modes = set(mode)
        else:
            modes = set()

        implied_settings = {
            "candidate": {"simfile_cursor"},
            "fast_path": {"simfile_cursor"},
            "sticky": {"simfile_cursor"},
            "allow_initial": {"simfile_cursor"},
            "ignore_stores": {"simfile_cursor"},
        }

        return bool(getattr(self.project, f"ctf_vpc_fd_read_pos_{setting}", False)) or \
            bool(modes & implied_settings.get(setting, set()))

    def _ctf_reg_tup_from_offset(self, offset):
        if offset is None:
            return None

        for reg_name, (reg_off, reg_size) in self.project.arch.registers.items():
            if reg_off != offset:
                continue
            canonical = self._ctf_canonical_reg_name(reg_name)
            if canonical != reg_name:
                continue
            return reg_name, (reg_off, reg_size)

        for reg_name, reg_tup, _ in self._ctf_register_values():
            if reg_tup[0] == offset:
                return reg_name, reg_tup

        return None

    def _ctf_observe_put(self, offset_expr, data_expr, stmt):
        if not self._ctf_finder_enabled():
            return

        offset = self._ctf_eval_one(offset_expr)
        reg_info = self._ctf_reg_tup_from_offset(offset)
        if reg_info is None:
            return

        _, reg_tup = reg_info
        value = self._ctf_eval_model_value(data_expr)
        if value is None or value < 0:
            return

        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        cur_reg_tup = cur_source[1] if isinstance(cur_source, tuple) and len(cur_source) > 1 and cur_source[0] == "reg_index" else None
        if cur_reg_tup is None:
            cur_source = self.state.globals.get("ctf_reg_index_source_by_reg", {}).get(reg_tup, None)
            cur_reg_tup = reg_tup if cur_source is not None else None

        origin = "reg_write"
        if cur_reg_tup != reg_tup:
            if not self._ctf_is_reg_index_source(cur_source) or \
                    not self._ctf_current_block_is_dispatcher_reg_write(reg_tup, cur_source):
                return

            cur_source = ("reg_index", reg_tup, cur_source[2], cur_source[3], cur_source[4])
            cur_reg_tup = reg_tup
            origin = "reg_write_dispatcher"
        elif self._ctf_current_block_self_clobbers_source(cur_source):
            return

        reg_vals = self._ctf_register_values()
        entropy_regions = self._ctf_entropy_regions(reg_vals=reg_vals)
        if not entropy_regions:
            return

        candidates = []
        for region in entropy_regions:
            region_size = region["end"] - region["start"]
            if self._ctf_region_contains(region, value) or 0 <= value < region_size:
                self._ctf_add_candidate(
                    candidates,
                    cur_source,
                    value,
                    24 + (region["delta"] * 2),
                    "reg_index",
                    reg_tup=reg_tup,
                    origin=origin,
                    region=region,
                )

        if candidates:
            observed = self.state.globals.get("ctf_vpc_observed_reg_candidates", [])
            observed.extend(candidates)
            self.state.globals["ctf_vpc_observed_reg_candidates"] = observed[-64:]
            self._ctf_commit_candidate(max(candidates, key=lambda cand: cand["score"]))

    def _ctf_store_data_size(self, stmt):
        try:
            return self._ty_to_bytes(stmt.data.result_type(self.irsb.tyenv))
        except Exception:
            return self.project.arch.bytes

    def _ctf_observe_store(self, addr_expr, data_expr, stmt):
        if not self._ctf_finder_enabled():
            return

        if self.state.globals.get("ctf_cur_vpc_kind", None) == "reg_index" and \
                self._ctf_locked_entropy_regions() and \
                getattr(self.project, "ctf_vpc_skip_store_candidates_when_reg_index_locked", True):
            return

        if self.state.globals.get("ctf_cur_vpc_kind", None) == "fd_read_pos" and \
                self._ctf_fd_read_pos_mode_enabled("ignore_stores"):
            return

        addr = self._ctf_eval_one(addr_expr)
        if addr is None or not self._ctf_is_stack_addr(addr):
            return

        size = self._ctf_store_data_size(stmt)
        try:
            stored_expr = self.state.memory.load(addr, size, endness=self.project.arch.memory_endness)
            value = self._ctf_eval_model_value(stored_expr)
        except Exception:
            value = None

        if value is None:
            value = self._ctf_eval_model_value(data_expr)

        if value is None or value < 0:
            return

        if getattr(self.project, "ctf_vpc_allow_stack_store_raw_offset", False):
            self._ctf_note_stack_raw_base_store(value)

        if self._ctf_try_stack_store_ptr_fast_path(addr, size, value):
            return

        word = {
            "addr": addr,
            "size": size,
            "value": value,
            "anchor": "store",
        }
        reg_vals = self._ctf_register_values()
        stack_words = self._ctf_stack_words() + [word]
        entropy_regions = self._ctf_entropy_regions(reg_vals=reg_vals, stack_words=stack_words)
        region_biases = self._ctf_region_biases(entropy_regions)
        stack_index_uses = self._ctf_stack_index_uses(entropy_regions)
        stack_pointer_uses = self._ctf_stack_pointer_uses(entropy_regions)
        has_stack_index_uses = bool(stack_index_uses)
        stack_index_regions = {key[2] for key in stack_index_uses}
        candidates = []

        if getattr(self.project, "ctf_vpc_allow_stack_store_raw_offset", False):
            raw_index_uses = self._ctf_stack_raw_index_uses()
            raw_info = raw_index_uses.get((addr, size), None) if self._ctf_stack_raw_slot_allowed(addr, size) else None
            if raw_info is None:
                raw_info = self._ctf_stack_raw_info_for_slot(addr, size)
            if raw_info is not None and value <= getattr(self.project, "ctf_vpc_max_index", 0x100000):
                base_addr = raw_info.get("base", None)
                namespace_bias = self._ctf_stack_raw_namespace_bias(base_addr, value)
                old_candidate_count = len(candidates)
                self._ctf_add_candidate(
                    candidates,
                    ("stack_store_raw_offset", addr, size, base_addr),
                    namespace_bias + value,
                    getattr(self.project, "ctf_vpc_stack_raw_source_score", 40) + raw_info.get("score", 0),
                    "stack_store_raw_offset",
                    origin="stack_store",
                )
                if len(candidates) > old_candidate_count and getattr(
                        self.project, "ctf_vpc_stack_raw_commit_on_store", True):
                    self._ctf_commit_candidate(candidates[-1])

        stack_store_ptr_candidates = []
        for region in entropy_regions:
            if self._ctf_region_contains(region, value):
                if region["start"] in stack_index_regions and \
                        getattr(self.project, "ctf_vpc_prefer_stack_index_over_pointer", True):
                    continue

                pointer_use_score = stack_pointer_uses.get((addr, size, region["start"]), None)
                origin = "stack_store"
                if pointer_use_score is None:
                    allow_unconfirmed = self._ctf_stack_store_ptr_mode_enabled("allow_unconfirmed_store") and \
                        not self.state.globals.get("ctf_stack_store_ptr_source_confirmed", False)
                    if not allow_unconfirmed and getattr(self.project, "ctf_vpc_require_stack_pointer_use", True):
                        continue
                    pointer_use_score = 0
                    origin = "stack_store_unconfirmed"

                if self.state.globals.get("ctf_cur_vpc_kind", None) == "stack_store_ptr" and \
                        self.state.globals.get("ctf_stack_store_ptr_source_confirmed", False) and \
                        getattr(self.project, "ctf_vpc_sticky_stack_store_ptr_source", True):
                    cur_slot = self._ctf_stack_source_slot(self.state.globals.get("ctf_cur_vpc_source", None))
                    if cur_slot is not None and cur_slot != (addr, size):
                        continue

                if pointer_use_score is None and getattr(self.project, "ctf_vpc_require_stack_pointer_use", True):
                    continue

                old_candidate_count = len(candidates)
                self._ctf_add_candidate(
                    candidates,
                    ("stack_store_ptr", addr, size, region["start"]),
                    value,
                    14 + (region["delta"] * 2) + pointer_use_score,
                    "stack_store_ptr",
                    origin=origin,
                    region=region,
                )
                stack_store_ptr_candidates.extend(candidates[old_candidate_count:])

            region_size = region["end"] - region["start"]
            if 0 <= value < min(region_size, getattr(self.project, "ctf_vpc_max_index", 0x100000)):
                index_use_score = stack_index_uses.get((addr, size, region["start"]), None)
                if index_use_score is None and getattr(self.project, "ctf_vpc_require_stack_index_use", True):
                    continue

                score = 18 + (region["delta"] * 2)
                if index_use_score is not None:
                    score += index_use_score
                if value == 0:
                    score -= 8
                self._ctf_add_candidate(
                    candidates,
                    ("stack_store_offset", addr, size, region["start"]),
                    region_biases[region["start"]] + value,
                    score,
                    "stack_store_offset",
                    region=region,
                )

        if stack_store_ptr_candidates and self._ctf_stack_store_ptr_mode_enabled("commit_on_store"):
            stack_store_ptr_candidates = self._ctf_stack_store_ptr_candidates_for_current_source(
                stack_store_ptr_candidates
            )
            if stack_store_ptr_candidates:
                self._ctf_commit_candidate(max(stack_store_ptr_candidates, key=lambda cand: cand["score"]))

        if getattr(self.project, "ctf_vpc_allow_codeptr", False) and self.project.loader.main_object.contains_addr(value):
            sec = self.project.loader.main_object.find_section_containing(value)
            if sec is not None and getattr(sec, "is_executable", False):
                self._ctf_add_candidate(
                    candidates,
                    ("stack_store_codeptr", addr, size),
                    value,
                    13,
                    "stack_store_codeptr",
                )

        if candidates:
            observed = self.state.globals.get("ctf_vpc_observed_store_candidates", [])
            observed.extend(candidates)
            self.state.globals["ctf_vpc_observed_store_candidates"] = observed[-64:]

    def _calc_entropy(self, data, size=None):
        """
        Calculate the entropy of a piece of data

        :param data: The target data to calculate entropy on
        :param size: Size of the data, Optional.
        :return: A float
        """

        if not data:
            return 0
        entropy = 0
        if size is None:
            size = len(data)

        for x in range(0, 256):
            p_x = float(data.count(x)) / size
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def _is_vip_candidate_section_addr(self, addr):
        obj = self.project.loader.main_object
        if not obj.contains_addr(addr):
            return False

        sec = obj.find_section_containing(addr)
        if sec is None:
            return False

        return not sec.name.startswith('.rdata') and not sec.name.startswith('.data')

    def _vip_canonical_reg_name(self, reg_name):
        if reg_name is None:
            return None

        reg_name = reg_name.lower()
        if self.project.arch.bits == 64:
            return self._ctf_canonical_reg_name(reg_name)

        aliases = {
            "ax": "eax", "al": "eax", "ah": "eax",
            "bx": "ebx", "bl": "ebx", "bh": "ebx",
            "cx": "ecx", "cl": "ecx", "ch": "ecx",
            "dx": "edx", "dl": "edx", "dh": "edx",
            "si": "esi", "sil": "esi",
            "di": "edi", "dil": "edi",
            "bp": "ebp", "bpl": "ebp",
            "sp": "esp", "spl": "esp",
        }
        return aliases.get(reg_name, reg_name)

    def _vip_reg_name_from_tup(self, reg_tup):
        reg_name = self._ctf_reg_name_from_tup(reg_tup)
        if reg_name is not None:
            return self._vip_canonical_reg_name(reg_name)

        for name, cur_reg_tup in self.project.arch.registers.items():
            if cur_reg_tup == reg_tup:
                return self._vip_canonical_reg_name(name)

        return None

    def _vip_candidate_use_scores(self, candidate_vips):
        bbl = self.state.globals.get("cur_bbl", None)
        if bbl is None or not candidate_vips:
            return {}

        scores = {reg_tup: 0 for reg_tup in candidate_vips}
        reg_to_tups = {}
        for reg_tup in candidate_vips:
            reg_name = self._vip_reg_name_from_tup(reg_tup)
            if reg_name is None:
                continue
            reg_to_tups.setdefault(reg_name, set()).add(reg_tup)

        if not reg_to_tups:
            return scores

        capstone_insns = getattr(getattr(bbl, "capstone", None), "insns", None)
        disassembly = getattr(bbl, "disassembly", None)
        insns = capstone_insns or getattr(disassembly, "insns", [])

        def add_score(reg_name, score):
            for reg_tup in reg_to_tups.get(reg_name, ()):
                scores[reg_tup] = scores.get(reg_tup, 0) + score

        def operand_reg(cap_insn, operand):
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None or getattr(operand, "type", None) != 1:
                return None
            return self._vip_canonical_reg_name(reg_name_func(operand.reg))

        def mem_regs(cap_insn, mem):
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None or mem is None:
                return []

            regs = []
            if getattr(mem, "base", 0):
                regs.append(self._vip_canonical_reg_name(reg_name_func(mem.base)))
            if getattr(mem, "index", 0):
                regs.append(self._vip_canonical_reg_name(reg_name_func(mem.index)))
            return [reg for reg in regs if reg is not None]

        def first_operand_is_written(operands, mnemonic):
            if not operands or getattr(operands[0], "type", None) != 1:
                return False

            access = getattr(operands[0], "access", None)
            if access:
                return bool(access & 2)

            return mnemonic not in {"cmp", "test", "jmp", "call", "push"}

        for ins in insns:
            cap_insn = getattr(ins, "insn", ins)
            operands = getattr(cap_insn, "operands", [])
            mnemonic = getattr(cap_insn, "mnemonic", "")
            if not operands:
                continue

            dest_reg = operand_reg(cap_insn, operands[0])
            dest_is_write = first_operand_is_written(operands, mnemonic)

            for op_idx, operand in enumerate(operands):
                mem = getattr(operand, "mem", None)
                if mem is None:
                    continue

                for reg_name in mem_regs(cap_insn, mem):
                    if reg_name not in reg_to_tups:
                        continue

                    add_score(reg_name, 36)
                    if op_idx > 0 or not dest_is_write:
                        add_score(reg_name, 24)
                    if mnemonic in ("mov", "movsxd", "movzx", "lods", "lodsb", "lodsd", "lodsq"):
                        add_score(reg_name, 10)

            if dest_reg is None or dest_reg not in reg_to_tups:
                continue

            if mnemonic == "lea" and len(operands) >= 2:
                mem = getattr(operands[1], "mem", None)
                regs = mem_regs(cap_insn, mem)
                if dest_reg in regs:
                    add_score(dest_reg, 30)
                elif not regs:
                    add_score(dest_reg, -50)
                continue

            if mnemonic in ("add", "sub") and len(operands) >= 2 and dest_is_write:
                add_score(dest_reg, 18)
                continue

            if mnemonic in ("inc", "dec") and dest_is_write:
                add_score(dest_reg, 12)
                continue

            if mnemonic in ("mov", "movabs") and len(operands) >= 2 and \
                    getattr(operands[1], "type", None) == 2:
                add_score(dest_reg, -40)

        return scores

    def _vip_candidate_use_allowed(self, reg_tup, candidate_vips, use_scores):
        if not getattr(self.project, "vip_candidate_use_filter", True):
            return True
        if len(candidate_vips) <= 1:
            return True

        best_score = max((use_scores.get(tup, 0) for tup in candidate_vips), default=0)
        if best_score < getattr(self.project, "vip_candidate_strong_use_score", 36):
            return True

        score = use_scores.get(reg_tup, 0)
        if score >= getattr(self.project, "vip_candidate_min_use_score", 12):
            return True

        return score >= best_score - getattr(self.project, "vip_candidate_use_score_slack", 24)

    def _vip_ordered_candidates(self, candidate_vips, use_scores):
        return sorted(
            candidate_vips.items(),
            key=lambda item: use_scores.get(item[0], 0),
            reverse=True,
        )

    @staticmethod
    def _ctf_unwrap_expr(expr):
        while isinstance(expr, tuple) and len(expr) == 2 and isinstance(expr[1], (frozenset, set)):
            expr = expr[0]

        return expr

    def _ctf_eval_one(self, expr):
        expr = self._ctf_unwrap_expr(expr)
        if expr is None:
            return None
        if isinstance(expr, int):
            return expr

        try:
            poss_vals = self.state.partial_symbolic_constraint_solver.eval_upto(expr, 2)
            if len(poss_vals) == 1:
                return poss_vals[0]
            return None
        except Exception:
            pass

        try:
            poss_vals = self.state.solver.eval_upto(expr, 2)
            if len(poss_vals) == 1:
                return poss_vals[0]
        except Exception:
            return None

        return None

    def _ctf_eval_model_value(self, expr):
        expr = self._ctf_unwrap_expr(expr)
        val = self._ctf_eval_one(expr)
        if val is not None:
            return val

        try:
            return self.state.solver.eval(expr)
        except Exception:
            return None

    def _ctf_read_state_bytes(self, addr, size):
        if addr is None or size <= 0:
            return None

        try:
            data = self.state.memory.load(addr, size, endness="Iend_BE")
            if self.state.solver.symbolic(data):
                return None
            return self.state.solver.eval(data, cast_to=bytes)
        except Exception:
            return None

    def _ctf_read_state_int(self, addr, size):
        if addr is None or size <= 0:
            return None

        try:
            data = self.state.memory.load(addr, size, endness=self.project.arch.memory_endness)
            return self._ctf_eval_one(data)
        except Exception:
            return None

    def _ctf_eval_register_tuple(self, reg_name, reg_tup, allow_model=False):
        def eval_loaded(tup, model=False):
            try:
                data = self.state.registers.load(tup[0], tup[1])
            except Exception:
                return None

            if model:
                return self._ctf_eval_model_value(data)

            return self._ctf_eval_one(data)

        val = eval_loaded(reg_tup)
        if val is not None:
            return val

        alias_tups = []
        for alias_name, alias_tup in self.project.arch.registers.items():
            if alias_tup[0] != reg_tup[0] or alias_tup[1] >= reg_tup[1]:
                continue
            if self._ctf_canonical_reg_name(alias_name) != reg_name:
                continue

            alias_tups.append(alias_tup)

        for alias_tup in sorted(set(alias_tups), key=lambda tup: tup[1], reverse=True):
            val = eval_loaded(alias_tup)
            if val is not None:
                return val

        if allow_model:
            val = eval_loaded(reg_tup, model=True)
            if val is not None:
                return val

            for alias_tup in sorted(set(alias_tups), key=lambda tup: tup[1], reverse=True):
                val = eval_loaded(alias_tup, model=True)
                if val is not None:
                    return val

        return None

    def _ctf_register_values(self):
        if self.project.arch.bits == 64:
            candidate_regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                              'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        elif self.project.arch.bits == 32:
            candidate_regs = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']
        else:
            candidate_regs = []

        reg_vals = []
        for reg in candidate_regs:
            if reg not in self.project.arch.registers:
                continue

            reg_off, size = self.project.arch.registers[reg]
            val = self._ctf_eval_register_tuple(reg, (reg_off, size))

            if val is not None and val >= 0:
                reg_vals.append((reg, (reg_off, size), val))

        return reg_vals

    def _ctf_canonical_reg_name(self, reg_name):
        if reg_name is None:
            return None

        reg_name = reg_name.lower()
        if self.project.arch.bits != 64:
            return reg_name

        aliases = {
            "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
            "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
            "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
            "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
            "esi": "rsi", "si": "rsi", "sil": "rsi",
            "edi": "rdi", "di": "rdi", "dil": "rdi",
            "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
            "esp": "rsp", "sp": "rsp", "spl": "rsp",
        }

        for reg in ("r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
            aliases[reg + "d"] = reg
            aliases[reg + "w"] = reg
            aliases[reg + "b"] = reg

        return aliases.get(reg_name, reg_name)

    @staticmethod
    def _ctf_is_reg_index_source(source_id):
        return isinstance(source_id, tuple) and len(source_id) >= 5 and source_id[0] == "reg_index"

    def _ctf_restore_reg_index_source(self):
        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        if self._ctf_is_reg_index_source(cur_source):
            return cur_source
        if cur_source is not None:
            return None

        cur_reg = self.state.globals.get("cur_vm_reg", None)
        source = None
        locked_source = self.state.globals.get("ctf_vpc_locked_source", None)
        if self._ctf_is_reg_index_source(locked_source) and (cur_reg is None or locked_source[1] == cur_reg):
            source = locked_source

        if source is None and cur_reg is not None:
            source = self.state.globals.get("ctf_reg_index_source_by_reg", {}).get(cur_reg, None)

        if not self._ctf_is_reg_index_source(source):
            return None

        self.state.globals["ctf_cur_vpc_source"] = source
        self.state.globals["ctf_cur_vpc_kind"] = "reg_index"
        self.state.globals["cur_vm_reg"] = source[1]
        return source

    def _ctf_reg_name_from_tup(self, reg_tup):
        if reg_tup is None:
            return None

        for reg_name, cur_reg_tup in self.project.arch.registers.items():
            if cur_reg_tup != reg_tup:
                continue

            canonical = self._ctf_canonical_reg_name(reg_name)
            if canonical == reg_name:
                return canonical

        for reg_name, cur_reg_tup, _ in self._ctf_register_values():
            if cur_reg_tup == reg_tup:
                return self._ctf_canonical_reg_name(reg_name)

        return None

    def _ctf_current_block_is_dispatcher_reg_write(self, reg_tup, source_id):
        if not isinstance(source_id, tuple) or len(source_id) < 5 or source_id[0] != "reg_index":
            return False

        target_reg = self._ctf_reg_name_from_tup(reg_tup)
        source_index_reg = self._ctf_reg_name_from_tup(source_id[1])
        bytecode_base_reg = source_id[2]
        if target_reg is None or source_index_reg is None or bytecode_base_reg is None:
            return False

        bbl = self.state.globals.get("cur_bbl", None)
        if bbl is None:
            return False

        capstone_insns = getattr(getattr(bbl, "capstone", None), "insns", None)
        disassembly = getattr(bbl, "disassembly", None)
        insns = capstone_insns or getattr(disassembly, "insns", [])
        bytecode_index_regs = set()

        for ins in insns:
            cap_insn = getattr(ins, "insn", ins)
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None:
                continue

            for operand in getattr(cap_insn, "operands", []):
                mem = getattr(operand, "mem", None)
                if mem is None or getattr(operand, "size", None) != 1:
                    continue

                base_reg = self._ctf_canonical_reg_name(reg_name_func(mem.base)) if getattr(mem, "base", 0) else None
                index_reg = self._ctf_canonical_reg_name(reg_name_func(mem.index)) if getattr(mem, "index", 0) else None
                if base_reg == bytecode_base_reg and index_reg is not None:
                    bytecode_index_regs.add(index_reg)

        if not bytecode_index_regs:
            return False
        if source_index_reg not in bytecode_index_regs:
            return False

        for ins in insns:
            cap_insn = getattr(ins, "insn", ins)
            operands = getattr(cap_insn, "operands", [])
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None or len(operands) < 2 or getattr(operands[0], "type", None) != 1:
                continue

            dest_reg = self._ctf_canonical_reg_name(reg_name_func(operands[0].reg))
            if dest_reg != target_reg:
                continue

            mnemonic = getattr(cap_insn, "mnemonic", "")
            src_regs = set()
            src_mem = getattr(operands[1], "mem", None)
            if src_mem is not None:
                if getattr(src_mem, "base", 0):
                    src_regs.add(self._ctf_canonical_reg_name(reg_name_func(src_mem.base)))
                if getattr(src_mem, "index", 0):
                    src_regs.add(self._ctf_canonical_reg_name(reg_name_func(src_mem.index)))
            elif getattr(operands[1], "type", None) == 1:
                src_regs.add(self._ctf_canonical_reg_name(reg_name_func(operands[1].reg)))

            if mnemonic in ("lea", "mov", "movsxd", "movzx") and source_index_reg in src_regs:
                return True

        return False

    def _ctf_current_block_self_clobbers_source(self, source_id):
        if not self._ctf_is_reg_index_source(source_id):
            return False

        index_reg = self._ctf_reg_name_from_tup(source_id[1])
        if index_reg is None:
            return False

        operand_info = self._ctf_indexed_memory_operands().get((source_id[2], index_reg, source_id[3]), None)
        return operand_info is not None and operand_info.get("byte_self_clobber", False)

    def _ctf_indexed_memory_operands(self):
        bbl = self.state.globals.get("cur_bbl", None)
        if bbl is None:
            return set()

        indexed_operands = {}
        reg_aliases = {}
        capstone_insns = getattr(getattr(bbl, "capstone", None), "insns", None)
        disassembly = getattr(bbl, "disassembly", None)

        def add_indexed_operand(key, score, insn_idx, byte_self_clobber=False):
            info = indexed_operands.get(key, {"score": 0, "byte_self_clobber": False, "first_insn_idx": None})
            info["score"] = max(info["score"], score)
            info["byte_self_clobber"] = info["byte_self_clobber"] or byte_self_clobber
            if info["first_insn_idx"] is None or insn_idx < info["first_insn_idx"]:
                info["first_insn_idx"] = insn_idx
            indexed_operands[key] = info

        def first_operand_is_written(operands, mnemonic):
            if not operands or getattr(operands[0], "type", None) != 1:
                return False

            access = getattr(operands[0], "access", None)
            if access:
                return bool(access & 2)

            return mnemonic not in {"cmp", "test", "jmp", "call", "push"}

        insns = capstone_insns or getattr(disassembly, "insns", [])
        dest_writes = []

        for insn_idx, ins in enumerate(insns):
            cap_insn = getattr(ins, "insn", ins)
            operands = getattr(cap_insn, "operands", [])
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None:
                continue

            mnemonic = getattr(cap_insn, "mnemonic", "")
            dest_reg = None
            if operands and getattr(operands[0], "type", None) == 1:
                dest_reg = self._ctf_canonical_reg_name(reg_name_func(operands[0].reg))
            dest_is_write = dest_reg is not None and first_operand_is_written(operands, mnemonic)
            if dest_is_write:
                dest_writes.append((insn_idx, dest_reg))

            for operand in operands:
                mem = getattr(operand, "mem", None)
                if mem is None or not getattr(mem, "base", 0) or not getattr(mem, "index", 0):
                    continue

                base_reg = self._ctf_canonical_reg_name(reg_name_func(mem.base))
                index_reg = self._ctf_canonical_reg_name(reg_name_func(mem.index))
                scale = getattr(mem, "scale", 1)
                if base_reg is None or index_reg is None:
                    continue

                byte_self_clobber = dest_reg == index_reg and getattr(operand, "size", None) == 1 and \
                    mnemonic in ("mov", "movsx", "movsxd", "movzx")
                add_indexed_operand(
                    (base_reg, index_reg, scale),
                    12,
                    insn_idx,
                    byte_self_clobber=byte_self_clobber,
                )

                alias_reg = reg_aliases.get(index_reg, None)
                if alias_reg is not None:
                    add_indexed_operand(
                        (base_reg, alias_reg, scale),
                        16,
                        insn_idx,
                        byte_self_clobber=byte_self_clobber,
                    )

            if not operands or getattr(operands[0], "type", None) != 1:
                continue

            dest_reg = self._ctf_canonical_reg_name(reg_name_func(operands[0].reg))
            if dest_reg is None:
                continue

            if len(operands) >= 2 and getattr(operands[1], "type", None) == 1 and \
                    getattr(cap_insn, "mnemonic", "") in ("mov", "movsxd", "movzx"):
                src_reg = self._ctf_canonical_reg_name(reg_name_func(operands[1].reg))
                reg_aliases[dest_reg] = reg_aliases.get(src_reg, src_reg)
            else:
                reg_aliases.pop(dest_reg, None)

        for key, info in indexed_operands.items():
            first_insn_idx = info.get("first_insn_idx", None)
            if first_insn_idx is None:
                continue

            index_reg = key[1]
            if any(write_idx > first_insn_idx and written_reg == index_reg for write_idx, written_reg in dest_writes):
                info["byte_self_clobber"] = True

        return indexed_operands

    def _ctf_region_for_addr(self, regions, addr):
        matching_regions = [region for region in regions if self._ctf_region_contains(region, addr)]
        if not matching_regions:
            return None

        return max(matching_regions, key=lambda region: region["delta"])

    def _ctf_mem_operand_addr(self, cap_insn, mem, reg_values):
        reg_name_func = getattr(cap_insn, "reg_name", None)
        if reg_name_func is None or mem is None:
            return None

        base = 0
        if getattr(mem, "base", 0):
            base_reg = self._ctf_canonical_reg_name(reg_name_func(mem.base))
            if base_reg == "rip":
                base = getattr(cap_insn, "address", 0) + getattr(cap_insn, "size", 0)
            else:
                base = reg_values.get(base_reg, None)
                if base is None:
                    return None

        index = 0
        if getattr(mem, "index", 0):
            index_reg = self._ctf_canonical_reg_name(reg_name_func(mem.index))
            index = reg_values.get(index_reg, None)
            if index is None:
                return None

        return base + (index * getattr(mem, "scale", 1)) + getattr(mem, "disp", 0)

    def _ctf_stack_index_uses(self, entropy_regions):
        if not entropy_regions:
            return {}

        bbl = self.state.globals.get("cur_bbl", None)
        if bbl is None:
            return {}

        reg_values = {reg: val for reg, _, val in self._ctf_register_values()}
        stack_aliases = {}
        region_aliases = {}
        index_uses = {}
        capstone_insns = getattr(getattr(bbl, "capstone", None), "insns", None)
        disassembly = getattr(bbl, "disassembly", None)

        def operand_reg(cap_insn, operand):
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None or getattr(operand, "type", None) != 1:
                return None
            return self._ctf_canonical_reg_name(reg_name_func(operand.reg))

        def operand_size(operand):
            return getattr(operand, "size", None) or self.project.arch.bytes

        def region_for_reg(reg_name):
            region_start = region_aliases.get(reg_name, None)
            if region_start is not None:
                return region_start

            reg_value = reg_values.get(reg_name, None)
            if reg_value is None:
                return None

            region = self._ctf_region_for_addr(entropy_regions, reg_value)
            return None if region is None else region["start"]

        def mark_stack_index(stack_slot, region_start, score):
            if stack_slot is None or region_start is None:
                return

            key = (stack_slot[0], stack_slot[1], region_start)
            index_uses[key] = max(index_uses.get(key, 0), score)

        def observe_indexed_mem(cap_insn, mem, score):
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None or mem is None:
                return

            base_reg = self._ctf_canonical_reg_name(reg_name_func(mem.base)) if getattr(mem, "base", 0) else None
            index_reg = self._ctf_canonical_reg_name(reg_name_func(mem.index)) if getattr(mem, "index", 0) else None
            if base_reg is None or index_reg is None:
                return

            mark_stack_index(stack_aliases.get(index_reg, None), region_for_reg(base_reg), score)
            mark_stack_index(stack_aliases.get(base_reg, None), region_for_reg(index_reg), score)

        for ins in capstone_insns or getattr(disassembly, "insns", []):
            cap_insn = getattr(ins, "insn", ins)
            operands = getattr(cap_insn, "operands", [])
            mnemonic = getattr(cap_insn, "mnemonic", "")
            if not operands:
                continue

            for operand in operands:
                observe_indexed_mem(cap_insn, getattr(operand, "mem", None), 22)

            dest_reg = operand_reg(cap_insn, operands[0])
            if dest_reg is None:
                continue

            if mnemonic in ("mov", "movsxd", "movzx", "movabs") and len(operands) >= 2:
                src = operands[1]
                src_reg = operand_reg(cap_insn, src)
                if src_reg is not None:
                    if src_reg in stack_aliases:
                        stack_aliases[dest_reg] = stack_aliases[src_reg]
                    else:
                        stack_aliases.pop(dest_reg, None)

                    if src_reg in region_aliases:
                        region_aliases[dest_reg] = region_aliases[src_reg]
                    else:
                        region_aliases.pop(dest_reg, None)
                    continue

                mem = getattr(src, "mem", None)
                if mem is not None:
                    addr = self._ctf_mem_operand_addr(cap_insn, mem, reg_values)
                    value = self._ctf_read_state_int(addr, operand_size(src))
                    region = self._ctf_region_for_addr(entropy_regions, value) if value is not None else None

                    if region is not None:
                        region_aliases[dest_reg] = region["start"]
                        stack_aliases.pop(dest_reg, None)
                    elif addr is not None and self._ctf_is_stack_addr(addr):
                        stack_aliases[dest_reg] = (addr, operand_size(src))
                        region_aliases.pop(dest_reg, None)
                    else:
                        stack_aliases.pop(dest_reg, None)
                        region_aliases.pop(dest_reg, None)
                    continue

            if mnemonic == "lea" and len(operands) >= 2:
                mem = getattr(operands[1], "mem", None)
                observe_indexed_mem(cap_insn, mem, 26)

                addr = self._ctf_mem_operand_addr(cap_insn, mem, reg_values)
                region = self._ctf_region_for_addr(entropy_regions, addr) if addr is not None else None
                if region is not None:
                    region_aliases[dest_reg] = region["start"]
                    stack_aliases.pop(dest_reg, None)
                else:
                    stack_aliases.pop(dest_reg, None)
                    region_aliases.pop(dest_reg, None)
                continue

            if mnemonic in ("add", "sub") and len(operands) >= 2:
                src_reg = operand_reg(cap_insn, operands[1])
                if src_reg is None:
                    stack_aliases.pop(dest_reg, None)
                    region_aliases.pop(dest_reg, None)
                    continue

                dest_region = region_for_reg(dest_reg)
                src_region = region_for_reg(src_reg)
                dest_stack = stack_aliases.get(dest_reg, None)
                src_stack = stack_aliases.get(src_reg, None)

                mark_stack_index(src_stack, dest_region, 28)
                mark_stack_index(dest_stack, src_region, 28)

                if dest_region is not None:
                    region_aliases[dest_reg] = dest_region
                    stack_aliases.pop(dest_reg, None)
                elif src_region is not None:
                    region_aliases[dest_reg] = src_region
                    stack_aliases.pop(dest_reg, None)
                else:
                    stack_aliases.pop(dest_reg, None)
                    region_aliases.pop(dest_reg, None)

        return index_uses

    def _ctf_stack_pointer_uses(self, entropy_regions):
        if not entropy_regions:
            return {}

        bbl = self.state.globals.get("cur_bbl", None)
        if bbl is None:
            return {}

        reg_values = {reg: val for reg, _, val in self._ctf_register_values()}
        stack_aliases = {}
        region_aliases = {}
        pointer_aliases = {}
        pointer_uses = {}
        capstone_insns = getattr(getattr(bbl, "capstone", None), "insns", None)
        disassembly = getattr(bbl, "disassembly", None)

        def operand_reg(cap_insn, operand):
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None or getattr(operand, "type", None) != 1:
                return None
            return self._ctf_canonical_reg_name(reg_name_func(operand.reg))

        def operand_size(operand):
            return getattr(operand, "size", None) or self.project.arch.bytes

        def region_for_reg(reg_name):
            region_start = region_aliases.get(reg_name, None)
            if region_start is not None:
                return region_start

            reg_value = reg_values.get(reg_name, None)
            if reg_value is None:
                return None

            region = self._ctf_region_for_addr(entropy_regions, reg_value)
            return None if region is None else region["start"]

        def mark_pointer_use(stack_slot, region_start, score):
            if stack_slot is None or region_start is None:
                return

            key = (stack_slot[0], stack_slot[1], region_start)
            pointer_uses[key] = max(pointer_uses.get(key, 0), score)

        def observe_pointer_mem(cap_insn, mem, score):
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None or mem is None:
                return

            base_reg = self._ctf_canonical_reg_name(reg_name_func(mem.base)) if getattr(mem, "base", 0) else None
            if base_reg is None:
                return

            stack_slot = pointer_aliases.get(base_reg, None)
            region_start = region_for_reg(base_reg)
            if stack_slot is not None and region_start is not None:
                mark_pointer_use(stack_slot, region_start, score)

        for ins in capstone_insns or getattr(disassembly, "insns", []):
            cap_insn = getattr(ins, "insn", ins)
            operands = getattr(cap_insn, "operands", [])
            mnemonic = getattr(cap_insn, "mnemonic", "")
            if not operands:
                continue

            for operand in operands:
                observe_pointer_mem(cap_insn, getattr(operand, "mem", None), 36)

            dest_reg = operand_reg(cap_insn, operands[0])
            if dest_reg is None:
                continue

            if mnemonic in ("mov", "movsxd", "movzx", "movabs") and len(operands) >= 2:
                src = operands[1]
                src_reg = operand_reg(cap_insn, src)
                if src_reg is not None:
                    if src_reg in stack_aliases:
                        stack_aliases[dest_reg] = stack_aliases[src_reg]
                    else:
                        stack_aliases.pop(dest_reg, None)

                    if src_reg in region_aliases:
                        region_aliases[dest_reg] = region_aliases[src_reg]
                    else:
                        region_aliases.pop(dest_reg, None)

                    if src_reg in pointer_aliases:
                        pointer_aliases[dest_reg] = pointer_aliases[src_reg]
                    else:
                        pointer_aliases.pop(dest_reg, None)
                    continue

                mem = getattr(src, "mem", None)
                if mem is not None:
                    addr = self._ctf_mem_operand_addr(cap_insn, mem, reg_values)
                    value = self._ctf_read_state_int(addr, operand_size(src))
                    region = self._ctf_region_for_addr(entropy_regions, value) if value is not None else None

                    if region is not None:
                        stack_slot = (addr, operand_size(src)) if addr is not None and self._ctf_is_stack_addr(addr) else None
                        region_aliases[dest_reg] = region["start"]
                        if stack_slot is not None:
                            pointer_aliases[dest_reg] = stack_slot
                        else:
                            pointer_aliases.pop(dest_reg, None)
                        stack_aliases.pop(dest_reg, None)
                    elif addr is not None and self._ctf_is_stack_addr(addr):
                        stack_aliases[dest_reg] = (addr, operand_size(src))
                        region_aliases.pop(dest_reg, None)
                        pointer_aliases.pop(dest_reg, None)
                    else:
                        stack_aliases.pop(dest_reg, None)
                        region_aliases.pop(dest_reg, None)
                        pointer_aliases.pop(dest_reg, None)
                    continue

            if mnemonic == "lea" and len(operands) >= 2:
                mem = getattr(operands[1], "mem", None)
                observe_pointer_mem(cap_insn, mem, 32)

                addr = self._ctf_mem_operand_addr(cap_insn, mem, reg_values)
                region = self._ctf_region_for_addr(entropy_regions, addr) if addr is not None else None
                base_reg = self._ctf_canonical_reg_name(cap_insn.reg_name(mem.base)) if mem is not None and getattr(mem, "base", 0) else None
                if region is not None:
                    region_aliases[dest_reg] = region["start"]
                    if base_reg in pointer_aliases:
                        pointer_aliases[dest_reg] = pointer_aliases[base_reg]
                    else:
                        pointer_aliases.pop(dest_reg, None)
                    stack_aliases.pop(dest_reg, None)
                else:
                    stack_aliases.pop(dest_reg, None)
                    region_aliases.pop(dest_reg, None)
                    pointer_aliases.pop(dest_reg, None)
                continue

            if mnemonic in ("add", "sub") and len(operands) >= 2:
                dest_region = region_for_reg(dest_reg)
                if dest_region is not None and dest_reg in pointer_aliases:
                    region_aliases[dest_reg] = dest_region
                else:
                    region_aliases.pop(dest_reg, None)
                    pointer_aliases.pop(dest_reg, None)
                stack_aliases.pop(dest_reg, None)

        return pointer_uses

    def _ctf_stack_raw_index_uses(self):
        bbl = self.state.globals.get("cur_bbl", None)
        if bbl is None:
            return {}

        reg_values = {reg: val for reg, _, val in self._ctf_register_values()}
        stack_aliases = {}
        pointer_aliases = {}
        raw_uses = {}
        capstone_insns = getattr(getattr(bbl, "capstone", None), "insns", None)
        disassembly = getattr(bbl, "disassembly", None)

        def operand_reg(cap_insn, operand):
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None or getattr(operand, "type", None) != 1:
                return None
            return self._ctf_canonical_reg_name(reg_name_func(operand.reg))

        def operand_size(operand):
            return getattr(operand, "size", None) or self.project.arch.bytes

        def mark_raw_index(stack_slot, base_addr, score):
            if stack_slot is None or not self._ctf_is_likely_bytecode_base(base_addr):
                return
            key = (stack_slot[0], stack_slot[1])
            info = raw_uses.get(key, {"score": 0, "base": base_addr})
            info["score"] = max(info["score"], score)
            info["base"] = base_addr
            raw_uses[key] = info

        def observe_indexed_mem(cap_insn, mem, score):
            reg_name_func = getattr(cap_insn, "reg_name", None)
            if reg_name_func is None or mem is None:
                return

            base_reg = self._ctf_canonical_reg_name(reg_name_func(mem.base)) if getattr(mem, "base", 0) else None
            index_reg = self._ctf_canonical_reg_name(reg_name_func(mem.index)) if getattr(mem, "index", 0) else None

            if base_reg is not None and index_reg is not None:
                mark_raw_index(stack_aliases.get(index_reg, None), reg_values.get(base_reg, None), score)
                mark_raw_index(stack_aliases.get(base_reg, None), reg_values.get(index_reg, None), score)
                if base_reg in pointer_aliases:
                    mark_raw_index(stack_aliases.get(index_reg, None), pointer_aliases[base_reg], score + 4)
                if index_reg in pointer_aliases:
                    mark_raw_index(stack_aliases.get(base_reg, None), pointer_aliases[index_reg], score + 4)

            if base_reg in pointer_aliases:
                mark_raw_index(stack_aliases.get(index_reg, None), pointer_aliases[base_reg], score)
            if index_reg in pointer_aliases:
                mark_raw_index(stack_aliases.get(base_reg, None), pointer_aliases[index_reg], score)

        def clear_aliases(reg_name):
            stack_aliases.pop(reg_name, None)
            pointer_aliases.pop(reg_name, None)

        for ins in capstone_insns or getattr(disassembly, "insns", []):
            cap_insn = getattr(ins, "insn", ins)
            operands = getattr(cap_insn, "operands", [])
            mnemonic = getattr(cap_insn, "mnemonic", "")
            if not operands:
                continue

            for operand in operands:
                observe_indexed_mem(cap_insn, getattr(operand, "mem", None), 24)

            dest_reg = operand_reg(cap_insn, operands[0])
            if dest_reg is None:
                continue

            if mnemonic in ("mov", "movsxd", "movzx", "movabs") and len(operands) >= 2:
                src = operands[1]
                src_reg = operand_reg(cap_insn, src)
                if src_reg is not None:
                    if src_reg in stack_aliases:
                        stack_aliases[dest_reg] = stack_aliases[src_reg]
                    else:
                        stack_aliases.pop(dest_reg, None)

                    if src_reg in pointer_aliases:
                        pointer_aliases[dest_reg] = pointer_aliases[src_reg]
                    else:
                        pointer_aliases.pop(dest_reg, None)
                    continue

                mem = getattr(src, "mem", None)
                if mem is not None:
                    addr = self._ctf_mem_operand_addr(cap_insn, mem, reg_values)
                    value = self._ctf_read_state_int(addr, operand_size(src))
                    if addr is not None and self._ctf_is_stack_addr(addr):
                        if self._ctf_is_likely_bytecode_base(value):
                            pointer_aliases[dest_reg] = value
                            stack_aliases.pop(dest_reg, None)
                        else:
                            stack_aliases[dest_reg] = (addr, operand_size(src))
                            pointer_aliases.pop(dest_reg, None)
                    else:
                        clear_aliases(dest_reg)
                    continue

            if mnemonic == "lea" and len(operands) >= 2:
                observe_indexed_mem(cap_insn, getattr(operands[1], "mem", None), 30)
                clear_aliases(dest_reg)
                continue

            if mnemonic in ("add", "sub") and len(operands) >= 2:
                src_reg = operand_reg(cap_insn, operands[1])
                if src_reg is not None:
                    if dest_reg in pointer_aliases:
                        mark_raw_index(stack_aliases.get(src_reg, None), pointer_aliases[dest_reg], 32)
                    if src_reg in pointer_aliases:
                        mark_raw_index(stack_aliases.get(dest_reg, None), pointer_aliases[src_reg], 32)
                clear_aliases(dest_reg)
                continue

            clear_aliases(dest_reg)

        return raw_uses

    def _ctf_is_likely_bytecode_base(self, addr):
        if addr is None or addr < 0x1000 or self._ctf_is_stack_addr(addr):
            return False
        sec = self.state.project.loader.main_object.find_section_containing(addr) \
            if self.state.project.loader.main_object.contains_addr(addr) else None
        return sec is not None and not getattr(sec, "is_executable", False)

    def _ctf_note_stack_raw_base_store(self, value):
        if not self._ctf_is_likely_bytecode_base(value):
            return

        self.state.globals["ctf_stack_raw_pending_base"] = value

    def _ctf_stack_raw_known_slots(self):
        known_slots = set()
        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        if isinstance(cur_source, tuple) and len(cur_source) >= 3 and cur_source[0] == "stack_store_raw_offset":
            known_slots.add((cur_source[1], cur_source[2]))

        known_slots.update(self.state.globals.get("ctf_stack_raw_source_by_slot", {}).keys())
        return known_slots

    def _ctf_stack_raw_slot_allowed(self, addr, size):
        known_slots = self._ctf_stack_raw_known_slots()
        return not known_slots or (addr, size) in known_slots

    def _ctf_stack_raw_info_for_slot(self, addr, size):
        pending_base = self.state.globals.get("ctf_stack_raw_pending_base", None)

        def with_pending_base(raw_info):
            if raw_info is None:
                return None
            raw_info = dict(raw_info)
            if self._ctf_is_likely_bytecode_base(pending_base) and raw_info.get("base", None) != pending_base:
                raw_info["base"] = pending_base
                raw_info["score"] = raw_info.get("score", 0) + getattr(
                    self.project, "ctf_vpc_stack_raw_pending_base_score", 24
                )
            return raw_info

        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        if isinstance(cur_source, tuple) and len(cur_source) >= 4 and \
                cur_source[0] == "stack_store_raw_offset" and cur_source[1] == addr and cur_source[2] == size:
            return with_pending_base({
                "base": cur_source[3],
                "score": getattr(self.project, "ctf_vpc_stack_raw_current_source_score", 32),
            })

        source_by_slot = self.state.globals.get("ctf_stack_raw_source_by_slot", {})
        raw_info = source_by_slot.get((addr, size), None)
        if isinstance(raw_info, dict):
            return with_pending_base(raw_info)
        if raw_info is not None:
            return with_pending_base({
                "base": raw_info,
                "score": getattr(self.project, "ctf_vpc_stack_raw_cached_source_score", 16),
            })

        return None

    def _ctf_remember_stack_raw_source(self, candidate):
        if candidate.get("kind", None) != "stack_store_raw_offset":
            return

        source_id = candidate.get("source_id", None)
        if not isinstance(source_id, tuple) or len(source_id) < 4:
            return

        source_by_slot = dict(self.state.globals.get("ctf_stack_raw_source_by_slot", {}))
        source_by_slot[(source_id[1], source_id[2])] = {
            "base": source_id[3],
            "score": getattr(self.project, "ctf_vpc_stack_raw_cached_source_score", 16),
        }
        self.state.globals["ctf_stack_raw_source_by_slot"] = source_by_slot

    @staticmethod
    def _ctf_stack_source_slot(source_id):
        if not isinstance(source_id, tuple) or len(source_id) < 3:
            return None

        if source_id[0] not in {
                "stack_ptr",
                "stack_store_ptr",
                "stack_offset",
                "stack_store_offset",
                "stack_store_raw_offset",
        }:
            return None

        return source_id[1], source_id[2]

    def _ctf_stack_store_ptr_candidates_for_current_source(self, candidates):
        stack_store_ptr_candidates = [
            cand for cand in candidates
            if cand.get("kind", None) == "stack_store_ptr"
        ]
        if not stack_store_ptr_candidates:
            return []

        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        if self.state.globals.get("ctf_cur_vpc_kind", None) != "stack_store_ptr" or cur_source is None or \
                not self.state.globals.get("ctf_stack_store_ptr_source_confirmed", False):
            return stack_store_ptr_candidates

        cur_slot = self._ctf_stack_source_slot(cur_source)
        if cur_slot is None:
            return stack_store_ptr_candidates

        return [
            cand for cand in stack_store_ptr_candidates
            if self._ctf_stack_source_slot(cand.get("source_id", None)) == cur_slot
        ]

    def _ctf_stack_store_ptr_region_for_source(self, source_id):
        if not isinstance(source_id, tuple) or len(source_id) < 4 or source_id[0] != "stack_store_ptr":
            return None

        region_start = source_id[3]
        return {
            "start": region_start,
            "end": region_start + getattr(self.project, "ctf_dynamic_region_size", 0x1000),
            "entropy": 0,
            "delta": 0,
            "kind": "locked",
        }

    def _ctf_try_stack_store_ptr_fast_path(self, addr, size, value):
        if not self._ctf_stack_store_ptr_mode_enabled("fast_path"):
            return False

        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        if self.state.globals.get("ctf_cur_vpc_kind", None) != "stack_store_ptr" or cur_source is None:
            return False

        cur_slot = self._ctf_stack_source_slot(cur_source)
        if cur_slot != (addr, size):
            return self.state.globals.get("ctf_stack_store_ptr_source_confirmed", False) and \
                getattr(self.project, "ctf_vpc_stack_store_ptr_skip_non_current_stores", True)

        region = self._ctf_stack_store_ptr_region_for_source(cur_source)
        if region is None or not self._ctf_region_contains(region, value):
            return False

        self._ctf_commit_candidate({
            "source_id": cur_source,
            "value": value,
            "score": getattr(self.project, "ctf_vpc_stack_store_ptr_fast_path_score", 80),
            "kind": "stack_store_ptr",
            "reg_tup": None,
            "origin": "stack_store_fast",
            "region": region,
        })
        return True

    def _ctf_try_stack_store_ptr_block_fast_path(self):
        if not self._ctf_stack_store_ptr_mode_enabled("block_fast_path"):
            return False

        if self.state.globals.get("ctf_cur_vpc_kind", None) != "stack_store_ptr":
            return False

        if not self.state.globals.get("ctf_vpc_stack_store_ptr_updated_in_block", False):
            return False

        if not self.state.globals.get("ctf_stack_store_ptr_source_confirmed", False) and not \
                self._ctf_stack_store_ptr_mode_enabled("allow_unconfirmed_block_fast_path"):
            return False

        return True

    def _ctf_try_stack_store_ptr_store_only_fast_path(self):
        if not self._ctf_stack_store_ptr_mode_enabled("store_only"):
            return False

        if self.state.globals.get("ctf_cur_vpc_kind", None) != "stack_store_ptr":
            return False

        if self.state.globals.get("ctf_cur_vpc_source", None) is None:
            return False

        if not self.state.globals.get("ctf_stack_store_ptr_source_confirmed", False) and not \
                self._ctf_stack_store_ptr_mode_enabled("allow_unconfirmed_store_only"):
            return False

        return True

    def _ctf_add_stack_raw_slot_candidate(self, candidates, addr, size, raw_info, origin, base_score):
        if raw_info is None:
            return

        value = self._ctf_read_state_int(addr, size)
        if value is None or value < 0 or value > getattr(self.project, "ctf_vpc_max_index", 0x100000):
            return

        base_addr = raw_info.get("base", None)
        namespace_bias = self._ctf_stack_raw_namespace_bias(base_addr, value)
        self._ctf_add_candidate(
            candidates,
            ("stack_store_raw_offset", addr, size, base_addr),
            namespace_bias + value,
            base_score + raw_info.get("score", 0),
            "stack_store_raw_offset",
            origin=origin,
        )

    def _ctf_stack_raw_slot_candidates(self):
        if not getattr(self.project, "ctf_vpc_allow_stack_store_raw_offset", False):
            return []

        candidates = []
        seen = set()
        seen_slots = set()
        raw_index_uses = self._ctf_stack_raw_index_uses()
        for (addr, size), raw_info in raw_index_uses.items():
            if not self._ctf_stack_raw_slot_allowed(addr, size):
                continue
            self._ctf_add_stack_raw_slot_candidate(
                candidates,
                addr,
                size,
                raw_info,
                "stack_slot_use",
                getattr(self.project, "ctf_vpc_stack_raw_slot_score", 28),
            )
            seen.add((addr, size, raw_info.get("base", None)))
            seen_slots.add((addr, size))

        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        if isinstance(cur_source, tuple) and len(cur_source) >= 4 and cur_source[0] == "stack_store_raw_offset":
            raw_info = self._ctf_stack_raw_info_for_slot(cur_source[1], cur_source[2])
            key = (cur_source[1], cur_source[2], cur_source[3])
            if key not in seen and (cur_source[1], cur_source[2]) not in seen_slots:
                self._ctf_add_stack_raw_slot_candidate(
                    candidates,
                    cur_source[1],
                    cur_source[2],
                    raw_info,
                    "stack_slot_current",
                    getattr(self.project, "ctf_vpc_stack_raw_current_slot_score", 36),
                )
                seen.add(key)

        for (addr, size), raw_info in self.state.globals.get("ctf_stack_raw_source_by_slot", {}).items():
            if not isinstance(raw_info, dict):
                raw_info = {"base": raw_info, "score": 0}
            key = (addr, size, raw_info.get("base", None))
            if key in seen or (addr, size) in seen_slots:
                continue
            self._ctf_add_stack_raw_slot_candidate(
                candidates,
                addr,
                size,
                raw_info,
                "stack_slot_cached",
                getattr(self.project, "ctf_vpc_stack_raw_cached_slot_score", 18),
            )

        return candidates

    def _ctf_stack_raw_namespace_bias(self, base_addr, value):
        if base_addr is None or not getattr(self.project, "ctf_vpc_stack_raw_compact_namespaces", True):
            return 0

        offsets = dict(self.state.globals.get("ctf_stack_raw_base_offsets", {}))
        max_values = dict(self.state.globals.get("ctf_stack_raw_base_max_values", {}))

        if base_addr not in offsets:
            if not offsets:
                offsets[base_addr] = 0
            else:
                next_offset = max(
                    offsets[known_base] + max_values.get(known_base, 0) + 1
                    for known_base in offsets
                )
                if getattr(self.project, "ctf_vpc_stack_raw_round_namespaces", True):
                    boundary = self._ctf_stack_raw_next_namespace_boundary(next_offset)
                    next_offset = max(next_offset, boundary - 1)
                offsets[base_addr] = next_offset

        max_values[base_addr] = max(max_values.get(base_addr, value), value)
        self.state.globals["ctf_stack_raw_base_offsets"] = offsets
        self.state.globals["ctf_stack_raw_base_max_values"] = max_values
        return offsets[base_addr]

    @staticmethod
    def _ctf_stack_raw_next_namespace_boundary(value):
        boundary = 10
        while boundary < value:
            boundary *= 10
        return boundary

    def _ctf_text_entropy(self):
        if hasattr(self.project, "_ctf_text_entropy"):
            return self.project._ctf_text_entropy

        text_entropy = 0
        text_size = 0
        for sec in self.project.loader.main_object.sections:
            sec_name = getattr(sec, "name", "")
            is_executable = getattr(sec, "is_executable", False)
            if not is_executable and sec_name != ".text":
                continue

            start = getattr(sec, "vaddr", None)
            size = getattr(sec, "memsize", getattr(sec, "filesize", 0))
            if start is None or size <= 0:
                continue

            try:
                data = self.project.loader.memory.load(start, min(size, 0x4000))
            except Exception:
                continue

            if len(data) > text_size:
                text_entropy = self._calc_entropy(data, len(data))
                text_size = len(data)

        self.project._ctf_text_entropy = text_entropy
        return text_entropy

    def _ctf_merge_regions(self, regions):
        merged = []
        for region in sorted(regions, key=lambda r: (r["start"], r["end"])):
            if not merged or region["start"] > merged[-1]["end"] + 0x80:
                merged.append(dict(region))
                continue

            merged[-1]["end"] = max(merged[-1]["end"], region["end"])
            merged[-1]["delta"] = max(merged[-1]["delta"], region["delta"])
            merged[-1]["entropy"] = max(merged[-1]["entropy"], region["entropy"])

        return merged

    def _ctf_static_entropy_regions(self):
        if hasattr(self.project, "_ctf_static_entropy_regions"):
            return self.project._ctf_static_entropy_regions

        text_entropy = self._ctf_text_entropy()
        delta_threshold = getattr(
            self.project,
            "ctf_dynamic_entropy_delta_threshold",
            min(getattr(self.project, "ctf_entropy_delta_threshold", 0.75), 0.10),
        )
        regions = []

        for region in self.project.byte_code_regions or []:
            start, end = region
            if end > start:
                regions.append({
                    "start": start,
                    "end": end,
                    "entropy": 0,
                    "delta": 8,
                    "kind": "explicit",
                })

        for sec in self.project.loader.main_object.sections:
            if getattr(sec, "is_executable", False):
                continue

            start = getattr(sec, "vaddr", None)
            size = getattr(sec, "memsize", getattr(sec, "filesize", 0))
            if start is None or size <= 0:
                continue

            try:
                data = self.project.loader.memory.load(start, size)
            except Exception:
                continue

            if not data:
                continue

            if len(data) < 0x100:
                windows = [(0, data)]
            else:
                windows = []
                for off in range(0, len(data) - 0x100 + 1, 0x40):
                    windows.append((off, data[off:off + 0x100]))

            for off, chunk in windows:
                if len(chunk) < 0x20 or len(set(chunk)) <= 2:
                    continue

                entropy = self._calc_entropy(chunk, len(chunk))
                delta = abs(entropy - text_entropy)
                if delta < delta_threshold:
                    continue

                regions.append({
                    "start": start + off,
                    "end": start + off + len(chunk),
                    "entropy": entropy,
                    "delta": delta,
                    "kind": "static",
                })

        self.project._ctf_static_entropy_regions = self._ctf_merge_regions(regions)
        return self.project._ctf_static_entropy_regions

    def _ctf_is_stack_addr(self, addr):
        if addr is None:
            return False

        sp_start = self.state.globals.get("sp_start_value", None)
        if sp_start is None:
            try:
                sp_start = self._ctf_eval_one(self.state.regs.sp)
            except Exception:
                sp_start = None

        return sp_start is not None and abs(addr - sp_start) < 0x100000

    def _ctf_dynamic_entropy_regions(self, reg_vals, stack_words):
        text_entropy = self._ctf_text_entropy()
        delta_threshold = getattr(self.project, "ctf_entropy_delta_threshold", 0.75)
        base_addrs = set()

        for _, _, val in reg_vals:
            base_addrs.add(val)
        for word in stack_words:
            base_addrs.add(word["value"])

        regions = []
        for addr in base_addrs:
            sec = self.state.project.loader.main_object.find_section_containing(addr) \
                if self.state.project.loader.main_object.contains_addr(addr) else None
            if addr < 0x1000 or self._ctf_is_stack_addr(addr) or (sec is not None and getattr(sec, "is_executable", False)):
                continue

            data = self._ctf_read_state_bytes(addr, 0x100)
            if not data or len(set(data)) <= 2:
                continue

            entropy = self._calc_entropy(data, len(data))
            delta = abs(entropy - text_entropy)
            if delta < delta_threshold:
                continue

            regions.append({
                "start": addr,
                "end": addr + getattr(self.project, "ctf_dynamic_region_size", 0x1000),
                "entropy": entropy,
                "delta": delta,
                "kind": "dynamic",
            })

        return self._ctf_merge_regions(regions)

    def _ctf_locked_entropy_regions(self):
        if not getattr(self.project, "ctf_vpc_use_locked_regions", True):
            return []

        return [dict(region) for region in self.state.globals.get("ctf_vpc_locked_regions", [])]

    def _ctf_entropy_regions(self, reg_vals=None, stack_words=None, use_locked=True):
        locked_regions = self._ctf_locked_entropy_regions() if use_locked else []
        if locked_regions:
            return locked_regions

        if reg_vals is None:
            reg_vals = self._ctf_register_values()
        if stack_words is None:
            stack_words = self._ctf_stack_words()

        return self._ctf_static_entropy_regions() + self._ctf_dynamic_entropy_regions(reg_vals, stack_words)

    def _ctf_stack_words(self):
        anchors = []
        for reg in ("sp", "bp", "rsp", "rbp", "esp", "ebp"):
            if reg not in self.project.arch.registers:
                continue

            reg_off, size = self.project.arch.registers[reg]
            val = self._ctf_eval_one(self.state.registers.load(reg_off, size))
            if val is not None and self._ctf_is_stack_addr(val):
                anchors.append((reg, val))

        stack_words = []
        seen = set()
        word_sizes = [4]
        if self.project.arch.bytes != 4:
            word_sizes.append(self.project.arch.bytes)

        window = getattr(self.project, "ctf_vpc_stack_scan_size", 0x80)
        for anchor_reg, anchor in anchors:
            for addr in range(anchor - window, anchor + window + 1, 4):
                if addr < 0:
                    continue
                for size in word_sizes:
                    key = (addr, size)
                    if key in seen:
                        continue
                    seen.add(key)

                    value = self._ctf_read_state_int(addr, size)
                    if value is None or value < 0:
                        continue

                    stack_words.append({
                        "addr": addr,
                        "size": size,
                        "value": value,
                        "anchor": anchor_reg,
                    })

        return stack_words

    @staticmethod
    def _ctf_region_contains(region, addr):
        return region["start"] <= addr < region["end"]

    def _ctf_region_biases(self, regions):
        stride = getattr(self.project, "ctf_vpc_region_stride", 0x10000)
        starts = sorted({region["start"] for region in regions})
        return {start: idx * stride for idx, start in enumerate(starts)}

    def _ctf_fd_positions(self):
        fd_store = getattr(self.state.posix, "fd", None)
        if fd_store is None:
            return []

        try:
            fd_items = fd_store.items()
        except AttributeError:
            try:
                fd_items = enumerate(fd_store)
            except TypeError:
                return []

        positions = []
        for fd_no, fd in fd_items:
            if fd is None or not hasattr(fd, "read_pos"):
                continue

            pos = self._ctf_eval_one(fd.read_pos)
            if pos is None or pos < 0:
                continue

            positions.append((fd_no, pos))

        return positions

    def _ctf_fd_position_map(self):
        return {fd_no: pos for fd_no, pos in self._ctf_fd_positions()}

    def _ctf_fd_read_pos_namespace_active(self, pos):
        stride = getattr(self.project, "ctf_vpc_fd_read_pos_namespace_stride", 0)
        if not stride:
            return False

        namespace_addrs = getattr(self.project, "ctf_vpc_fd_read_pos_namespace_addrs", None)
        if namespace_addrs:
            bbl = self.state.globals.get("cur_bbl", None)
            bbl_addr = getattr(bbl, "addr", None)
            namespace_addrs = set(namespace_addrs)
            insn_addrs = {
                getattr(insn, "address", None)
                for insn in getattr(getattr(bbl, "disassembly", None), "insns", [])
            }
            if bbl_addr not in namespace_addrs and not (insn_addrs & namespace_addrs):
                return False

        modulus = getattr(self.project, "ctf_vpc_fd_read_pos_namespace_modulus", None)
        if modulus is not None:
            if modulus <= 0 or pos % modulus != 0:
                return False

        return True

    def _ctf_fd_read_pos_value(self, pos):
        if self._ctf_fd_read_pos_namespace_active(pos):
            return pos + getattr(self.project, "ctf_vpc_fd_read_pos_namespace_stride", 0)

        return pos

    def _ctf_note_fd_read_pos_candidates(self, candidates):
        if not self._ctf_fd_read_pos_mode_enabled("candidate"):
            return

        positions = self._ctf_fd_position_map()
        if not positions:
            return

        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        history = dict(self.state.globals.get("ctf_fd_read_pos_history", {}))
        changed_sources = set()
        nonzero_positions = [(fd_no, pos) for fd_no, pos in positions.items() if pos != 0]

        for fd_no, pos in positions.items():
            old = history.get(fd_no, {})
            if old and old.get("pos", None) != pos:
                changed_sources.add(("fd_read_pos", fd_no))
                old["changes"] = min(old.get("changes", 0) + 1, 255)
            old["pos"] = pos
            old["seen"] = min(old.get("seen", 0) + 1, 255)
            history[fd_no] = old

        self.state.globals["ctf_fd_read_pos_history"] = history

        for fd_no, pos in positions.items():
            source_id = ("fd_read_pos", fd_no)
            if pos == 0 and source_id != cur_source:
                continue

            hist = history.get(fd_no, {})
            score = 13 + min(hist.get("changes", 0), 8) * 4
            origin = "fd_read_pos"
            if source_id in changed_sources:
                score += 12
                origin = "fd_read_pos_changed"
            elif source_id == cur_source:
                score += 16
                origin = "fd_read_pos_current"
            elif hist.get("changes", 0) == 0:
                if len(nonzero_positions) != 1 or not self._ctf_fd_read_pos_mode_enabled("allow_initial"):
                    continue
                if getattr(self.project, "ctf_vpc_fd_read_pos_initial_requires_namespace", False) and \
                        not self._ctf_fd_read_pos_namespace_active(pos):
                    continue
                score -= 2
                origin = "fd_read_pos_initial"

            self._ctf_add_candidate(
                candidates,
                source_id,
                self._ctf_fd_read_pos_value(pos),
                score,
                "fd_read_pos",
                origin=origin,
                raw_value=pos,
            )

    def _ctf_fd_read_pos_candidates_for_current_source(self, candidates):
        fd_candidates = [
            cand for cand in candidates
            if cand.get("kind", None) == "fd_read_pos"
        ]
        if not fd_candidates:
            return []

        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        if self.state.globals.get("ctf_cur_vpc_kind", None) != "fd_read_pos" or cur_source is None:
            return fd_candidates

        current_fd_candidates = [
            cand for cand in fd_candidates
            if cand.get("source_id", None) == cur_source
        ]
        return current_fd_candidates

    def _ctf_try_fd_read_pos_fast_path(self):
        if not self._ctf_fd_read_pos_mode_enabled("fast_path"):
            return False

        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        if self.state.globals.get("ctf_cur_vpc_kind", None) != "fd_read_pos" or \
                not isinstance(cur_source, tuple) or len(cur_source) != 2:
            return False

        positions = self._ctf_fd_position_map()
        if cur_source[1] not in positions:
            return False

        pos = positions[cur_source[1]]
        value = self._ctf_fd_read_pos_value(pos)
        raw_value = self.state.globals.get("ctf_fd_read_pos_raw_value", None)
        cur_vpc = self.state.globals.get("cur_vm_vpc", None)
        if raw_value == pos and value == pos and cur_vpc is not None and cur_vpc != pos:
            self.state.globals["vpc"] = cur_vpc
            return True

        candidate = {
            "source_id": cur_source,
            "value": value,
            "score": getattr(self.project, "ctf_vpc_fd_read_pos_fast_path_score", 80),
            "kind": "fd_read_pos",
            "reg_tup": None,
            "origin": "fd_read_pos_fast",
            "region": None,
            "raw_value": pos,
        }
        self._ctf_commit_candidate(candidate)
        return True

    def _ctf_add_candidate(
            self, candidates, source_id, value, score, kind, reg_tup=None, origin=None, region=None, raw_value=None):
        if value is None or value < 0:
            return
        allow_zero_reg_index = kind == "reg_index" and region is not None and getattr(
            self.project, "ctf_vpc_allow_zero_reg_index", True
        )
        allow_zero_stack_raw = kind == "stack_store_raw_offset" and getattr(
            self.project, "ctf_vpc_allow_zero_stack_raw_offset", True
        )
        if value == 0 and not (
                getattr(self.project, "ctf_vpc_allow_zero", False) or allow_zero_reg_index or allow_zero_stack_raw):
            return

        candidates.append({
            "source_id": source_id,
            "value": value,
            "score": score,
            "kind": kind,
            "reg_tup": reg_tup,
            "origin": origin,
            "region": dict(region) if region is not None else None,
            "raw_value": raw_value,
        })

    def _ctf_region_for_candidate(self, candidate):
        region = candidate.get("region", None)
        if region is not None:
            return dict(region)

        source_id = candidate.get("source_id", None)
        if not isinstance(source_id, tuple):
            return None

        region_start = None
        if source_id and source_id[0] == "reg_index" and len(source_id) >= 5:
            region_start = source_id[4]
        elif source_id and source_id[0] in {
                "reg_ptr",
                "stack_ptr",
                "stack_offset",
                "stack_store_ptr",
                "stack_store_offset",
        }:
            region_start = source_id[-1]

        if region_start is None:
            return None

        for known_region in self._ctf_locked_entropy_regions() + self._ctf_static_entropy_regions():
            if known_region["start"] == region_start:
                return dict(known_region)

        return {
            "start": region_start,
            "end": region_start + getattr(self.project, "ctf_dynamic_region_size", 0x1000),
            "entropy": 0,
            "delta": 0,
            "kind": "locked",
        }

    def _ctf_update_region_lock(self, candidate):
        if candidate["kind"] != "reg_index":
            return

        source_id = candidate["source_id"]
        prev_lock_source = self.state.globals.get("ctf_vpc_region_lock_candidate_source", None)
        if prev_lock_source == source_id:
            hits = self.state.globals.get("ctf_vpc_region_lock_candidate_hits", 0) + 1
        else:
            hits = 1

        self.state.globals["ctf_vpc_region_lock_candidate_source"] = source_id
        self.state.globals["ctf_vpc_region_lock_candidate_hits"] = min(hits, 255)

        if hits < getattr(self.project, "ctf_vpc_region_lock_min_hits", 2):
            return

        region = self._ctf_region_for_candidate(candidate)
        if region is None:
            return

        self.state.globals["ctf_vpc_locked_source"] = source_id
        self.state.globals["ctf_vpc_locked_regions"] = [region]

    def _ctf_try_locked_reg_index_fast_path(self):
        if not getattr(self.project, "ctf_vpc_locked_source_fast_path", True):
            return False

        locked_regions = self._ctf_locked_entropy_regions()
        if not locked_regions:
            return False

        source_id = self.state.globals.get("ctf_vpc_locked_source", None)
        if not isinstance(source_id, tuple) or len(source_id) < 5 or source_id[0] != "reg_index":
            return False

        idx_tup = source_id[1]
        idx_name = self._ctf_reg_name_from_tup(idx_tup)
        value = self._ctf_eval_register_tuple(idx_name, idx_tup, allow_model=True)

        if value is None or value < 0:
            return False

        region = next((cur_region for cur_region in locked_regions if cur_region["start"] == source_id[4]), locked_regions[0])
        region_size = region["end"] - region["start"]
        if not self._ctf_region_contains(region, value) and value >= region_size:
            return False

        cur_vpc = self.state.globals.get("cur_vm_vpc", None)
        observed_source_write = any(
            cand.get("kind") == "reg_index" and cand.get("source_id") == source_id and
            cand.get("origin") in ("reg_write", "reg_write_dispatcher")
            for cand in self.state.globals.get("ctf_vpc_observed_reg_candidates", [])
        )
        if cur_vpc is not None and value != cur_vpc and not observed_source_write and getattr(
                self.project, "ctf_vpc_require_reg_write_for_locked_reg_index", True):
            self.state.globals["ctf_cur_vpc_source"] = source_id
            self.state.globals["ctf_cur_vpc_kind"] = "reg_index"
            self.state.globals["cur_vm_reg"] = idx_tup
            self.state.globals["vpc"] = cur_vpc
            return True

        candidate = {
            "source_id": source_id,
            "value": value,
            "score": getattr(self.project, "ctf_vpc_locked_source_score", 64),
            "kind": "reg_index",
            "reg_tup": idx_tup,
            "origin": "locked_source",
            "region": dict(region),
        }
        self._ctf_commit_candidate(candidate)
        return True

    def _ctf_commit_candidate(self, candidate):
        prev_vpc = self.state.globals.get("cur_vm_vpc", None)
        prev_source = self.state.globals.get("ctf_cur_vpc_source", None)

        self.state.globals["cur_vm_vpc"] = candidate["value"]
        self.state.globals["vpc"] = candidate["value"]
        self.state.globals["ctf_cur_vpc_source"] = candidate["source_id"]
        self.state.globals["ctf_cur_vpc_kind"] = candidate["kind"]
        self.state.globals["cur_vm_reg"] = candidate["reg_tup"]

        if candidate["kind"] == "reg_index" and candidate["reg_tup"] is not None:
            source_by_reg = dict(self.state.globals.get("ctf_reg_index_source_by_reg", {}))
            source_by_reg[candidate["reg_tup"]] = candidate["source_id"]
            self.state.globals["ctf_reg_index_source_by_reg"] = source_by_reg
            self._ctf_update_region_lock(candidate)
        elif candidate["kind"] == "stack_store_ptr":
            if candidate.get("origin", None) in ("stack_store", "stack_store_unconfirmed", "stack_store_fast"):
                self.state.globals["ctf_vpc_stack_store_ptr_updated_in_block"] = True
            if candidate.get("origin", None) != "stack_store_unconfirmed":
                self.state.globals["ctf_stack_store_ptr_source_confirmed"] = True
        elif candidate["kind"] == "stack_store_raw_offset":
            self._ctf_remember_stack_raw_source(candidate)
        elif candidate["kind"] == "fd_read_pos":
            self.state.globals["ctf_fd_read_pos_raw_value"] = candidate.get("raw_value", candidate["value"])

        if prev_vpc != candidate["value"] or prev_source != candidate["source_id"]:
            self.state.globals["last_change_time"] = 0

    def _ctf_score_candidates(self, candidates):
        history = self.state.globals.get("ctf_vpc_candidate_history", {})
        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)

        for cand in candidates:
            hist = history.get(cand["source_id"], None)
            if hist is not None:
                cand["score"] += min(hist.get("seen", 0), 8) * 0.5
                if hist.get("value", None) != cand["value"]:
                    cand["score"] += 8

            if cand["source_id"] == cur_source:
                cand["score"] += getattr(self.project, "ctf_vpc_current_source_bonus", 24)
                if cand["kind"] in ("stack_ptr", "stack_store_ptr", "reg_ptr"):
                    cand["score"] += getattr(self.project, "ctf_vpc_pointer_source_bonus", 8)

        for cand in candidates:
            hist = history.get(cand["source_id"], {"seen": 0})
            history[cand["source_id"]] = {
                "value": cand["value"],
                "seen": hist.get("seen", 0) + 1,
                "kind": cand["kind"],
            }

        self.state.globals["ctf_vpc_candidate_history"] = history
        return candidates

    def _ctf_candidate_value_map(self, candidates):
        values_by_source = {}
        for cand in candidates:
            source_id = cand.get("source_id", None)
            value = cand.get("value", None)
            if source_id is None or value is None:
                continue

            values_by_source.setdefault(source_id, set()).add(value)

        return {source_id: tuple(sorted(values)) for source_id, values in values_by_source.items()}

    def _ctf_has_plausible_delta(self, prev_values, cur_values):
        max_delta = getattr(self.project, "ctf_vpc_delta_threshold", 15)
        for prev_value in prev_values or ():
            for cur_value in cur_values or ():
                if 0 < abs(prev_value - cur_value) <= max_delta:
                    return True

        return False

    def _ctf_record_candidate_movement(self, candidates, prev_values_by_source):
        cur_values_by_source = self._ctf_candidate_value_map(candidates)
        delta_hits = dict(self.state.globals.get("ctf_vpc_source_delta_hits", {}))

        for source_id, cur_values in cur_values_by_source.items():
            prev_values = prev_values_by_source.get(source_id, ())
            if self._ctf_has_plausible_delta(prev_values, cur_values):
                delta_hits[source_id] = min(delta_hits.get(source_id, 0) + 1, 255)

        history_limit = getattr(self.project, "ctf_vpc_source_history_limit", 256)
        if len(delta_hits) > history_limit:
            active_sources = set(cur_values_by_source) | set(prev_values_by_source)
            delta_hits = {
                source_id: hits
                for source_id, hits in delta_hits.items()
                if source_id in active_sources
            }

        self.state.globals["ctf_prev_candidate_vpcs"] = cur_values_by_source
        self.state.globals["ctf_vpc_source_delta_hits"] = delta_hits

    def _ctf_filter_reg_index_candidates_by_movement(self, candidates, source_delta_hits):
        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        cur_kind = self.state.globals.get("ctf_cur_vpc_kind", None)
        if cur_kind != "reg_index" or cur_source is None:
            return candidates

        reg_index_candidates = [cand for cand in candidates if cand["kind"] == "reg_index"]
        if not reg_index_candidates:
            return candidates

        current_source_candidates = [
            cand for cand in reg_index_candidates
            if cand["source_id"] == cur_source
        ]

        if current_source_candidates:
            self.state.globals["ctf_vpc_current_source_missing_count"] = 0
            current_reg_write_candidates = [
                cand for cand in current_source_candidates
                if cand.get("origin", None) in ("reg_write", "reg_write_dispatcher")
            ]
            if current_reg_write_candidates:
                return current_reg_write_candidates

            cur_vpc = self.state.globals.get("cur_vm_vpc", None)
            unchanged_candidates = [
                cand for cand in current_source_candidates
                if cur_vpc is not None and cand["value"] == cur_vpc
            ]
            if unchanged_candidates:
                return unchanged_candidates

            return current_source_candidates

        missing_count = self.state.globals.get("ctf_vpc_current_source_missing_count", 0) + 1
        self.state.globals["ctf_vpc_current_source_missing_count"] = min(missing_count, 255)

        min_switch_hits = getattr(self.project, "ctf_vpc_source_switch_min_delta_hits", 2)
        switch_candidates = [
            cand for cand in reg_index_candidates
            if source_delta_hits.get(cand["source_id"], 0) >= min_switch_hits
        ]
        if getattr(self.project, "ctf_vpc_require_reg_write_for_reg_index_source_switch", True):
            reg_write_sources = {
                cand["source_id"]
                for cand in reg_index_candidates
                if cand.get("origin", None) in ("reg_write", "reg_write_dispatcher")
            }
            switch_candidates = [
                cand for cand in switch_candidates
                if cand["source_id"] in reg_write_sources
            ]

        min_missing_count = getattr(self.project, "ctf_vpc_source_switch_min_missing_count", 2)
        if switch_candidates and missing_count >= min_missing_count:
            self.state.globals["ctf_vpc_current_source_missing_count"] = 0
            return switch_candidates

        return []

    def find_ctf_vpc(self):
        self._ctf_restore_reg_index_source()
        if self._ctf_try_stack_store_ptr_store_only_fast_path():
            return

        if self._ctf_try_stack_store_ptr_block_fast_path():
            return

        if self._ctf_try_fd_read_pos_fast_path():
            return

        if self._ctf_try_locked_reg_index_fast_path():
            return

        reg_vals = self._ctf_register_values()
        stack_words = self._ctf_stack_words()
        entropy_regions = self._ctf_entropy_regions(reg_vals=reg_vals, stack_words=stack_words, use_locked=False)
        region_biases = self._ctf_region_biases(entropy_regions)
        indexed_memory_operands = self._ctf_indexed_memory_operands()
        stack_index_uses = self._ctf_stack_index_uses(entropy_regions)
        stack_pointer_uses = self._ctf_stack_pointer_uses(entropy_regions)
        has_stack_index_uses = bool(stack_index_uses)
        stack_index_regions = {key[2] for key in stack_index_uses}
        candidates = []
        candidates.extend(self.state.globals.get("ctf_vpc_observed_reg_candidates", []))
        candidates.extend(self.state.globals.get("ctf_vpc_observed_store_candidates", []))
        if getattr(self.project, "ctf_vpc_stack_raw_use_passive_slot_candidates", False):
            candidates.extend(self._ctf_stack_raw_slot_candidates())

        for base_reg, _, base_val in reg_vals:
            possible_regions = [region for region in entropy_regions if self._ctf_region_contains(region, base_val)]
            if not possible_regions:
                continue

            for idx_reg, idx_tup, idx_val in reg_vals:
                if idx_val > getattr(self.project, "ctf_vpc_max_index", 0x100000):
                    continue

                for scale in (1, 2, 4, 8):
                    source_id = ("reg_index", idx_tup, base_reg, scale, possible_regions[0]["start"])
                    operand_info = indexed_memory_operands.get((base_reg, idx_reg, scale), None)
                    if operand_info is None or operand_info.get("byte_self_clobber", False):
                        continue

                    indexed_addr = base_val + (idx_val * scale)
                    matching_regions = [region for region in possible_regions if self._ctf_region_contains(region, indexed_addr)]
                    if not matching_regions:
                        continue

                    best_region = max(matching_regions, key=lambda region: region["delta"])
                    source_id = ("reg_index", idx_tup, base_reg, scale, best_region["start"])
                    score = 12 + (best_region["delta"] * 2)
                    score += operand_info["score"]
                    if idx_val == 0:
                        score -= 1

                    self._ctf_add_candidate(
                        candidates,
                        source_id,
                        idx_val,
                        score,
                        "reg_index",
                        reg_tup=idx_tup,
                        region=best_region,
                    )

        has_reg_index_candidate = any(cand["kind"] == "reg_index" for cand in candidates)
        cur_kind = self.state.globals.get("ctf_cur_vpc_kind", None)
        if cur_kind == "reg_index" and not has_reg_index_candidate:
            return

        sticky_fallback_kinds = {
            "stack_ptr",
            "stack_offset",
            "stack_store_ptr",
            "stack_store_offset",
            "stack_store_raw_offset",
            "fd_read_pos",
        }
        allow_fallback_sources = not has_reg_index_candidate or cur_kind in sticky_fallback_kinds

        if allow_fallback_sources and getattr(self.project, "ctf_vpc_allow_reg_ptr", False):
            for reg_name, reg_tup, reg_val in reg_vals:
                for region in entropy_regions:
                    if not self._ctf_region_contains(region, reg_val):
                        continue

                    self._ctf_add_candidate(
                        candidates,
                        ("reg_ptr", reg_tup, region["start"]),
                        reg_val,
                        9 + (region["delta"] * 2),
                        "reg_ptr",
                        reg_tup=reg_tup,
                        region=region,
                    )

        if allow_fallback_sources:
            for word in stack_words:
                for region in entropy_regions:
                    if self._ctf_region_contains(region, word["value"]):
                        if region["start"] in stack_index_regions and \
                                getattr(self.project, "ctf_vpc_prefer_stack_index_over_pointer", True):
                            continue

                        pointer_use_score = stack_pointer_uses.get((word["addr"], word["size"], region["start"]), None)
                        if pointer_use_score is None and getattr(self.project, "ctf_vpc_require_stack_pointer_use", True):
                            continue

                        self._ctf_add_candidate(
                            candidates,
                            ("stack_ptr", word["addr"], word["size"], region["start"]),
                            word["value"],
                            11 + (region["delta"] * 2) + pointer_use_score,
                            "stack_ptr",
                            region=region,
                        )

                    region_size = region["end"] - region["start"]
                    if 0 < word["value"] < region_size:
                        index_use_score = stack_index_uses.get((word["addr"], word["size"], region["start"]), None)
                        if index_use_score is None and getattr(self.project, "ctf_vpc_require_stack_index_use", True):
                            continue

                        score = 10 + (region["delta"] * 2)
                        if index_use_score is not None:
                            score += index_use_score

                        self._ctf_add_candidate(
                            candidates,
                            ("stack_offset", word["addr"], word["size"], region["start"]),
                            region_biases[region["start"]] + word["value"],
                            score,
                            "stack_offset",
                            region=region,
                        )

        self._ctf_note_fd_read_pos_candidates(candidates)

        cur_source = self.state.globals.get("ctf_cur_vpc_source", None)
        if cur_kind == "stack_store_raw_offset" and getattr(self.project, "ctf_vpc_sticky_stack_raw_source", True):
            cur_slot = cur_source[1:3] if isinstance(cur_source, tuple) and len(cur_source) >= 3 else None
            raw_candidates = [
                cand for cand in candidates
                if cand["kind"] == "stack_store_raw_offset" and (
                    cur_slot is None or (
                        isinstance(cand.get("source_id", None), tuple) and
                        len(cand["source_id"]) >= 3 and
                        cand["source_id"][1:3] == cur_slot
                    )
                )
            ]
            if raw_candidates:
                candidates = raw_candidates
            else:
                return

        if cur_kind == "stack_store_ptr" and getattr(self.project, "ctf_vpc_sticky_stack_store_ptr_source", True):
            stack_store_ptr_candidates = self._ctf_stack_store_ptr_candidates_for_current_source(candidates)
            if stack_store_ptr_candidates:
                candidates = stack_store_ptr_candidates
            else:
                return

        if cur_kind == "fd_read_pos" and self._ctf_fd_read_pos_mode_enabled("sticky"):
            fd_read_pos_candidates = self._ctf_fd_read_pos_candidates_for_current_source(candidates)
            if fd_read_pos_candidates:
                candidates = fd_read_pos_candidates
            else:
                return

        if not candidates:
            return

        prev_candidate_values = self.state.globals.get("ctf_prev_candidate_vpcs", {})
        source_delta_hits = dict(self.state.globals.get("ctf_vpc_source_delta_hits", {}))
        self._ctf_record_candidate_movement(candidates, prev_candidate_values)
        candidates = self._ctf_filter_reg_index_candidates_by_movement(candidates, source_delta_hits)
        if not candidates:
            return

        cur_vpc = self.state.globals.get("cur_vm_vpc", None)
        cur_kind = self.state.globals.get("ctf_cur_vpc_kind", None)
        pointer_kinds = {"stack_ptr", "stack_store_ptr", "reg_ptr"}
        if cur_kind in pointer_kinds and cur_source is not None and getattr(
                self.project, "ctf_vpc_sticky_pointer_source", True):
            pointer_candidates = [cand for cand in candidates if cand["kind"] in pointer_kinds]
            has_current_pointer_candidate = any(cand["source_id"] == cur_source for cand in pointer_candidates)
            if not has_current_pointer_candidate:
                if pointer_candidates:
                    candidates = pointer_candidates
                else:
                    return

        if cur_kind == "reg_index" and cur_source is not None and getattr(
                self.project, "ctf_vpc_require_reg_write_to_advance_reg_index", True):
            has_current_reg_write = any(
                cand["kind"] == "reg_index" and cand["source_id"] == cur_source and
                cand.get("origin") in ("reg_write", "reg_write_dispatcher")
                for cand in candidates
            )
            if not has_current_reg_write:
                candidates = [
                    cand for cand in candidates
                    if not (
                        cand["kind"] == "reg_index" and
                        cand["source_id"] == cur_source and
                        cand.get("origin") not in ("reg_write", "reg_write_dispatcher")
                    )
                ]
                if not candidates:
                    return

        if cur_kind == "reg_index" and cur_source is not None:
            has_current_reg_candidate = any(
                cand["kind"] == "reg_index" and cand["source_id"] == cur_source
                for cand in candidates
            )
            for cand in candidates:
                if cand["kind"] != "reg_index" or cand["source_id"] == cur_source:
                    continue
                if cur_vpc is not None and cand["value"] == cur_vpc:
                    cand["score"] -= getattr(self.project, "ctf_vpc_same_value_source_switch_penalty", 32)
                elif has_current_reg_candidate:
                    cand["score"] -= getattr(self.project, "ctf_vpc_reg_source_switch_penalty", 24)

        candidates = self._ctf_score_candidates(candidates)
        best_candidate = max(candidates, key=lambda cand: cand["score"])
        if best_candidate["score"] < getattr(self.project, "ctf_vpc_score_threshold", 10):
            return

        if getattr(self.project, "ctf_vpc_debug", False):
            bbl = self.state.globals.get("cur_bbl", None)
            bbl_addr = getattr(bbl, "addr", None)
            top_candidates = sorted(candidates, key=lambda cand: cand["score"], reverse=True)[:5]
            print("ctf-vpc", hex(bbl_addr) if bbl_addr is not None else None,
                  [(cand["kind"], cand["value"], round(cand["score"], 2), cand["source_id"])
                   for cand in top_candidates])

        self._ctf_commit_candidate(best_candidate)

    def find_vip(self):
        # if 'prev_candidate_vips' in self.state.globals:
        #     print(self.state.globals['prev_candidate_vips'])
        candidate_vips = {}
        if self.project.arch.bits == 64:
            candidate_regs = ['rbx', 'rcx', 'rdx', 'rax', 'rsp', 'rbp', 'rsi', 'rdi','r8', 'r9', 'r10', 'r11']
        elif self.project.arch.bits == 32:
            candidate_regs = ['eax', 'ebx', 'ecx', 'edx', 'esp', 'esi', 'edi', 'ebp']

        data_chunk_size = 256
        for reg, off_size_tuple in self.project.arch.registers.items():
            if reg in candidate_regs:
                reg_off, size = self.project.arch.registers[reg]
                reg_val = self.state.registers.load(reg_off, size)
                poss_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(reg_val, 3)

                if len(poss_addrs) == 1:
                    # we store the constant value back to save on solving time, next time we call this function
                    skip = False
                    for var in reg_val.variables:
                        if var.startswith('precon_sp'):
                            skip = True
                            break
                    if not skip:
                        self.state.registers.store(reg_off, poss_addrs[0], size)
                    addr = poss_addrs[0]
                    if self.project.byte_code_regions:
                        for region in self.project.byte_code_regions:
                            if self.state.project.loader.main_object.contains_addr(addr) and (region[0] <= addr <= region[1]):
                                data = None
                                # check if the data lies in the correct segment
                                t_sec = self.project.loader.main_object.find_section_containing(addr - (data_chunk_size//2))
                                if not (self.state.project.loader.main_object.contains_addr(
                                        addr - (data_chunk_size//2)) and (region[0] <= addr-(data_chunk_size//2) <= region[1])):
                                    data = self.project.loader.memory.load(addr, data_chunk_size)
                                else:
                                    t_sec = self.project.loader.main_object.find_section_containing(addr + (data_chunk_size//2))
                                    if not (self.state.project.loader.main_object.contains_addr(
                                            addr + (data_chunk_size//2)) and (region[0] <= addr+(data_chunk_size//2) <= region[1])):
                                        data = self.project.loader.memory.load(addr - data_chunk_size, data_chunk_size)

                                if data is None:
                                    data = self.project.loader.memory.load(addr - (data_chunk_size//2), data_chunk_size)
                                entropy = self._calc_entropy(data, data_chunk_size)
                                if entropy > self.project.min_entropy_threshold and poss_addrs[0] not in [54231039]:#, 55656928, 55002152, 54543638]:
                                    print(entropy)
                                    print(addr)
                                    candidate_vips[(reg_off, size)] = (poss_addrs[0],)
                                    break
                    else:
                        if self._is_vip_candidate_section_addr(addr):
                            data = None
                            # check if the data lies in the correct segment
                            if not self._is_vip_candidate_section_addr(addr - (data_chunk_size//2)):
                                data = self.project.loader.memory.load(addr, data_chunk_size)
                            else:
                                if not self._is_vip_candidate_section_addr(addr + (data_chunk_size//2)):
                                    data = self.project.loader.memory.load(addr - data_chunk_size, data_chunk_size) # this is slow, replace with self.project.loader.memory.load(addr, self.size)

                            if data is None:
                                data = self.project.loader.memory.load(addr - (data_chunk_size//2), data_chunk_size)
                            entropy = self._calc_entropy(data, data_chunk_size)

                            print(addr)
                            print(entropy)
                            if entropy > self.project.min_entropy_threshold and poss_addrs[0] not in [4995114]: # this vpc exception is for blaster_vmp_3.10
                                print(entropy)
                                print(addr)
                                candidate_vips[(reg_off, size)] = (poss_addrs[0],)
                            elif off_size_tuple[0] == self.state.globals['cur_vm_reg'] and 1 < abs(addr- self.state.globals['vpc']) < 15:
                                candidate_vips[(reg_off, size)] = (poss_addrs[0],)


                elif len(poss_addrs) == 2:
                    if self.project.byte_code_regions:
                        dont_add_addr = False
                        for poss_addr in poss_addrs:
                            is_vpc=False
                            for region in self.project.byte_code_regions:
                                if self.state.project.loader.main_object.contains_addr(poss_addr) and \
                                        (region[0] <= poss_addr <= region[1]):
                                    data = None
                                    # check if the data lies in the correct segment
                                    t_sec = self.project.loader.main_object.find_section_containing(poss_addr - (data_chunk_size//2))
                                    if not (self.state.project.loader.main_object.contains_addr(
                                            poss_addr - (data_chunk_size//2)) and (region[0] <= poss_addr-(data_chunk_size//2) <= region[1])):
                                        data = self.project.loader.memory.load(poss_addr, data_chunk_size)
                                    else:
                                        t_sec = self.project.loader.main_object.find_section_containing(poss_addr + (data_chunk_size//2))
                                        if not (self.state.project.loader.main_object.contains_addr(
                                                poss_addr + (data_chunk_size//2)) and (region[0] <= poss_addr+(data_chunk_size//2) <= region[1])):
                                            data = self.project.loader.memory.load(poss_addr - data_chunk_size, data_chunk_size)

                                    if data is None:
                                        data = self.project.loader.memory.load(poss_addr - (data_chunk_size//2), data_chunk_size)
                                    entropy = self._calc_entropy(data, data_chunk_size)
                                    if entropy > self.project.min_entropy_threshold:
                                        print(entropy)
                                        print(poss_addr)
                                        is_vpc = True
                                        break
                            if not is_vpc:
                                dont_add_addr = True
                                break
                    else:
                        dont_add_addr = False
                        for poss_addr in poss_addrs:
                            is_vpc=False
                            if self._is_vip_candidate_section_addr(poss_addr):
                                data=None
                                #check if the data lies in the correct segment
                                if not self._is_vip_candidate_section_addr(poss_addr - (data_chunk_size//2)):
                                    data = self.project.loader.memory.load(poss_addr, data_chunk_size)
                                else:
                                    if not self._is_vip_candidate_section_addr(poss_addr + (data_chunk_size//2)):
                                        data = self.project.loader.memory.load(poss_addr-data_chunk_size, data_chunk_size)

                                if data is None:
                                    data = self.project.loader.memory.load(poss_addr - (data_chunk_size//2), data_chunk_size)
                                entropy = self._calc_entropy(data, data_chunk_size)
                                if entropy > self.project.min_entropy_threshold:
                                    print(entropy)
                                    print(poss_addr)
                                    is_vpc=True

                            if not is_vpc:
                                dont_add_addr = True
                                break
                    if not dont_add_addr and len(poss_addrs) == 2:
                        l.debug("More than one VIP, gonna add both values and create a new one")
                        candidate_vips[(reg_off, size)] = (poss_addrs[0], poss_addrs[1])

        candidate_use_scores = self._vip_candidate_use_scores(candidate_vips)

        found_vip = False
        if len(candidate_vips) > 1:
            # first prioritise the existing vpc reg, by checking if it has inc/dec, if not check others later
            if not found_vip and self.state.globals['cur_vm_reg'] in candidate_vips and \
                    self._vip_candidate_use_allowed(
                        self.state.globals['cur_vm_reg'], candidate_vips, candidate_use_scores
                    ) and \
                    0 < abs(self.state.globals['cur_vm_vpc'] - candidate_vips[self.state.globals['cur_vm_reg']][0]) <=15:
                self.state.globals['cur_vm_vpc'] =  candidate_vips[self.state.globals['cur_vm_reg']][0]
                self.state.globals['vpc'] =  candidate_vips[self.state.globals['cur_vm_reg']][0]
                self.state.globals["last_change_time"] = 0
                found_vip = True

            if not found_vip and self.state.globals["last_change_time"] > 1:
                for reg_tup, poss_addrs in self._vip_ordered_candidates(candidate_vips, candidate_use_scores):
                    if not self._vip_candidate_use_allowed(reg_tup, candidate_vips, candidate_use_scores):
                        continue
                    if reg_tup in self.state.globals['prev_candidate_vips'] and len(poss_addrs) == 1 and len(self.state.globals['prev_candidate_vips'][reg_tup]) == 1:
                        poss_vpc_val_0 = self.state.globals['prev_candidate_vips'][reg_tup][0]
                        poss_vpc_val_1 = poss_addrs[0]
                        if 0 < abs(poss_vpc_val_0 - poss_vpc_val_1) <=15:
                            if not(self.state.globals['vpc'] == poss_vpc_val_1):
                                # this makes sure we don't keep overwriting the loop unroll vpc values with the unchanging vpc
                                self.state.globals['cur_vm_vpc'] = poss_vpc_val_1
                                self.state.globals['vpc'] = poss_vpc_val_1
                                self.state.globals['cur_vm_reg'] = reg_tup
                                self.state.globals["last_change_time"] = 0

                            found_vip = True
                            break

            if not found_vip and self.state.globals["last_change_time"] > 1 and self.state.globals['cur_vm_vpc'] is None and self.state.globals['cur_vm_reg'] is None:
                # when vpc has not been set initially
                for reg_tup, poss_addrs in self._vip_ordered_candidates(candidate_vips, candidate_use_scores):
                    if not self._vip_candidate_use_allowed(reg_tup, candidate_vips, candidate_use_scores):
                        continue
                    if len(poss_addrs) == 1:
                        self.state.globals['cur_vm_vpc'] = poss_addrs[0]
                        self.state.globals['vpc'] = poss_addrs[0]
                        self.state.globals['cur_vm_reg'] = reg_tup
                        self.state.globals["last_change_time"] = 0
                        found_vip = True
                        break


            # if not found_vip:
            #     # looks for the case when multiple vpcs for branching
            #     for reg_tup, poss_addrs in candidate_vips.items():
            #         if reg_tup in self.state.globals['prev_candidate_vips'] and len(poss_addrs) == 2 and len(self.state.globals['prev_candidate_vips'][reg_tup]) == 2:
            #             poss_vpc_val_0 = sum(self.state.globals['prev_candidate_vips'][reg_tup])
            #             poss_vpc_val_1 = sum(poss_addrs)
            #             if 0 < abs(poss_vpc_val_0 - poss_vpc_val_1) <=25:
            #                 import ipdb;ipdb.set_trace()
            #                 self.state.globals['cur_vm_vpc'] = poss_vpc_val_1
            #                 self.state.globals['cur_vm_reg'] = reg_tup
            #                 found_vip = True
            #                 break

            if not found_vip and self.state.globals["last_change_time"] > 1:
                #keep previous vpc
                reg_off, size = self.state.globals['cur_vm_reg']
                reg_val = self.state.registers.load(reg_off, size)
                poss_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(reg_val, 2)
                if len(poss_addrs) == 1 and poss_addrs[0] == self.state.globals['cur_vm_vpc'] and \
                        self._vip_candidate_use_allowed(
                            self.state.globals['cur_vm_reg'], candidate_vips, candidate_use_scores
                        ):
                    #we are keeping the vpc same, if no change detected
                    found_vip = True

            if not found_vip and self.state.globals["last_change_time"] > 1:
                for reg_tup, poss_addrs in self._vip_ordered_candidates(candidate_vips, candidate_use_scores):
                    if not self._vip_candidate_use_allowed(reg_tup, candidate_vips, candidate_use_scores):
                        continue
                    if len(poss_addrs) == 2 and reg_tup in self.state.globals['prev_candidate_vips']:
                        poss_vpc_val_0 = sum(self.state.globals['prev_candidate_vips'][reg_tup])
                        poss_vpc_val_1 = sum(poss_addrs)
                        if 0 < abs(poss_vpc_val_0 - poss_vpc_val_1) <= 15:
                            #possible branching so add the vpcs
                            self.state.globals['cur_vm_vpc'] = sum(poss_addrs)
                            self.state.globals['cur_vm_reg'] = reg_tup
                            self.state.globals["last_change_time"] = 0
                            found_vip = True
                            break

            # if not found_vip:
            #     for reg_tup, poss_addrs in candidate_vips.items():
            #         if len(poss_addrs) == 2:
            #             #possible branching so add the vpcs
            #             self.state.globals['cur_vm_vpc'] = sum(poss_addrs)
            #             self.state.globals['cur_vm_reg'] = reg_tup
            #             found_vip = True
            #             break


        elif len(candidate_vips) == 1:
            reg_tup = list(candidate_vips.keys())[0]
            poss_addrs = list(candidate_vips.values())[0]
            if len(list(candidate_vips.values())[0]) > 1:
                if reg_tup in self.state.globals['prev_candidate_vips'] and len(poss_addrs) == 2 and len(
                        self.state.globals['prev_candidate_vips'][reg_tup]) == 2:
                    poss_vpc_val_0 = sum(self.state.globals['prev_candidate_vips'][reg_tup])
                    poss_vpc_val_1 = sum(poss_addrs)
                    if 0 < abs(poss_vpc_val_0 - poss_vpc_val_1) <= 20: # added less than equal for VMProtect 3.5
                        self.state.globals['cur_vm_vpc'] = sum(list(candidate_vips.values())[0])
                        self.state.globals['vpc'] = sum(list(candidate_vips.values())[0])
                        self.state.globals['cur_vm_reg'] = list(candidate_vips.keys())[0]
            else:
                if reg_tup != self.state.globals['cur_vm_reg'] and len(poss_addrs) == 1:
                    # if the previous vpc reg is no longer in the candidates and only a single new candidate exists, let use that
                    self.state.globals['cur_vm_vpc'] = list(candidate_vips.values())[0][0]
                    self.state.globals['vpc'] = list(candidate_vips.values())[0][0]
                    self.state.globals['cur_vm_reg'] = list(candidate_vips.keys())[0]

                elif reg_tup in self.state.globals['prev_candidate_vips'] and len(poss_addrs) == 1 and len(
                        self.state.globals['prev_candidate_vips'][reg_tup]) == 1:
                    poss_vpc_val_0 = self.state.globals['prev_candidate_vips'][reg_tup][0]
                    poss_vpc_val_1 = poss_addrs[0]
                    if 0 < abs(poss_vpc_val_0 - poss_vpc_val_1) <= 15:
                        self.state.globals['cur_vm_vpc'] = list(candidate_vips.values())[0][0]
                        self.state.globals['vpc'] = list(candidate_vips.values())[0][0]
                        self.state.globals['cur_vm_reg'] = list(candidate_vips.keys())[0]
                elif reg_tup in self.state.globals['prev_candidate_vips'] and len(poss_addrs) == 1 and len(
                        self.state.globals['prev_candidate_vips'][reg_tup]) == 2:
                    # if the prev vpc was a sum becasue of branching let's switch to single value
                    assign_new_vpc = False
                    for prev_addr in self.state.globals['prev_candidate_vips'][reg_tup]:
                        if 0 < abs(prev_addr - poss_addrs[0]) <= 15:
                            assign_new_vpc = True
                    if assign_new_vpc:
                        self.state.globals['cur_vm_vpc'] = list(candidate_vips.values())[0][0]
                        self.state.globals['vpc'] = list(candidate_vips.values())[0][0]
                        self.state.globals['cur_vm_reg'] = list(candidate_vips.keys())[0]

        self.state.globals['prev_candidate_vips'] = candidate_vips
        print(candidate_vips)

    def handle_vex_block(self, irsb: pyvex.IRSB):
        self.irsb = irsb
        self.tmps = [None]*self.irsb.tyenv.types_used
        curr_ins_addr = None
        ins_skip = []
        full_skip_ins = []

        if 'vm_graph_exploration' in self.state.globals and self.state.globals['vm_graph_exploration']:
            if self.state.globals.get("use_ctf_vpc_finder", False):
                self.state.globals["ctf_vpc_observed_store_candidates"] = []
                self.state.globals["ctf_vpc_observed_reg_candidates"] = []
                self.state.globals["ctf_vpc_block_entry_vpc"] = self.state.globals.get("cur_vm_vpc", None)
                self.state.globals["ctf_vpc_stack_store_ptr_updated_in_block"] = False
            self.state.globals["last_change_time"] += 1
            bbl = self.state.globals['cur_bbl']

            for ins in bbl.disassembly.insns:
                if ins.mnemonic in ["popf", "popfd"]:
                    ins_skip.append(ins.address)
                if ins.mnemonic in ['btc', 'bts', 'bt', 'btr']:
                    self.project.bt_ins_addrs.add(ins.address)
                if ins.mnemonic in ['rdtsc']:
                    self.project.rdtsc_ins_addrs.add(ins.address)

        ins_addr = -1
        for stmt_idx, stmt in enumerate(irsb.statements):
            if 'vm_graph_exploration' in self.state.globals and self.state.globals['vm_graph_exploration'] and \
                    'use_vip_finder' in self.state.globals and self.state.globals['use_vip_finder'] and \
                    stmt_idx == len(irsb.statements)//2 and \
                    (self.state.globals['start_deobfuscation'] == True or self.project.start_deobfuscation_immediately==True):
                self.find_vip()
            if self._ctf_finder_enabled() and stmt_idx == len(irsb.statements)//2 and \
                    getattr(self.project, "ctf_vpc_find_mid_block", False):
                self.find_ctf_vpc()
            if isinstance(stmt, pyvex.stmt.IMark):
                ins_addr +=1
                curr_ins_addr = stmt.addr

            if curr_ins_addr in ins_skip and isinstance(stmt, pyvex.stmt.Exit):
               # import ipdb;ipdb.set_trace()
                continue
            self.stmt_idx = stmt_idx
            handle_rep_movsb = getattr(self.project, "enable_rep_movsb_shortcut", False) and (
                curr_ins_addr in self.project.rep_movsb_addr or
                (
                    'vm_graph_exploration' in self.state.globals and
                    self.state.globals['vm_graph_exploration'] and
                    bbl.disassembly.insns[ins_addr].mnemonic == "rep movsb"
                )
            )
            if handle_rep_movsb:
                print("experimental")
                self.project.rep_movsb_addr.add(curr_ins_addr)
                if curr_ins_addr in ins_skip:
                    continue

                if self.project.arch.bits == 64:
                    print("ADD SUPPORT FOR DIRECTION FLAG")
                    count = self.state.partial_symbolic_constraint_solver.eval_one(self.state.regs.rcx)  # Number of bytes to copy
                    buf = self.state.memory.load(self.state.partial_symbolic_constraint_solver.eval_one(self.state.regs.rsi), count, endness="Iend_BE")  # Load 'count' bytes from source
                    self.state.memory.store(self.state.partial_symbolic_constraint_solver.eval_one(self.state.regs.rdi), buf, endness="Iend_BE")  # Store to destination

                    # Update registers
                    self.state.regs.rsi += count  # Increment source index
                    self.state.regs.rdi += count  # Increment destination index
                    self.state.regs.rcx = 0  # REP MOVSB decrements ECX to 0
                    ins_skip.append(curr_ins_addr)
                if self.project.arch.bits == 32:
                    count = self.state.partial_symbolic_constraint_solver.eval_one(
                        self.state.regs.ecx)  # Number of bytes to copy
                    buf = self.state.memory.load(
                        self.state.partial_symbolic_constraint_solver.eval_one(self.state.regs.esi), count,
                        endness="Iend_BE")  # Load 'count' bytes from source
                    self.state.memory.store(self.state.partial_symbolic_constraint_solver.eval_one(self.state.regs.edi),
                                            buf, endness="Iend_BE")  # Store to destination

                    # Update registers
                    self.state.regs.esi += count  # Increment source index
                    self.state.regs.edi += count  # Increment destination index
                    self.state.regs.ecx = 0  # REP MOVSB decrements ECX to 0
                    ins_skip.append(curr_ins_addr)

                target = irsb.statements[stmt_idx + 3].dst
                self.state.scratch.temps[irsb.next.tmp] = claripy.BVV(
                    target.value,
                    pyvex.get_type_size(irsb.tyenv.lookup(irsb.next.tmp)),
                )

            else:
                self._handle_vex_stmt(stmt)
        if 'vm_graph_exploration' in self.state.globals and self.state.globals['vm_graph_exploration'] and \
                'use_vip_finder' in self.state.globals and self.state.globals['use_vip_finder'] and \
                (self.state.globals['start_deobfuscation'] == True or self.project.start_deobfuscation_immediately):
            self.find_vip()
        if self._ctf_finder_enabled():
            self.find_ctf_vpc()
        self.stmt_idx = DEFAULT_STATEMENT
        self._handle_vex_defaultexit(irsb.next, irsb.jumpkind)


    def _handle_vex_defaultexit(self, expr: pyvex.expr.IRExpr | None, jumpkind: str):
        self._perform_vex_defaultexit(self._analyze_vex_defaultexit(expr) if expr is not None else None, jumpkind)

    def _perform_vex_defaultexit(self, expr, jumpkind):
        pass

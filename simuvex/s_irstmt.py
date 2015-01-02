#!/usr/bin/env python
'''This module handles constraint generation for VEX IRStmt.'''

import logging
l = logging.getLogger("s_irstmt")

class SimIRStmt(object):
    '''A class for symbolically translating VEX IRStmts.'''

    def __init__(self, stmt, imark, irsb_addr, stmt_idx, state, tyenv):
        self.imark = imark
        self.irsb_addr = irsb_addr
        self.stmt_idx = stmt_idx
        self.state = state
        self.tyenv = tyenv

        # references by the statement
        self.actions = []
        self._constraints = [ ]

        # attribtues for a conditional exit
        self.guard = None
        self.target = None
        self.jumpkind = None

        func_name = "_handle_" + type(stmt).__name__
        if hasattr(self, func_name):
            l.debug("Handling IRStmt %s (index %d)", type(stmt), stmt_idx)
            getattr(self, func_name)(stmt)
        else:
            l.error("Unsupported statement type %s", (type(stmt)))
            if o.BYPASS_UNSUPPORTED_IRSTMT not in self.state.options:
                raise UnsupportedIRStmtError("Unsupported statement type %s" % (type(stmt)))
            self.state.log.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')

        del self.tyenv

    def _translate_expr(self, expr):
        '''Translates an IRExpr into a SimIRExpr.'''
        e = SimIRExpr(expr, self.imark, self.stmt_idx, self.state, self.tyenv)
        self._record_expr(e)
        return e

    def _translate_exprs(self, exprs):
        '''Translates a sequence of IRExprs into SimIRExprs.'''
        return [ self._translate_expr(e) for e in exprs ]

    def _record_expr(self, expr):
        '''Records the references of an expression.'''
        self.actions.extend(expr.actions)

    def _add_constraints(self, *constraints):
        '''Adds constraints to the state.'''
        self._constraints.extend(constraints)
        self.state.add_constraints(*constraints)

    def _write_tmp(self, tmp, v, size, reg_deps, tmp_deps):
        '''Writes an expression to a tmp. If in symbolic mode, this involves adding a constraint for the tmp's symbolic variable.'''
        self.state.store_tmp(tmp, v)

        # get the size, and record the write
        if o.TMP_REFS in self.state.options:
            data_ao = SimActionObject(v, reg_deps=reg_deps, tmp_deps=tmp_deps)
            r = SimActionData(self.state, SimActionData.TMP, SimActionData.WRITE, data=data_ao, size=size)
            self.actions.append(r)

    ##########################
    ### statement handlers ###
    ##########################
    def _handle_NoOp(self, stmt):
        pass

    def _handle_IMark(self, stmt):
        pass

    def _handle_WrTmp(self, stmt):
        # get data and track data reads
        data = self._translate_expr(stmt.data)
        self._write_tmp(stmt.tmp, data.expr, data.size_bits(), data.reg_deps(), data.tmp_deps())

        actual_size = data.size_bits()
        expected_size = size_bits(self.tyenv.typeOf(stmt.data))
        if actual_size != expected_size:
            raise SimStatementError("WrTmp expected length %d but got %d" % (actual_size, expected_size))

    def _handle_Put(self, stmt):
        # value to put
        data = self._translate_expr(stmt.data)

        # do the put (if we should)
        if o.DO_PUTS in self.state.options:
            self.state.store_reg(stmt.offset, data.expr)

        # track the put
        if o.REGISTER_REFS in self.state.options:
            data_ao = SimActionObject(data.expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            size_ao = SimActionObject(data.size_bits())
            r = SimActionData(self.state, SimActionData.REG, SimActionData.WRITE, offset=stmt.offset, data=data_ao, size=size_ao)
            self.actions.append(r)

    def _handle_Store(self, stmt):
        # first resolve the address and record stuff
        addr = self._translate_expr(stmt.addr)

        # now get the value and track everything
        data = self._translate_expr(stmt.data)

        # fix endianness
        data_endianness = data.expr.reversed if stmt.endness == "Iend_LE" else data.expr

        # Now do the store (if we should)
        if o.DO_STORES in self.state.options:
            self.state.store_mem(addr.expr, data_endianness, endness="Iend_BE")

        # track the write
        if o.MEMORY_REFS in self.state.options:
            data_ao = SimActionObject(data.expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            size_ao = SimActionObject(data.size_bits())
            r = SimActionData(self.state, SimActionData.TMP, SimActionData.WRITE, data=data_ao, size=size_ao, addr=addr_ao)
            self.actions.append(r)

    def _handle_Exit(self, stmt):
        self.guard = self._translate_expr(stmt.guard).expr != 0

        # get the destination
        self.target = translate_irconst(self.state, stmt.dst)
        self.jumpkind = stmt.jumpkind

        #if o.CODE_REFS in self.state.options:
        #   self.actions.append(SimCodeRef(self.imark.addr, self.stmt_idx, dst, set(), set()))

    def _handle_AbiHint(self, stmt):
        # TODO: determine if this needs to do something
        pass

    def _handle_CAS(self, stmt):
        # first, get the expression of the add
        addr = self._translate_expr(stmt.addr)

        # figure out if it's a single or double
        double_element = (stmt.oldHi != 0xFFFFFFFF) and (stmt.expdHi is not None)

        if double_element:
            # translate the expected values
            expd_lo = self._translate_expr(stmt.expdLo)
            expd_hi = self._translate_expr(stmt.expdHi)

            # read the old values
            old_cnt = self.state.mem_expr(addr.expr, len(expd_lo.expr)*2/8, endness=stmt.endness)
            old_hi, old_lo = old_cnt.chop(bits=len(expd_lo))
            self.state.store_tmp(stmt.oldLo, old_lo)
            self.state.store_tmp(stmt.oldHi, old_hi)

            # the write data
            data_lo = self._translate_expr(stmt.dataLo)
            data_hi = self._translate_expr(stmt.dataHi)
            data = self.state.se.Concat(data_hi.expr, data_lo.expr)

            # do it
            self.state.store_mem(addr.expr, data, condition=self.state.se.And(old_lo == expd_lo.expr, old_hi == expd_hi.expr), endness=stmt.endness)
        else:
            # translate the expected value
            expd_lo = self._translate_expr(stmt.expdLo)

            # read the old values
            old_lo = self.state.mem_expr(addr.expr, len(expd_lo.expr)/8, endness=stmt.endness)
            self.state.store_tmp(stmt.oldLo, old_lo)

            # the write data
            data = self._translate_expr(stmt.dataLo)

            # do it
            self.state.store_mem(addr.expr, data.expr, condition=self.state.se.And(old_lo == expd_lo.expr), endness=stmt.endness)

    # Example:
    # t1 = DIRTY 1:I1 ::: ppcg_dirtyhelper_MFTB{0x7fad2549ef00}()
    def _handle_Dirty(self, stmt):
        exprs = self._translate_exprs(stmt.args())
        if stmt.tmp not in (0xffffffff, -1):
            retval_size = size_bits(self.tyenv.typeOf(stmt.tmp))

        if hasattr(s_dirty, stmt.cee.name):
            s_args = [ex.expr for ex in exprs]
            reg_deps = sum([ e.reg_deps() for e in exprs ], [ ])
            tmp_deps = sum([ e.tmp_deps() for e in exprs ], [ ])

            func = getattr(s_dirty, stmt.cee.name)
            retval, retval_constraints = func(self.state, *s_args)

            self._add_constraints(*retval_constraints)

            # FIXME: this is probably slow-ish due to the size_bits() call
            if stmt.tmp not in (0xffffffff, -1):
                self._write_tmp(stmt.tmp, retval, retval_size, reg_deps, tmp_deps)
        else:
            l.error("Unsupported dirty helper %s", stmt.cee.name)
            if o.BYPASS_UNSUPPORTED_IRDIRTY not in self.state.options:
                raise UnsupportedDirtyError("Unsupported dirty helper %s" % stmt.cee.name)
            elif stmt.tmp not in (0xffffffff, -1):
                retval = self.state.se.Unconstrained("unsupported_dirty_%s" % stmt.cee.name, retval_size)
                self._write_tmp(stmt.tmp, retval, retval_size, [], [])

            self.state.log.add_event('resilience', resilience_type='dirty', dirty=stmt.cee.name, message='unsupported Dirty call')

    def _handle_MBE(self, stmt):
        l.warning(
            "Ignoring MBE IRStmt %s. This decision might need to be revisited. SimIRStmt %s", stmt, self)

    def _handle_LoadG(self, stmt):
        addr = self._translate_expr(stmt.addr)
        alt = self._translate_expr(stmt.alt)
        guard = self._translate_expr(stmt.guard)

        read_type, converted_type = stmt.cvt_types()
        read_size = size_bytes(read_type)
        converted_size = size_bytes(converted_type)

        read_expr = self.state.mem_expr(addr.expr, read_size, endness=stmt.end, condition=guard.expr != 0, fallback=0)
        if read_size == converted_size:
            converted_expr = read_expr
        elif "S" in stmt.cvt:
            converted_expr = read_expr.sign_extend(converted_size*8 - read_size*8)
        elif "U" in stmt.cvt:
            converted_expr = read_expr.zero_extend(converted_size*8 - read_size*8)
        else:
            raise SimStatementError("Unrecognized IRLoadGOp %s!", stmt.cvt)

        # See the comments of SimIRExpr._handle_ITE for why this is as it is.
        read_expr = self.state.se.If(guard.expr != 0, converted_expr, alt.expr)

        reg_deps = addr.reg_deps() | alt.reg_deps() | guard.reg_deps()
        tmp_deps = addr.tmp_deps() | alt.tmp_deps() | guard.tmp_deps()
        self._write_tmp(stmt.dst, read_expr, converted_size*8, reg_deps, tmp_deps)

        if o.MEMORY_REFS in self.state.options:
            data_ao = SimActionObject(converted_expr)
            alt_ao = SimActionObject(alt.expr, reg_deps=alt.reg_deps(), tmp_deps=alt.tmp_deps())
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            guard_ao = SimActionObject(guard.expr, reg_deps=guard.reg_deps(), tmp_deps=guard.tmp_deps())
            size_ao = SimActionObject(size_bits(converted_type))

            r = SimActionData(self.state, self.state.memory.id, SimActionData.READ, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao, fallback=alt_ao)
            self.actions.append(r)

    def _handle_StoreG(self, stmt):
        addr = self._translate_expr(stmt.addr)
        data = self._translate_expr(stmt.data)
        guard = self._translate_expr(stmt.guard)

        self.state.store_mem(addr.expr, data.expr, condition=guard.expr == 1, endness=stmt.end)

        if o.MEMORY_REFS in self.state.options:
            data_ao = SimActionObject(data.expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            guard_ao = SimActionObject(guard.expr, reg_deps=guard.reg_deps(), tmp_deps=guard.tmp_deps())
            size_ao = SimActionObject(data.size_bits())

            r = SimActionData(self.state, self.state.memory.id, SimActionData.WRITE, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao)
            self.actions.append(r)

    def _handle_LLSC(self, stmt):
        l.warning("LLSC is handled soundly but imprecisely.")
        addr = self._translate_expr(stmt.addr)

        if stmt.storedata is None:
            # it's a load-linked
            load_size = size_bytes(self.tyenv.typeOf(stmt.result))
            data = self.state.mem_expr(addr.expr, load_size, endness=stmt.endness)
            self.state.store_tmp(stmt.result, data)
        else:
            # it's a store-conditional
            result = self.state.se.Unconstrained('llcd_result', 1)

            new_data = self._translate_expr(stmt.storedata)
            old_data = self.state.mem_expr(addr.expr, new_data.size_bytes(), endness=stmt.endness)

            store_data = self.state.se.If(result == 1, new_data.expr, old_data)
            self.state.store_mem(addr.expr, store_data)
            self.state.store_tmp(stmt.result, result)


import simuvex.s_dirty as s_dirty
from .s_helpers import size_bytes, translate_irconst, size_bits
import simuvex.s_options as o
from .s_errors import UnsupportedIRStmtError, UnsupportedDirtyError, SimStatementError
from .s_action import SimActionData, SimActionObject
from .s_irexpr import SimIRExpr

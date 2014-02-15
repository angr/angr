#!/usr/bin/env python
'''This module handles constraint generation for VEX IRStmt.'''

import symexec
import s_dirty
import s_helpers
import s_options as o
from .s_irexpr import SimIRExpr
from .s_ref import SimTmpWrite, SimRegWrite, SimMemWrite, SimCodeRef, SimMemRead

import itertools
import logging
l = logging.getLogger("s_irstmt")

loadg_counter = itertools.count()
storeg_counter = itertools.count()


class UnsupportedIRStmtType(Exception):
    pass

class SimIRStmt(object):
    '''A class for symbolically translating VEX IRStmts.'''

    __slots__ = [ 'stmt', 'imark', 'stmt_idx', 'state', 'options', 'refs', 'exit_taken', '_constraints', '_branch_constraints' ]

    def __init__(self, stmt, imark, stmt_idx, state, options):
        self.stmt = stmt
        self.imark = imark
        self.stmt_idx = stmt_idx
        self.state = state

        # the options and mode
        self.options = options

        # references by the statement
        self.refs = []
        self._constraints = [ ]
        self._branch_constraints = [ ]

        # for concrete mode, whether or not the exit was taken
        self.exit_taken = False

        func_name = "_handle_" + type(stmt).__name__
        if hasattr(self, func_name):
            l.debug("Handling IRStmt %s" % (type(stmt)))
            getattr(self, func_name)(stmt)
        else:
            raise UnsupportedIRStmtType(
                "Unsupported statement type %s" % (type(stmt)))

    def _translate_expr(self, expr):
        '''Translates an IRExpr into a SimIRExpr.'''
        e = SimIRExpr(expr, self.imark, self.stmt_idx, self.state, self.options)
        self._record_expr(e)
        return e

    def _translate_exprs(self, exprs):
        '''Translates a sequence of IRExprs into SimIRExprs.'''
        return [ self._translate_expr(e) for e in exprs ]

    def _record_expr(self, expr):
        '''Records the references of an expression.'''
        self.refs.extend(expr.refs)

    def _add_constraints(self, *constraints):
        '''Adds constraints to the state.'''
        self._constraints.extend(constraints)
        self.state.add_constraints(*constraints)

    def _add_branch_constraints(self, *constraints):
        '''Adds constraints to the state.'''
        self._branch_constraints.extend(constraints)
        self.state.add_branch_constraints(*constraints)

    def _write_tmp(self, tmp, sv, size, reg_deps, tmp_deps):
        '''Writes an expression to a tmp. If in symbolic mode, this involves adding a constraint for the tmp's symbolic variable.'''
        self.state.store_tmp(tmp, sv.expr)
        # get the size, and record the write
        if o.TMP_REFS in self.options:
            self.refs.append(
                # FIXME FIXME FIXME TODO: switch back to bits so that this works
                SimTmpWrite(self.imark.addr, self.stmt_idx, tmp, sv, (size+7) / 8, reg_deps, tmp_deps))

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
        self._write_tmp(stmt.tmp, data.sim_value, data.size_bits(), data.reg_deps(), data.tmp_deps())

    def _handle_Put(self, stmt):
        # value to put
        data = self._translate_expr(stmt.data)

        # do the put (if we should)
        if o.DO_PUTS in self.options:
            self.state.store_reg(stmt.offset, data.expr)

        # track the put
        if o.REGISTER_REFS in self.options:
            self.refs.append(
                SimRegWrite(self.imark.addr, self.stmt_idx, stmt.offset,
                            data.sim_value, data.size() / 8, data.reg_deps(), data.tmp_deps()))

    def _handle_Store(self, stmt):
        # first resolve the address and record stuff
        addr = self._translate_expr(stmt.addr)

        if o.SYMBOLIC not in self.options and addr.sim_value.is_symbolic():
            return

        # now get the value and track everything
        data = self._translate_expr(stmt.data)

        # fix endianness
        data_endianness = s_helpers.fix_endian(stmt.endness, data.expr)

        # Now do the store (if we should)
        if o.DO_STORES in self.options and (o.SYMBOLIC in self.options or not addr.sim_value.is_symbolic()):
            self.state.store_mem(addr.expr, data_endianness)

        # track the write
        data_val = self.state.expr_value(data_endianness)
        if o.MEMORY_REFS in self.options:
            self.refs.append(
                SimMemWrite(
                    self.imark.addr, self.stmt_idx, addr.sim_value, data_val,
                    data.size() / 8, addr.reg_deps(), addr.tmp_deps(), data.reg_deps(), data.tmp_deps()))

    def _handle_Exit(self, stmt):
        guard = self._translate_expr(stmt.guard)

        # track branching constraints
        if o.TRACK_CONSTRAINTS in self.options:
            self._add_branch_constraints(guard.expr != 0)

        # get the destination
        dst = self.state.expr_value(s_helpers.translate_irconst(stmt.dst))
        if o.CODE_REFS in self.options:
            self.refs.append(
                SimCodeRef(self.imark.addr, self.stmt_idx, dst, set(), set()))

        # TODO: update instruction pointer

        if o.SYMBOLIC not in self.options and guard.sim_value.is_symbolic():
            return

        if o.TAKEN_EXIT in self.options and guard.sim_value.any() != 0:
            self.exit_taken = True

    def _handle_AbiHint(self, stmt):
        # TODO: determine if this needs to do something
        pass

    def _handle_CAS(self, stmt):
        #
        # figure out if it's a single or double
        #
        double_element = (stmt.oldHi != 0xFFFFFFFF) and (
            stmt.expdHi is not None)

        #
        # first, get the expression of the add
        #
        addr_expr = self._translate_expr(stmt.addr)
        if o.SYMBOLIC not in self.options and addr_expr.sim_value.is_symbolic():
            return

        #
        # now concretize the address, since this is going to be a write
        #
        addr = self.state.memory.concretize_write_addr(addr_expr.sim_value)[0]
        self._add_constraints(addr_expr.expr == addr)

        #
        # translate the expected values
        #
        expd_lo = self._translate_expr(stmt.expdLo)
        if double_element: expd_hi = self._translate_expr(stmt.expdHi)

        # size of the elements
        element_size = expd_lo.expr.size() / 8  # pylint: disable=E1103,
        write_size = element_size if not double_element else element_size * 2

        # the two places to write
        addr_first = self.state.expr_value(symexec.BitVecVal(addr, self.state.arch.bits))
        addr_second = self.state.expr_value(symexec.BitVecVal(addr + element_size, self.state.arch.bits))

        #
        # Get the memory offsets
        #
        if not double_element:
            # single-element case
            addr_lo = addr_first
            addr_hi = None
        elif stmt.endness == "Iend_BE":
            # double-element big endian
            addr_hi = addr_first
            addr_lo = addr_second
        else:
            # double-element little endian
            addr_hi = addr_second
            addr_lo = addr_first

        #
        # save the old value
        #

        # load lo
        old_lo = self.state.mem_expr(addr_lo, element_size, endness=stmt.endness)
        old_lo_val = self.state.expr_value(old_lo)
        self._write_tmp(stmt.oldLo, old_lo_val, element_size*8, addr_expr.reg_deps(), addr_expr.tmp_deps())

        # track the write
        if o.MEMORY_REFS in self.options:
            self.refs.append(SimMemRead(self.imark.addr, self.stmt_idx, addr_lo,
                             old_lo_val, element_size, addr_expr.reg_deps(), addr_expr.tmp_deps()))

        # load hi
        old_hi = None
        if double_element:
            old_hi = self.state.mem_expr(addr_hi, element_size, endness=stmt.endness)
            old_hi_val = self.state.expr_value(old_hi)
            self._write_tmp(stmt.oldHi, old_hi_val, element_size*8, addr_expr.reg_deps(), addr_expr.tmp_deps())

            if o.MEMORY_REFS in self.options:
                self.refs.append(
                    SimMemRead(self.imark.addr, self.stmt_idx, addr_hi,
                               old_hi_val, element_size, addr_expr.reg_deps(), addr_expr.tmp_deps()))

        #
        # comparator for compare
        #
        comparator = old_lo == expd_lo.expr
        if old_hi:
            comparator = symexec.And(comparator, old_hi.expr == expd_hi.expr)

        #
        # the value to write
        #
        data_lo = self._translate_expr(stmt.dataLo)
        data_reg_deps = data_lo.reg_deps()
        data_tmp_deps = data_lo.tmp_deps()

        data_lo_end = s_helpers.fix_endian(stmt.endness, data_lo.expr)
        if double_element:
            data_hi = self._translate_expr(stmt.dataHi)
            data_reg_deps |= data_hi.reg_deps()
            data_tmp_deps |= data_hi.tmp_deps()

            data_hi_end = s_helpers.fix_endian(stmt.endness, data_hi.expr)

        # combine it to the ITE
        if not double_element:
            write_expr = symexec.If(comparator, data_lo_end, old_lo)
        elif stmt.endness == "Iend_BE":
            write_expr = symexec.If(comparator, symexec.Concat(
                data_hi_end, data_lo_end), symexec.Concat(old_hi, old_lo))
        else:
            write_expr = symexec.If(comparator, symexec.Concat(
                data_lo_end, data_hi_end), symexec.Concat(old_lo, old_hi))

        # record the write
        write_simval = self.state.expr_value(write_expr)
        if o.MEMORY_REFS in self.options:
            self.refs.append(
                SimMemWrite(
                    self.imark.addr, self.stmt_idx, addr_first, write_simval,
                    write_size, addr_expr.reg_deps(), addr_expr.tmp_deps(), data_reg_deps, data_tmp_deps))

        if o.SYMBOLIC not in self.options and symexec.is_symbolic(comparator):
            return

        # and now write, if it's enabled
        if o.DO_STORES in self.options:
            self.state.store_mem(addr_first, write_expr)

    # Example:
    # t1 = DIRTY 1:I1 ::: ppcg_dirtyhelper_MFTB{0x7fad2549ef00}()
    def _handle_Dirty(self, stmt):
        exprs = self._translate_exprs(stmt.args())

        if hasattr(s_dirty, stmt.cee.name):
            s_args = [ex.expr for ex in exprs]
            reg_deps = sum([ e.reg_deps() for e in exprs ], [ ])
            tmp_deps = sum([ e.tmp_deps() for e in exprs ], [ ])

            func = getattr(s_dirty, stmt.cee.name)
            retval, retval_constraints = func(self.state, *s_args)

            self._add_constraints(retval_constraints)
            sim_value = self.state.expr_value(retval)

            # FIXME: this is probably slow-ish due to the size() call
            self._write_tmp(stmt.tmp, sim_value, retval.size(), reg_deps, tmp_deps)
        else:
            raise Exception("Unsupported dirty helper %s" % stmt.cee.name)

    def _handle_MBE(self, stmt):
        l.warning(
            "Ignoring MBE IRStmt %s. This decision might need to be revisited. SimIRStmt %s", stmt, self)

    def _handle_LoadG(self, stmt):
        addr = self._translate_expr(stmt.addr)
        alt = self._translate_expr(stmt.alt)
        guard = self._translate_expr(stmt.guard)

        read_type, converted_type = stmt.cvt_types()
        read_size = s_helpers.size_bytes(read_type)
        converted_size = s_helpers.size_bytes(converted_type)

        read_expr = self.state.mem_expr(addr.expr, read_size, endness=stmt.end)
        if read_size == converted_size:
            converted_expr = read_expr
        elif "S" in stmt.cvt:
            converted_expr = symexec.SignExt(converted_size - read_size, read_expr)
        elif "U" in stmt.cvt:
            converted_expr = symexec.ZeroExt(converted_size - read_size, read_expr)
        else:
            raise Exception("Unrecognized IRLoadGOp %s!", stmt.cvt)

        # See the comments of SimIRExpr._handle_ITE for why this is as it is.
        if o.SYMBOLIC in self.options:
            read_expr = symexec.BitVec("loadg_%d" % loadg_counter.next(), converted_size*8)
            self._add_constraints(symexec.Or(symexec.And(guard.expr != 0, read_expr == converted_expr), symexec.And(guard.expr == 0, read_expr == alt.expr)))
        else:
            read_expr = symexec.If(guard.expr != 0, converted_expr, alt.expr)

        reg_deps = addr.reg_deps() | alt.reg_deps() | guard.reg_deps()
        tmp_deps = addr.tmp_deps() | alt.tmp_deps() | guard.tmp_deps()
        self._write_tmp(stmt.dst, self.state.expr_value(read_expr), read_size*8, reg_deps, tmp_deps)

    def _handle_StoreG(self, stmt):
        addr = self._translate_expr(stmt.addr)
        data = self._translate_expr(stmt.data)
        guard = self._translate_expr(stmt.guard)

        #
        # now concretize the address, since this is going to be a write
        #
        concrete_addr = self.state.memory.concretize_write_addr(addr.sim_value)[0]
        self._add_constraints(addr.expr == concrete_addr)

        write_size = data.size()
        old_data = self.state.mem_expr(concrete_addr, write_size, endness=stmt.end)

        # See the comments of SimIRExpr._handle_ITE for why this is as it is.
        if o.SYMBOLIC in self.options:
            write_expr = symexec.BitVec("storeg_%d" % storeg_counter.next(), write_size*8)
            self._add_constraints(symexec.Or(symexec.And(guard.expr != 0, write_expr == data.expr), symexec.And(guard.expr == 0, write_expr == old_data)))
        else:
            write_expr = symexec.If(guard.expr != 0, data.expr, old_data)

        self.state.store_mem(concrete_addr, write_expr, endness=stmt.end)

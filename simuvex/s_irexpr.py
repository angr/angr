#!/usr/bin/env python
'''This module handles constraint generation.'''

import symexec
from .s_ref import SimTmpRead, SimRegRead, SimMemRead, SimMemRef

import logging
l = logging.getLogger("s_irexpr")

class UnsupportedIRExprType(Exception):
    pass

class SimIRExpr(object):
    __slots__ = ['options', 'state', '_constraints', 'imark', 'stmt_idx', 'refs', '_post_processed', 'sim_value', 'expr', 'type', 'child_exprs' ]

    def __init__(self, expr, imark, stmt_idx, state):
        self.state = state
        self._constraints = [ ]
        self.imark = imark
        self.stmt_idx = stmt_idx
        self.child_exprs = [ ]

        # effects tracking
        self.refs = [ ]
        self._post_processed = False

        self.sim_value = None
        self.expr = None
        self.type = None

        func_name = "_handle_" + type(expr).__name__
        l.debug("Looking for handler for IRExpr %s", type(expr))
        if hasattr(self, func_name):
            getattr(self, func_name)(expr)
        else:
            raise UnsupportedIRExprType("Unsupported expression type %s" % (type(expr)))

        self._post_process()

    # A post-processing step for the helpers. Simplifies constants, checks for memory references, etc.
    def _post_process(self):
        if self._post_processed: return
        self._post_processed = True

        if o.SIMPLIFY_CONSTANTS in self.state.options:
            self.expr = symexec.simplify_expression(self.expr)

        self.state.add_constraints(*self._constraints)
        self.sim_value = self.make_sim_value()

        if self.sim_value.is_symbolic() and o.CONCRETIZE in self.state.options:
            self.make_concrete()

        if (
            o.MEMORY_MAPPED_REFS in self.state.options and
                (o.SYMBOLIC in self.state.options or not self.sim_value.is_symbolic()) and
                self.sim_value.any() in self.state['memory'] and
                self.sim_value.any() != self.imark.addr + self.imark.len
            ):
            self.refs.append(SimMemRef(self.imark.addr, self.stmt_idx, self.sim_value, self.reg_deps(), self.tmp_deps()))

    def size_bits(self):
        if self.type is not None:
            return size_bits(self.type)

        l.info("Calling out to sim_value.size(). MIGHT BE SLOW")
        return self.make_sim_value().size()

    def size(self):
        s = self.size_bits()
        if s % 8 != 0:
            raise Exception("SimIRExpr.size() called for a non-byte size!")
        return s/8

    def make_sim_value(self):
        return self.state.expr_value(self.expr)

    # Returns a set of registers that this IRExpr depends on.
    def reg_deps(self):
        return set([r.offset for r in self.refs if type(r) == SimRegRead])

    # Returns a set of tmps that this IRExpr depends on
    def tmp_deps(self):
        return set([r.tmp for r in self.refs if type(r) == SimTmpRead])

    def _translate_expr(self, expr):
        '''Translate a single IRExpr, honoring mode and options and so forth. Also updates state...'''
        e = SimIRExpr(expr, self.imark, self.stmt_idx, self.state)
        self._record_expr(e)
        self.child_exprs.append(e)
        return e

    def _translate_exprs(self, exprs):
        '''Translates a sequence of IRExprs into SimIRExprs.'''
        return [ self._translate_expr(e) for e in exprs ]

    # track references in other expressions
    def _record_expr(self, *others):
        for e in others:
            self.refs.extend(e.refs)

    # Concretize this expression
    def make_concrete(self):
        size = self.size()
        concrete_value = self.sim_value.any()
        self._constraints.append(self.expr == concrete_value)
        self.state.add_constraints(self.expr == concrete_value)
        self.expr = symexec.BitVecVal(concrete_value, size*8)

    ###########################
    ### expression handlers ###
    ###########################

    def _handle_Get(self, expr):
        size = size_bytes(expr.type)
        self.type = expr.type

        # get it!
        self.expr = self.state.reg_expr(expr.offset, size)

        # finish it and save the register references
        self._post_process()
        if o.REGISTER_REFS in self.state.options:
            self.refs.append(SimRegRead(self.imark.addr, self.stmt_idx, expr.offset, self.sim_value, size))

    def _handle_op(self, expr):
        exprs = self._translate_exprs(expr.args())
        self.expr = translate(expr.op, [ e.expr for e in exprs ])

    _handle_Unop = _handle_op
    _handle_Binop = _handle_op
    _handle_Triop = _handle_op
    _handle_Qop = _handle_op

    def _handle_RdTmp(self, expr):
        self.expr = self.state.tmp_expr(expr.tmp)

        # finish it and save the tmp reference
        self._post_process()
        if o.TMP_REFS in self.state.options:
            self.refs.append(SimTmpRead(self.imark.addr, self.stmt_idx, expr.tmp, self.state.expr_value(self.expr), (self.size_bits()+7)/8))

    def _handle_Const(self, expr):
        self.expr = translate_irconst(expr.con)

    def _handle_Load(self, expr):
        # size of the load
        size = size_bytes(expr.type)
        self.type = expr.type

        # get the address expression and track stuff
        addr = self._translate_expr(expr.addr)

        # if we got a symbolic address and we're not in symbolic mode, just return a symbolic value to deal with later
        if o.DO_LOADS not in self.state.options or o.SYMBOLIC not in self.state.options and addr.sim_value.is_symbolic():
            self.expr = self.state.new_symbolic("sym_expr_0x%x_%d" % (self.imark.addr, self.stmt_idx), size*8)
        else:
            # load from memory and fix endianness
            self.expr = self.state.mem_expr(addr.sim_value, size, endness=expr.endness)

        # finish it and save the mem read
        self._post_process()
        if o.MEMORY_REFS in self.state.options:
            self.refs.append(SimMemRead(self.imark.addr, self.stmt_idx, addr.sim_value, self.make_sim_value(), size, addr.reg_deps(), addr.tmp_deps()))

    def _handle_CCall(self, expr):
        exprs = self._translate_exprs(expr.args())

        if hasattr(simuvex.s_ccall, expr.callee.name):
            s_args = [ e.expr for e in exprs ]
            func = getattr(simuvex.s_ccall, expr.callee.name)
            self.expr, retval_constraints = func(self.state, *s_args)
            self._constraints.extend(retval_constraints)
        else:
            raise Exception("Unsupported callee %s" % expr.callee.name)

    def _handle_ITE(self, expr):
        cond = self._translate_expr(expr.cond)
        expr0 = self._translate_expr(expr.iffalse)
        exprX = self._translate_expr(expr.iftrue)

        self.expr, constraints = sim_ite(self.state, cond.expr == 0, expr0.expr, exprX.expr, sym_size=expr0.size_bits())
        self._constraints.extend(constraints)

from .s_irop import translate
import simuvex.s_ccall
from .s_helpers import size_bits, size_bytes, sim_ite, translate_irconst
import simuvex.s_options as o

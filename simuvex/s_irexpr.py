#!/usr/bin/env python
'''This module handles constraint generation.'''

from .s_ref import SimTmpRead, SimRegRead, SimMemRead, SimMemRef

import logging
l = logging.getLogger("s_irexpr")

class UnsupportedIRExprType(Exception):
    pass

class SimIRExpr(object):
    __slots__ = ['options', 'state', '_constraints', 'imark', 'stmt_idx', 'refs', '_post_processed', 'expr', 'type', 'child_exprs' ]

    def __init__(self, expr, imark, stmt_idx, state):
        self.state = state
        self._constraints = [ ]
        self.imark = imark
        self.stmt_idx = stmt_idx
        self.child_exprs = [ ]

        # effects tracking
        self.refs = [ ]
        self._post_processed = False

        self.expr = None
        self.type = None

        self.state._inspect('expr', BP_BEFORE)


        func_name = "_handle_" + type(expr).__name__
        l.debug("Looking for handler for IRExpr %s", type(expr))
        if hasattr(self, func_name):
            getattr(self, func_name)(expr)
        else:
            raise UnsupportedIRExprType("Unsupported expression type %s" % (type(expr)))

        self._post_process()
        self.state._inspect('expr', BP_AFTER, expr=self.expr)

    # A post-processing step for the helpers. Simplifies constants, checks for memory references, etc.
    def _post_process(self):
        if self._post_processed: return
        self._post_processed = True

        if o.SIMPLIFY_CONSTANTS in self.state.options:
            self.expr = self.expr.simplify()

        self.state.add_constraints(*self._constraints)

        if self.state.symbolic(self.expr) and o.CONCRETIZE in self.state.options:
            self.make_concrete()

        if (
            o.MEMORY_MAPPED_REFS in self.state.options and
                (o.SYMBOLIC in self.state.options or not self.state.symbolic(self.expr)) and
                self.state.any(self.expr) in self.state['memory'] and
                self.state.any(self.expr) != self.imark.addr + self.imark.len
            ):
            self.refs.append(SimMemRef(self.imark.addr, self.stmt_idx, self.expr, self.reg_deps(), self.tmp_deps()))

    def size_bits(self):
        if self.type is not None:
            return size_bits(self.type)

        l.info("Calling out to sim_value.size_bits(). MIGHT BE SLOW")
        return len(self.expr)

    def size_bytes(self):
        s = self.size_bits()
        if s % 8 != 0:
            raise Exception("SimIRExpr.size_bytes() called for a non-byte size!")
        return s/8

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
        concrete_value = self.state.any(self.expr)
        self._constraints.append(self.expr == concrete_value)
        self.state.add_constraints(self.expr == concrete_value)
        self.expr = concrete_value

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
            self.refs.append(SimRegRead(self.imark.addr, self.stmt_idx, expr.offset, self.expr, size))

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
            self.refs.append(SimTmpRead(self.imark.addr, self.stmt_idx, expr.tmp, self.expr, (self.size_bits()+7)/8))

    def _handle_Const(self, expr):
        self.expr = translate_irconst(self.state, expr.con)

    def _handle_Load(self, expr):
        # size of the load
        size = size_bytes(expr.type)
        self.type = expr.type

        # get the address expression and track stuff
        addr = self._translate_expr(expr.addr)

        # if we got a symbolic address and we're not in symbolic mode, just return a symbolic value to deal with later
        if o.DO_LOADS not in self.state.options or o.SYMBOLIC not in self.state.options and self.state.symbolic(addr.expr):
            self.expr = self.state.BV("sym_expr_0x%x_%d" % (self.imark.addr, self.stmt_idx), size*8)
        else:
            # load from memory and fix endianness
            self.expr = self.state.mem_expr(addr.expr, size, endness=expr.endness)

        # finish it and save the mem read
        self._post_process()
        if o.MEMORY_REFS in self.state.options:
            self.refs.append(SimMemRead(self.imark.addr, self.stmt_idx, addr.expr, self.expr, size, addr.reg_deps(), addr.tmp_deps()))

    def _handle_CCall(self, expr):
        exprs = self._translate_exprs(expr.args())

        if o.DO_CCALLS not in self.state.options:
            self.expr = self.state.BV("ccall_ret", self.state.arch.bits)
            return

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

        self.expr = self.state.claripy.If(cond.expr == 0, expr0.expr, exprX.expr, sym_size=expr0.size_bits())

from .s_irop import translate
import simuvex.s_ccall
from .s_helpers import size_bits, size_bytes, translate_irconst
import simuvex.s_options as o
from .s_inspect import BP_AFTER, BP_BEFORE

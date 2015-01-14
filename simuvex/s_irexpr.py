#!/usr/bin/env python
'''This module handles constraint generation.'''

import logging
l = logging.getLogger("s_irexpr")

class SimIRExpr(object):
    def __init__(self, expr, imark, stmt_idx, state, tyenv):
        self.tyenv = tyenv
        self.state = state
        self._constraints = [ ]
        self.imark = imark
        self.stmt_idx = stmt_idx
        self.child_exprs = [ ]

        # effects tracking
        self.actions = [ ]
        self._post_processed = False

        self.expr = None
        if expr.tag in ('Iex_BBPTR', 'Iex_VECRET'):
            self.type = None
        else:
            self.type = tyenv.typeOf(expr)

        self.state._inspect('expr', BP_BEFORE)

        func_name = "_handle_" + type(expr).__name__
        l.debug("Looking for handler for IRExpr %s", type(expr))
        if hasattr(self, func_name):
            getattr(self, func_name)(expr)
        else:
            l.error("Unsupported IRExpr %s. Please implement.", type(expr).__name__)

            if o.BYPASS_UNSUPPORTED_IREXPR in self.state.options:
                self.expr = self.state.se.Unconstrained(type(expr).__name__, self.size_bits())
                self.state.log.add_event('resilience', resilience_type='irexpr', expr=type(expr).__name__, message='unsupported irexpr')
            else:
                raise UnsupportedIRExprError("Unsupported expression type %s" % (type(expr)))

        self._post_process()
        self.state._inspect('expr', BP_AFTER, expr=self.expr)

        del self.tyenv

    # A post-processing step for the helpers. Simplifies constants, checks for memory references, etc.
    def _post_process(self):
        if self._post_processed: return
        self._post_processed = True

        if o.SIMPLIFY_EXPRS in self.state.options:
            self.expr = self.state.se.simplify(self.expr)

        self.state.add_constraints(*self._constraints)

        if self.state.se.symbolic(self.expr) and o.CONCRETIZE in self.state.options:
            self.make_concrete()

        if self.expr.size() != self.size_bits():
            raise SimExpressionError("Inconsistent expression size: should be %d but is %d" % (self.size_bits(), self.expr.size()))

    def size_bits(self):
        if self.type is not None:
            return size_bits(self.type)
        return len(self.expr)

    def size_bytes(self):
        s = self.size_bits()
        if s % 8 != 0:
            raise Exception("SimIRExpr.size_bytes() called for a non-byte size!")
        return s/8

    def _translate_expr(self, expr):
        '''Translate a single IRExpr, honoring mode and options and so forth. Also updates state...'''
        e = SimIRExpr(expr, self.imark, self.stmt_idx, self.state, self.tyenv)
        self._record_expr(e)
        self.child_exprs.append(e)
        return e

    def _translate_exprs(self, exprs):
        '''Translates a sequence of IRExprs into SimIRExprs.'''
        return [ self._translate_expr(e) for e in exprs ]

    # track references in other expressions
    def _record_expr(self, *others):
        for e in others:
            self.actions.extend(e.actions)

    # Concretize this expression
    def make_concrete(self):
        concrete_value = self.state.se.any_int(self.expr)
        self._constraints.append(self.expr == concrete_value)
        self.state.add_constraints(self.expr == concrete_value)
        self.expr = concrete_value

    def reg_deps(self):
        '''
        Returns a set of registers that this IRExpr depends on.
        '''
        if len(self.actions) == 0:
            return set()
        else:
            return set.union(*[r.reg_deps for r in self.actions if type(r) == SimActionData])

    def tmp_deps(self):
        '''
        Returns a set of tmps that this IRExpr depends on
        '''
        if len(self.actions) == 0:
            return set()
        else:
            return set.union(*[r.tmp_deps for r in self.actions if type(r) == SimActionData])

    ###########################
    ### expression handlers ###
    ###########################

    def _handle_BBPTR(self, expr): #pylint:disable=unused-argument
        l.warning("BBPTR IRExpr encountered. This is (probably) not bad, but we have no real idea how to handle it.")
        self.type = "Ity_I32"
        self.expr = self.state.BVV("WTF!")

    def _handle_VECRET(self, expr): #pylint:disable=unused-argument
        l.warning("VECRET IRExpr encountered. This is (probably) not bad, but we have no real idea how to handle it.")
        self.type = "Ity_I32"
        self.expr = self.state.BVV("OMG!")

    def _handle_Get(self, expr):
        size = size_bytes(expr.type)
        self.type = expr.type

        # get it!
        self.expr = self.state.reg_expr(expr.offset, size)

        # finish it and save the register references
        self._post_process()
        if o.REGISTER_REFS in self.state.options:
            r = SimActionData(self.state, self.state.registers.id, SimActionData.READ, offset=expr.offset, size=size, data=self.expr)
            self.actions.append(r)

    def _handle_op(self, expr):
        exprs = self._translate_exprs(expr.args())
        try:
            self.expr = translate(self.state, expr.op, [ e.expr for e in exprs ])
        except UnsupportedIROpError:
            if o.BYPASS_UNSUPPORTED_IROP in self.state.options:
                self.state.log.add_event('resilience', resilience_type='irop', op=expr.op, message='unsupported IROp')
                self.expr = self.state.se.Unconstrained(type(expr).__name__, self.size_bits())
            else:
                raise

    _handle_Unop = _handle_op
    _handle_Binop = _handle_op
    _handle_Triop = _handle_op
    _handle_Qop = _handle_op

    def _handle_RdTmp(self, expr):
        self.expr = self.state.tmp_expr(expr.tmp)

        # finish it and save the tmp reference
        self._post_process()
        if o.TMP_REFS in self.state.options:
            r = SimActionData(self.state, SimActionData.TMP, SimActionData.READ, tmp=expr.tmp, size=self.size_bits(), data=self.expr)
            self.actions.append(r)

    def _handle_Const(self, expr):
        self.expr = translate_irconst(self.state, expr.con)

    def _handle_Load(self, expr):
        # size of the load
        size = size_bytes(expr.type)
        self.type = expr.type

        # get the address expression and track stuff
        addr = self._translate_expr(expr.addr)

        # if we got a symbolic address and we're not in symbolic mode, just return a symbolic value to deal with later
        if o.DO_LOADS not in self.state.options:
            self.expr = self.state.se.Unconstrained("load_expr_0x%x_%d" % (self.imark.addr, self.stmt_idx), size*8)
        else:
            # load from memory and fix endianness
            self.expr = self.state.mem_expr(addr.expr, size, endness=expr.endness)

        # finish it and save the mem read
        self._post_process()
        if o.MEMORY_REFS in self.state.options:
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            r = SimActionData(self.state, self.state.memory.id, SimActionData.READ, addr=addr_ao, size=size_bits(expr.type), data=self.expr)
            self.actions.append(r)

    def _handle_CCall(self, expr):
        exprs = self._translate_exprs(expr.args())

        if o.DO_CCALLS not in self.state.options:
            self.expr = self.state.se.Unconstrained("ccall_ret", size_bits(expr.ret_type))
            return

        if hasattr(simuvex.s_ccall, expr.callee.name):
            s_args = [ e.expr for e in exprs ]

            try:
                func = getattr(simuvex.s_ccall, expr.callee.name)
                self.expr, retval_constraints = func(self.state, *s_args)
                self._constraints.extend(retval_constraints)
            except SimCCallError:
                if o.BYPASS_ERRORED_IRCCALL not in self.state.options:
                    raise
                self.state.log.add_event('resilience', resilience_type='ccall', callee=expr.callee.name, message='ccall raised SimCCallError')
                self.expr = self.state.se.Unconstrained("errored_%s" % expr.callee.name, size_bits(expr.ret_type))
        else:
            l.error("Unsupported CCall %s", expr.callee.name)
            if o.BYPASS_UNSUPPORTED_IRCCALL in self.state.options:
                self.expr = self.state.se.Unconstrained("unsupported_%s" % expr.callee.name, size_bits(expr.ret_type))
                self.state.log.add_event('resilience', resilience_type='ccall', callee=expr.callee.name, message='unsupported ccall')
            else:
                raise UnsupportedCCallError("Unsupported CCall %s" % expr.callee.name)

    def _handle_ITE(self, expr):
        cond = self._translate_expr(expr.cond)
        expr0 = self._translate_expr(expr.iffalse)
        exprX = self._translate_expr(expr.iftrue)

        self.expr = self.state.se.If(cond.expr == 0, expr0.expr, exprX.expr)

from .s_irop import translate
import simuvex.s_ccall
from .s_helpers import size_bits, size_bytes, translate_irconst
import simuvex.s_options as o
from .plugins.inspect import BP_AFTER, BP_BEFORE
from .s_errors import UnsupportedIRExprError, UnsupportedIROpError, UnsupportedCCallError, SimCCallError, SimExpressionError
from .s_action import SimActionData, SimActionObject

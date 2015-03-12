#!/usr/bin/env python
'''This module handles constraint generation.'''

import logging
l = logging.getLogger("simuvex.vex.expressions.base")

_nonset = frozenset()

class SimIRExpr(object):
    def __init__(self, expr, imark, stmt_idx, state):
        self.state = state
        self._constraints = [ ]
        self.imark = imark
        self.stmt_idx = stmt_idx
        self.child_exprs = [ ]

        # effects tracking
        self.actions = [ ]
        self._post_processed = False

        # delete later
        self._expr = expr

        self.expr = None
        if expr.tag in ('Iex_BBPTR', 'Iex_VECRET'):
            self.type = None
        else:
            self.type = expr.result_type

        self.state._inspect('expr', BP_BEFORE)

    def process(self):
        '''
        Process the expression in whatever ways are specified by the state options.
        '''

        # this should change when additional analyses are implemented
        self._execute()

        self._post_process()
        self.state._inspect('expr', BP_AFTER, expr=self.expr)

    def _execute(self):
        raise NotImplementedError()

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
        e = translate_expr(expr, self.imark, self.stmt_idx, self.state)
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
        if len(self.actions) == 0 or o.ACTION_DEPS not in self.state.options:
            return _nonset
        else:
            return frozenset.union(*[r.reg_deps for r in self.actions if type(r) == SimActionData])

    def tmp_deps(self):
        '''
        Returns a set of tmps that this IRExpr depends on
        '''
        if len(self.actions) == 0 or o.ACTION_DEPS not in self.state.options:
            return _nonset
        else:
            return frozenset.union(*[r.tmp_deps for r in self.actions if type(r) == SimActionData])

from .. import size_bits
from ... import s_options as o
from ...plugins.inspect import BP_AFTER, BP_BEFORE
from ...s_errors import SimExpressionError
from ...s_action import SimActionData
from . import translate_expr

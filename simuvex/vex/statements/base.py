import logging
l = logging.getLogger("simuvex.vex.statements")

class SimIRStmt(object):
    '''A class for symbolically translating VEX IRStmts.'''

    def __init__(self, irsb, stmt_idx, imark, state):
        self.imark = imark
        self.stmt_idx = stmt_idx
        self.state = state

        # temporarily store this
        self.stmt = irsb.statements[stmt_idx]
        self.irsb = irsb

        # references by the statement
        self.actions = []
        self._constraints = [ ]

    def process(self):
        '''
        Process the statement, applying its effects on the state.
        '''

        # this is where we would choose between different analysis modes
        self._execute()

        del self.stmt
        del self.irsb

    def _execute(self):
        raise NotImplementedError()

    def _translate_expr(self, expr):
        '''Translates an IRExpr into a SimIRExpr.'''
        e = translate_expr(expr, self.imark, self.stmt_idx, self.state)
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
        self.state.scratch.store_tmp(tmp, v)

        # get the size, and record the write
        if o.TRACK_TMP_ACTIONS in self.state.options:
            data_ao = SimActionObject(v, reg_deps=reg_deps, tmp_deps=tmp_deps)
            r = SimActionData(self.state, SimActionData.TMP, SimActionData.WRITE, tmp=tmp, data=data_ao, size=size)
            self.actions.append(r)

from ... import s_options as o
from ...s_action import SimActionData, SimActionObject
from ..expressions import translate_expr

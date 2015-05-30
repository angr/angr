#!/usr/bin/env python

from .plugin import SimStatePlugin
from ..s_action_object import ast_stripping_op as _actual_ast_stripping_op

import sys
import functools
import logging
l = logging.getLogger('simuvex.plugins.solver')

#pylint:disable=unidiomatic-typecheck

#
# Timing stuff
#

import time
lt = logging.getLogger('simuvex.plugins.solver.timing')
def _timed_ast_stripping_op(f, self, *args, **kwargs):
    start = time.time()
    r = _actual_ast_stripping_op(f, self, *args, **kwargs)
    end = time.time()
    duration = end-start
    lt.log(int((end-start)*10), 'SimSolver.%s took %s seconds', f.__name__, duration)
    return r
ast_stripping_op = _actual_ast_stripping_op

def enable_timing():
    global ast_stripping_op
    lt.setLevel(1)
    ast_stripping_op = _timed_ast_stripping_op

def disable_timing():
    global ast_stripping_op
    ast_stripping_op = _actual_ast_stripping_op

disable_timing()

#
# Various over-engineered crap
#

def auto_actions(f):
    @functools.wraps(f)
    def autoed_f(self, *args, **kwargs):
        return ast_stripping_op(f, self, *args, **kwargs)
    return autoed_f

def unsat_catcher(f):
    @functools.wraps(f)
    def wrapped_f(self, *args, **kwargs):
        try:
            return f(self, *args, **kwargs)
        except claripy.UnsatError:
            e_type, value, traceback = sys.exc_info()
            raise SimUnsatError, ("Got an unsat result", e_type, value), traceback
    return wrapped_f

def symbolic_guard(f):
    @functools.wraps(f)
    def guarded_f(self, *args, **kwargs):
        e = args[0]
        if o.SYMBOLIC not in self.state.options and self.symbolic(e):
            raise SimSolverModeError('SimSolver.%s() called on a symbolic variable without SYMBOLIC option' % f.__name__)
        return f(self, *args, **kwargs)
    return guarded_f

import claripy
class SimSolver(SimStatePlugin):
    def __init__(self, solver=None, claripy=None): #pylint:disable=redefined-outer-name
        l.debug("Creating SimSolverClaripy.")
        SimStatePlugin.__init__(self)

        self._claripy = claripy
        self._stored_solver = solver

    def _ana_getstate(self):
        return self._stored_solver, self.state

    def _ana_setstate(self, s):
        self._stored_solver, self.state = s
        self._claripy = None

    def set_state(self, state):
        SimStatePlugin.set_state(self, state)

        if self._claripy is None:
            if o.ABSTRACT_SOLVER in self.state.options:
                self._claripy = claripy.Claripies['VSA']
            #elif o.SYMBOLIC not in self.state.options:
            #   self._claripy = claripy.Claripies['Concrete']
            elif o.PARALLEL_SOLVES in self.state.options:
                self._claripy = claripy.Claripies['ParallelZ3']
            else:
                self._claripy = claripy.Claripies['SerialZ3']

    @property
    def _solver(self):
        if self._stored_solver is not None:
            return self._stored_solver

        if o.COMPOSITE_SOLVER in self.state.options:
            self._stored_solver = self._claripy.composite_solver()
        else:
            self._stored_solver = self._claripy.solver()
        return self._stored_solver

    @property
    def constraints(self):
        return self._solver.constraints

    #
    # Get unconstrained stuff
    #
    def Unconstrained(self, name, bits, **kwargs):
        if o.SYMBOLIC_INITIAL_VALUES in self.state.options:
            # Return a symbolic value
            if o.ABSTRACT_MEMORY in self.state.options:
                l.debug("Creating new top StridedInterval")
                r = self._claripy.TSI(bits=bits, name=name, signed=True, uninitialized=True, **kwargs)
            else:
                l.debug("Creating new unconstrained BV named %s", name)
                r = self._claripy.BitVec(name, bits, **kwargs)

            self.state.log.add_event('unconstrained', name=iter(r.variables).next(), bits=bits, **kwargs)
            return r
        else:
            # Return a default value, aka. 0
            return self._claripy.BitVecVal(0, bits)

    #
    # Various passthroughs
    #

    def downsize(self):
        return self._solver.downsize()

    def __getattr__(self, a):
        f = getattr(self._claripy, a)
        if hasattr(f, '__call__'):
            return functools.partial(ast_stripping_op, f)
        else:
            return f

    @auto_actions
    def add(self, *constraints):
        return self._solver.add(constraints)

    @unsat_catcher
    @auto_actions
    def satisfiable(self, **kwargs):
        if o.SYMBOLIC not in self.state.options:
            if self._solver._results is None:
                return True
            else:
                return self._solver._results.satness

        return self._solver.satisfiable(**kwargs)

    @unsat_catcher
    @auto_actions
    @symbolic_guard
    def solution(self, e, v, **kwargs):
        return self._solver.solution(e, v, **kwargs)


    #
    # And these return raw results
    #

    @unsat_catcher
    @auto_actions
    @symbolic_guard
    def any_raw(self, e, extra_constraints=()):
        return self._solver.eval(e, 1, extra_constraints=extra_constraints)[0]

    @symbolic_guard
    @auto_actions
    def any_n_raw(self, e, n, extra_constraints=()):
        try:
            return self._solver.eval(e, n, extra_constraints=extra_constraints)
        except claripy.UnsatError:
            return [ ]

    @unsat_catcher
    @auto_actions
    @symbolic_guard
    def min_raw(self, e, extra_constraints=()):
        return self._solver.min(e, extra_constraints=extra_constraints)

    @unsat_catcher
    @auto_actions
    @symbolic_guard
    def max_raw(self, e, extra_constraints=()):
        return self._solver.max(e, extra_constraints=extra_constraints)

    def symbolic(self, e): # pylint:disable=R0201
        if type(e) in (int, str, float, bool, long, claripy.BVV):
            return False
        return e.symbolic

    def simplify(self, *args):
        if len(args) == 0:
            return self._solver.simplify()
        elif isinstance(args[0], claripy.Base):
            return self._claripy.simplify(args[0])
        else:
            return args[0]

    def variables(self, e): #pylint:disable=no-self-use
        return e.variables

    #
    # Branching stuff
    #

    def copy(self):
        return SimSolver(solver=self._solver.branch(), claripy=self._claripy)

    def merge(self, others, merge_flag, flag_values): # pylint: disable=W0613
        #import ipdb; ipdb.set_trace()
        merging_occurred, self._stored_solver = self._solver.merge([ oc._solver for oc in others ], merge_flag, flag_values)
        #import ipdb; ipdb.set_trace()
        return merging_occurred, [ ]

    def widen(self, others, merge_flag, flag_values):

        merging_occurred, _ = self.merge(others, merge_flag, flag_values)

        return merging_occurred

    #
    # Other stuff
    #

    def any_str(self, e, extra_constraints=()):
        return self.any_n_str(e, 1, extra_constraints=extra_constraints)[0]

    def any_n_str_iter(self, e, n, extra_constraints=()):
        for s in self.any_n_raw(e, n, extra_constraints=extra_constraints):
            if type(s) not in (int, long):
                yield ("%x" % s.value).zfill(s.bits/4).decode('hex')
            else:
                ss = "%x"%s
                ss = ss.zfill(len(ss)%2+len(ss))
                yield ss.decode('hex')

    def any_n_str(self, e, n, extra_constraints=()):
        return list(self.any_n_str_iter(e, n, extra_constraints=extra_constraints))

    def any_int(self, e, extra_constraints=()):
        r = self.any_raw(e, extra_constraints=extra_constraints)
        return r.value if type(r) is claripy.BVV else r

    def any_n_int(self, e, n, extra_constraints=()):
        rr = self.any_n_raw(e, n, extra_constraints=extra_constraints)
        return [ r.value if type(r) is claripy.BVV else r for r in rr ]

    def min_int(self, e, extra_constraints=()):
        r = self.min_raw(e, extra_constraints=extra_constraints)
        return r.value if type(r) is claripy.BVV else r

    def max_int(self, e, extra_constraints=()):
        r = self.max_raw(e, extra_constraints=extra_constraints)
        return r.value if type(r) is claripy.BVV else r

    def exactly_n(self, e, n, extra_constraints=()):
        r = self.any_n_raw(e, n, extra_constraints=extra_constraints)
        if len(r) != n:
            raise SimValueError("concretized %d values (%d required) in exactly_n" % (len(r), n))
        return r

    def exactly_n_int(self, e, n, extra_constraints=()):
        r = self.any_n_int(e, n, extra_constraints=extra_constraints)
        if len(r) != n:
            raise SimValueError("concretized %d values (%d required) in exactly_n" % (len(r), n))
        return r

    def exactly_int(self, e, extra_constraints=(), default=None):
        try:
            r = self.any_n_int(e, 1, extra_constraints=extra_constraints)
        except (SimValueError, SimSolverModeError):
            if default is not None:
                return default
            raise

        if len(r) != 1:
            if default is None:
                raise SimValueError("concretized %d values (%d required) in exactly_int", len(r), 1)
            else:
                return default
        return r[0]

    @auto_actions
    def unique(self, e, extra_constraints=()):
        if not isinstance(e, claripy.Base):
            return True

        # if we don't want to do symbolic checks, assume symbolic variables are multivalued
        if o.SYMBOLIC not in self.state.options and self.symbolic(e):
            return False

        r = self.any_n_raw(e, 2, extra_constraints=extra_constraints)
        if len(r) == 1:
            self.add(e == r[0])
            return True
        elif len(r) == 0:
            raise SimValueError("unsatness during uniqueness check(ness)")
        else:
            return False

SimStatePlugin.register_default('solver_engine', SimSolver)
from .. import s_options as o
from ..s_errors import SimValueError, SimUnsatError, SimSolverModeError

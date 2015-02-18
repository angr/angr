#!/usr/bin/env python

from .plugin import SimStatePlugin

import sys
import functools
import logging
l = logging.getLogger("simuvex.s_solver")

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
        if o.SYMBOLIC in self.state.options or o.SYMBOLIC_INITIAL_VALUES in self.state.options:
            # Return a symbolic value
            if o.ABSTRACT_MEMORY in self.state.options:
                l.debug("Creating new zero StridedInterval")
                r = self._claripy.TSI(bits=bits, name=name, signed=True, **kwargs)
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

    def __getattribute__(self, a):
        try:
            f = SimStatePlugin.__getattribute__(self, a)
        except AttributeError:
            f = getattr(self._claripy, a)

        state = object.__getattribute__(self, 'state')
        if not hasattr(f, '__call__') or state is None:
            return f
        elif o.AST_DEPS in state.options:
            return functools.partial(ast_preserving_op, f)
        else:
            return f

    def add(self, *constraints):
        return self._solver.add(constraints)

    @unsat_catcher
    def satisfiable(self, **kwargs):
        if o.SYMBOLIC not in self.state.options:
            if self._solver._results is None:
                return True
            else:
                return self._solver._results.satness

        return self._solver.satisfiable(**kwargs)

    @unsat_catcher
    @symbolic_guard
    def solution(self, e, v, **kwargs):
        return self._solver.solution(e, v, **kwargs)


    #
    # These solver routines return claripy expressions
    #

    @unsat_catcher
    @symbolic_guard
    def any_expr(self, e, extra_constraints=()):
        return claripy.I(self._claripy, self._solver.eval(e, 1, extra_constraints=extra_constraints)[0])

    @symbolic_guard
    def any_n_expr(self, e, n, extra_constraints=()):
        try:
            vals = self._solver.eval(e, n, extra_constraints=extra_constraints)
            return [ claripy.I(self._claripy, v) for v in vals ]
        except claripy.UnsatError:
            return [ ]

    @unsat_catcher
    @symbolic_guard
    def max_expr(self, e, **kwargs):
        return claripy.I(self._claripy, self._solver.max(e, **kwargs))

    @unsat_catcher
    @symbolic_guard
    def min_expr(self, e, **kwargs):
        return claripy.I(self._claripy, self._solver.min(e, **kwargs))

    #
    # And these return raw results
    #

    @unsat_catcher
    @symbolic_guard
    def any_raw(self, e, extra_constraints=()):
        return self._solver.eval(e, 1, extra_constraints=extra_constraints)[0]

    @symbolic_guard
    def any_n_raw(self, e, n, extra_constraints=()):
        try:
            return self._solver.eval(e, n, extra_constraints=extra_constraints)
        except claripy.UnsatError:
            return [ ]

    @unsat_catcher
    @symbolic_guard
    def min_raw(self, e, extra_constraints=()):
        return self._solver.min(e, extra_constraints=extra_constraints)

    @unsat_catcher
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
        elif isinstance(args[0], claripy.A):
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
        merging_occured = False
        merging_occured, self._stored_solver = self._solver.merge([ oc._solver for oc in others ], merge_flag, flag_values)
        #import ipdb; ipdb.set_trace()
        return merging_occured, [ ]

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
        r = self.any_n_expr(e, n, extra_constraints=extra_constraints)
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
                raise SimValueError("concretized %d values (%d required) in exactly_n" % (len(r), n))
            else:
                return default
        return r[0]

    def unique(self, e, extra_constraints=()):
        if type(e) is not claripy.A:
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

    def is_true(self, e):
        return self._claripy.is_true(e)

    def is_false(self, e):
        return self._claripy.is_false(e)

    def constraint_to_si(self, expr, side):
        return self._claripy.constraint_to_si(expr, side)

SimStatePlugin.register_default('solver_engine', SimSolver)
from .. import s_options as o
from ..s_errors import SimValueError, SimUnsatError, SimSolverModeError
from ..s_ast import ast_preserving_op

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

_timing_enabled = False

import time
lt = logging.getLogger('simuvex.plugins.solver.timing')
def ast_stripping_op(f, *args, **kwargs):
    the_solver = kwargs.pop('the_solver', None)
    if _timing_enabled:
        the_solver = args[0] if the_solver is None else the_solver
        s = the_solver.state

        start = time.time()
        r = _actual_ast_stripping_op(f, *args, **kwargs)
        end = time.time()
        duration = end-start

        if s.scratch.sim_procedure is None and s.scratch.bbl_addr is not None:
            location = "bbl 0x%x, stmt %d (inst 0x%x)" % (s.scratch.bbl_addr, s.scratch.stmt_idx, s.scratch.ins_addr)
        elif s.scratch.sim_procedure is not None:
            location = "sim_procedure %s" % s.scratch.sim_procedure
        else:
            location = "unknown"
        lt.log(int((end-start)*10), '%s took %s seconds at %s', f.__name__, round(duration, 2), location)

        if break_time >= 0 and duration > break_time:
            import ipdb; ipdb.set_trace()
    else:
        r = _actual_ast_stripping_op(f, *args, **kwargs)

    return r

#pylint:disable=global-variable-undefined
def enable_timing():
    global _timing_enabled
    _timing_enabled = True
    lt.setLevel(1)


def disable_timing():
    global _timing_enabled
    _timing_enabled = False

import os
if os.environ.get('SOLVER_TIMING', False):
    enable_timing()
else:
    disable_timing()

break_time = float(os.environ.get('SOLVER_BREAK_TIME', -1))

#
# Various over-engineered crap
#

def auto_actions(f):
    @functools.wraps(f)
    def autoed_f(self, *args, **kwargs):
        return ast_stripping_op(f, self, *args, **kwargs)
    return autoed_f

def error_converter(f):
    @functools.wraps(f)
    def wrapped_f(self, *args, **kwargs):
        try:
            return f(self, *args, **kwargs)
        except claripy.UnsatError:
            e_type, value, traceback = sys.exc_info()
            raise SimUnsatError, ("Got an unsat result", e_type, value), traceback
        except claripy.ClaripyFrontendError:
            e_type, value, traceback = sys.exc_info()
            raise SimSolverModeError, ("Translated claripy error:", e_type, value), traceback
    return wrapped_f

import claripy
class SimSolver(SimStatePlugin):
    def __init__(self, solver=None): #pylint:disable=redefined-outer-name
        l.debug("Creating SimSolverClaripy.")
        SimStatePlugin.__init__(self)
        self._stored_solver = solver

    def _ana_getstate(self):
        return self._stored_solver, self.state

    def _ana_setstate(self, s):
        self._stored_solver, self.state = s

    def set_state(self, state):
        SimStatePlugin.set_state(self, state)

    @property
    def _solver(self):
        if self._stored_solver is not None:
            return self._stored_solver

        if o.ABSTRACT_SOLVER in self.state.options:
            self._stored_solver = claripy.LightFrontend(claripy.backends.vsa, cache=False)
        elif o.REPLACEMENT_SOLVER in self.state.options:
            self._stored_solver = claripy.ReplacementFrontend(claripy.FullFrontend(claripy.backends.z3), unsafe_replacement=True)
        elif o.COMPOSITE_SOLVER in self.state.options:
            self._stored_solver = claripy.CompositeFrontend(claripy.hybrid_vsa_z3())
        elif o.SYMBOLIC in self.state.options:
            if o.approximation & self.state.options:
                self._stored_solver = claripy.hybrid_vsa_z3()
            else:
                self._stored_solver = claripy.FullFrontend(claripy.backends.z3)
        else:
            self._stored_solver = claripy.LightFrontend(claripy.backends.concrete)

        return self._stored_solver

    #
    # Get unconstrained stuff
    #
    def Unconstrained(self, name, bits, **kwargs):
        if o.SYMBOLIC_INITIAL_VALUES in self.state.options:
            # Return a symbolic value
            if o.ABSTRACT_MEMORY in self.state.options:
                l.debug("Creating new top StridedInterval")
                r = claripy.TSI(bits=bits, name=name, uninitialized=True, **kwargs)
            else:
                l.debug("Creating new unconstrained BV named %s", name)
                if o.UNDER_CONSTRAINED_SYMEXEC in self.state.options:
                    r = self.BVS(name, bits, uninitialized=True, **kwargs)
                else:
                    r = self.BVS(name, bits, **kwargs)

            return r
        else:
            # Return a default value, aka. 0
            return claripy.BVV(0, bits)

    def BVS(self, name, size, min=None, max=None, stride=None, uninitialized=False, explicit_name=None, **kwargs): #pylint:disable=redefined-builtin
        '''
        Creates a bit-vector symbol (i.e., a variable).

        @param name: the name of the symbol
        @param size: the size (in bits) of the bit-vector
        @param min: the minimum value of the symbol
        @param max: the maximum value of the symbol
        @param stride: the stride of the symbol
        @param uninitialized: whether this value should be counted as an
                              "uninitialized" value in the course of an analysis.
        @param explicit_name: if False, an identifier is appended to the name to ensure
                              uniqueness.

        Other **kwargs are passed directly on to the constructor of claripy.ast.BV.

        @returns a BV object representing this symbol
        '''

        r = claripy.BVS(name, size, min=min, max=max, stride=stride, uninitialized=uninitialized, explicit_name=explicit_name, **kwargs)
        self.state._inspect('symbolic_variable', BP_AFTER, symbolic_name=next(iter(r.variables)), symbolic_size=size, symbolic_expr=r)
        self.state.log.add_event('unconstrained', name=iter(r.variables).next(), bits=size, **kwargs)
        return r

    #
    # Operation passthroughs to claripy
    #

    def __getattr__(self, a):
        f = getattr(claripy._all_operations, a)
        if hasattr(f, '__call__'):
            ff = functools.partial(ast_stripping_op, f, the_solver=self)
            ff.__doc__ = f.__doc__
            return ff
        else:
            return f

    def __dir__(self):
        return sorted(set(dir(super(SimSolver, self)) + dir(claripy._all_operations) + dir(self.__class__)))

    #
    # Branching stuff
    #

    def copy(self):
        return SimSolver(solver=self._solver.branch())

    @error_converter
    def merge(self, others, merge_flag, flag_values): # pylint: disable=W0613
        #import ipdb; ipdb.set_trace()
        merging_occurred, self._stored_solver = self._solver.merge([ oc._solver for oc in others ], merge_flag, flag_values)
        #import ipdb; ipdb.set_trace()
        return merging_occurred, [ ]

    def widen(self, others, merge_flag, flag_values):

        merging_occurred, _ = self.merge(others, merge_flag, flag_values)

        return merging_occurred

    #
    # Frontend passthroughs
    #

    def downsize(self):
        return self._solver.downsize()

    @property
    def constraints(self):
        return self._solver.constraints

    def _adjust_constraint(self, c):
        if self.state._global_condition is None:
            return c
        elif c is None: # this should never happen
            l.critical("PLEASE REPORT THIS MESSAGE, AND WHAT YOU WERE DOING, TO YAN")
            return self.state._global_condition
        else:
            return self.Or(self.Not(self.state._global_condition), c)

    def _adjust_constraint_list(self, constraints):
        if self.state._global_condition is None:
            return constraints
        if len(constraints) == 0:
            return constraints.__class__((self.state._global_condition,))
        else:
            return constraints.__class__((self._adjust_constraint(self.And(*constraints)),))

    @auto_actions
    @error_converter
    def eval_to_ast(self, e, n, extra_constraints=(), exact=None):
        return self._solver.eval_to_ast(e, n, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @auto_actions
    @error_converter
    def eval(self, e, n, extra_constraints=(), exact=None):
        return self._solver.eval(e, n, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @auto_actions
    @error_converter
    def max(self, e, extra_constraints=(), exact=None):
        return self._solver.max(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @auto_actions
    @error_converter
    def min(self, e, extra_constraints=(), exact=None):
        return self._solver.min(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @auto_actions
    @error_converter
    def solution(self, e, v, extra_constraints=(), exact=None):
        return self._solver.solution(e, v, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @auto_actions
    @error_converter
    def is_true(self, e, extra_constraints=(), exact=None):
        return self._solver.is_true(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @auto_actions
    @error_converter
    def is_false(self, e, extra_constraints=(), exact=None):
        return self._solver.is_false(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @auto_actions
    @error_converter
    def solve(self, extra_constraints=(), exact=None):
        return self._solver.solve(extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @auto_actions
    @error_converter
    def satisfiable(self, extra_constraints=(), exact=None):
        return self._solver.satisfiable(extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @auto_actions
    @error_converter
    def add(self, *constraints):
        cc = self._adjust_constraint_list(constraints)
        return self._solver.add(cc)

    #
    # And some convenience stuff
    #

    def any_int(self, e, extra_constraints=()):
        ans = self.any_n_int(e, 1, extra_constraints=extra_constraints)
        if len(ans) > 0: return ans[0]
        else: raise SimUnsatError("Not satisfiable: %s" % e.shallow_repr())

    def any_str(self, e, extra_constraints=()):
        ans = self.any_n_str(e, 1, extra_constraints=extra_constraints)
        if len(ans) > 0: return ans[0]
        else: raise SimUnsatError("Not satisfiable: %s" % e.shallow_repr())

    def any_n_str_iter(self, e, n, extra_constraints=(), exact=None):
        for s in self.eval(e, n, extra_constraints=extra_constraints, exact=exact):
            yield ("%x" % s).zfill(len(e)/4).decode('hex')

    def any_n_str(self, e, n, extra_constraints=(), exact=None):
        return list(self.any_n_str_iter(e, n, extra_constraints=extra_constraints, exact=exact))

    min_int = min
    max_int = max

    def any_n_int(self, e, n, extra_constraints=(), exact=None):
        try:
            return list(self.eval(e, n, extra_constraints=extra_constraints, exact=exact))
        except SimUnsatError:
            return [ ]

    def exactly_n(self, e, n, extra_constraints=(), exact=None):
        r = self.any_n_int(e, n, extra_constraints=extra_constraints, exact=exact)
        if len(r) != n:
            raise SimValueError("concretized %d values (%d required) in exactly_n" % (len(r), n))
        return r

    def exactly_n_int(self, e, n, extra_constraints=(), exact=None):
        r = self.any_n_int(e, n, extra_constraints=extra_constraints, exact=exact)
        if len(r) != n:
            raise SimValueError("concretized %d values (%d required) in exactly_n" % (len(r), n))
        return r

    def exactly_int(self, e, extra_constraints=(), default=None, exact=None):
        try:
            r = self.any_n_int(e, 1, extra_constraints=extra_constraints, exact=exact)
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
    def unique(self, e, extra_constraints=(), exact=None):
        if not isinstance(e, claripy.ast.Base):
            return True

        # if we don't want to do symbolic checks, assume symbolic variables are multivalued
        if o.SYMBOLIC not in self.state.options and self.symbolic(e):
            return False

        r = self.any_n_int(e, 2, extra_constraints=extra_constraints, exact=exact)
        if len(r) == 1:
            self.add(e == r[0])
            return True
        elif len(r) == 0:
            raise SimValueError("unsatness during uniqueness check(ness)")
        else:
            return False

    def symbolic(self, e): # pylint:disable=R0201
        if type(e) in (int, str, float, bool, long):
            return False
        return e.symbolic

    def single_valued(self, e):
        if self.state.mode == 'static':
            if type(e) in (int, str, float, bool, long):
                return True
            else:
                return e.cardinality <= 1

        else:
            # All symbolic expressions are not single-valued
            return not self.symbolic(e)

    @auto_actions
    @error_converter
    def simplify(self, *args):
        if len(args) == 0:
            return self._solver.simplify()
        elif isinstance(args[0], claripy.ast.Base):
            return claripy.simplify(args[0])
        else:
            return args[0]

    def variables(self, e): #pylint:disable=no-self-use
        return e.variables

SimStatePlugin.register_default('solver_engine', SimSolver)
from .. import s_options as o
from .inspect import BP_AFTER
from ..s_errors import SimValueError, SimUnsatError, SimSolverModeError

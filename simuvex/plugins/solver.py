#!/usr/bin/env python

from .plugin import SimStatePlugin
from ..s_action_object import ast_stripping_decorator, SimActionObject

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
def timed_function(f):
    if _timing_enabled:
        @functools.wraps(f)
        def timing_guy(*args, **kwargs):
            the_solver = kwargs.pop('the_solver', None)
            the_solver = args[0] if the_solver is None else the_solver
            s = the_solver.state

            start = time.time()
            r = f(*args, **kwargs)
            end = time.time()
            duration = end-start

            try:
                if s.scratch.sim_procedure is None and s.scratch.bbl_addr is not None:
                    location = "bbl %#x, stmt %s (inst %s)" % (
                        s.scratch.bbl_addr,
                        s.scratch.stmt_idx,
                        ('%s' % s.scratch.ins_addr if s.scratch.ins_addr is None else '%#x' % s.scratch.ins_addr)
                    )
                elif s.scratch.sim_procedure is not None:
                    location = "sim_procedure %s" % s.scratch.sim_procedure
                else:
                    location = "unknown"
            except Exception: #pylint:disable=broad-except
                l.error("Got exception while generating timer message:", exc_info=True)
                location = "unknown"
            lt.log(int((end-start)*10), '%s took %s seconds at %s', f.__name__, round(duration, 2), location)

            if break_time >= 0 and duration > break_time:
                import ipdb; ipdb.set_trace()

            return r

        return timing_guy
    else:
        return f

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

def error_converter(f):
    @functools.wraps(f)
    def wrapped_f(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except claripy.UnsatError:
            e_type, value, traceback = sys.exc_info()
            raise SimUnsatError, ("Got an unsat result", e_type, value), traceback
        except claripy.ClaripyFrontendError:
            e_type, value, traceback = sys.exc_info()
            raise SimSolverModeError, ("Translated claripy error:", e_type, value), traceback
    return wrapped_f

#
# Premature optimizations
#

def _concrete_bool(e):
    if isinstance(e, bool):
        return e
    elif isinstance(e, claripy.ast.Base) and e.op == 'BoolV':
        return e.args[0]
    elif isinstance(e, SimActionObject) and e.op == 'BoolV':
        return e.args[0]
    else:
        return None

def _concrete_value(e):
    # shortcuts for speed improvement
    if isinstance(e, (int, long, float, bool)):
        return e
    elif isinstance(e, claripy.ast.Base) and e.op in claripy.operations.leaf_operations_concrete:
        return e.args[0]
    elif isinstance(e, SimActionObject) and e.op in claripy.operations.leaf_operations_concrete:
        return e.args[0]
    else:
        return None

def concrete_path_bool(f):
    @functools.wraps(f)
    def concrete_shortcut_bool(self, *args, **kwargs):
        v = _concrete_bool(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        else:
            return v
    return concrete_shortcut_bool

def concrete_path_not_bool(f):
    @functools.wraps(f)
    def concrete_shortcut_not_bool(self, *args, **kwargs):
        v = _concrete_bool(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        else:
            return not v
    return concrete_shortcut_not_bool

def concrete_path_scalar(f):
    @functools.wraps(f)
    def concrete_shortcut_scalar(self, *args, **kwargs):
        v = _concrete_value(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        else:
            return v
    return concrete_shortcut_scalar

def concrete_path_tuple(f):
    @functools.wraps(f)
    def concrete_shortcut_tuple(self, *args, **kwargs):
        v = _concrete_value(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        else:
            return ( v, )
    return concrete_shortcut_tuple

def concrete_path_list(f):
    @functools.wraps(f)
    def concrete_shortcut_list(self, *args, **kwargs):
        v = _concrete_value(args[0])
        if v is None:
            return f(self, *args, **kwargs)
        else:
            return [ v ]
    return concrete_shortcut_list

#
# The main event
#

import claripy
class SimSolver(SimStatePlugin):
    """
    Symbolic solver.
    """
    def __init__(self, solver=None): #pylint:disable=redefined-outer-name
        l.debug("Creating SimSolverClaripy.")
        SimStatePlugin.__init__(self)
        self._stored_solver = solver

    def reload_solver(self):
        """
        Reloads the solver. Useful when changing solver options.
        """

        constraints = self._solver.constraints
        self._stored_solver = None
        self._solver.add(constraints)

    @property
    def _solver(self):
        if self._stored_solver is not None:
            return self._stored_solver

        if o.ABSTRACT_SOLVER in self.state.options:
            self._stored_solver = claripy.SolverVSA()
        elif o.REPLACEMENT_SOLVER in self.state.options:
            self._stored_solver = claripy.SolverReplacement(auto_replace=False)
        elif o.CACHELESS_SOLVER in self.state.options:
            self._stored_solver = claripy.SolverCacheless()
        elif o.COMPOSITE_SOLVER in self.state.options:
            self._stored_solver = claripy.SolverComposite()
        elif o.SYMBOLIC in self.state.options and o.approximation & self.state.options:
            self._stored_solver = claripy.SolverHybrid()
        elif o.SYMBOLIC in self.state.options:
            self._stored_solver = claripy.Solver()
        else:
            self._stored_solver = claripy.SolverConcrete()

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
        """
        Creates a bit-vector symbol (i.e., a variable). Other **kwargs are passed directly on to the constructor of
        claripy.ast.BV.

        :param name:            The name of the symbol.
        :param size:            The size (in bits) of the bit-vector.
        :param min:             The minimum value of the symbol.
        :param max:             The maximum value of the symbol.
        :param stride:          The stride of the symbol.
        :param uninitialized:   Whether this value should be counted as an "uninitialized" value in the course of an
                                analysis.
        :param explicit_name:   If False, an identifier is appended to the name to ensure uniqueness.

        :return:                A BV object representing this symbol.
        """

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
            ff = error_converter(ast_stripping_decorator(f))
            if _timing_enabled:
                ff = functools.partial(timed_function(ff), the_solver=self)
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
    def merge(self, others, merge_conditions): # pylint: disable=W0613
        #import ipdb; ipdb.set_trace()
        merging_occurred, self._stored_solver = self._solver.merge(
            [ oc._solver for oc in others ],
            merge_conditions,
        )
        #import ipdb; ipdb.set_trace()
        return merging_occurred

    @error_converter
    def widen(self, others):
        c = self.state.se.BVS('random_widen_condition', 32)
        merge_conditions = [ [ c == i ] for i in range(len(others)+1) ]
        merging_occurred = self.merge(others, merge_conditions)
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

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def eval_to_ast(self, e, n, extra_constraints=(), exact=None):
        """
        Evaluate an expression, using the solver if necessary. Returns AST objects.

        :param e: the expression
        :param n: the number of desired solutions
        :param extra_constraints: extra constraints to apply to the solver
        :param exact: if False, returns approximate solutions
        :return: a tuple of the solutions, in the form of claripy AST nodes
        :rtype: tuple
        """
        return self._solver.eval_to_ast(e, n, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @concrete_path_tuple
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def eval(self, e, n, extra_constraints=(), exact=None):
        """
        Evaluate an expression, using the solver if necessary. Returns primitives.

        :param e: the expression
        :param n: the number of desired solutions
        :param extra_constraints: extra constraints to apply to the solver
        :param exact: if False, returns approximate solutions
        :return: a tuple of the solutions, in the form of Python primitives
        :rtype: tuple
        """
        return self._solver.eval(e, n, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @concrete_path_scalar
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def max(self, e, extra_constraints=(), exact=None):
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.max(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False)
            er = self._solver.max(e, extra_constraints=self._adjust_constraint_list(extra_constraints))
            assert er <= ar
            return ar
        return self._solver.max(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @concrete_path_scalar
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def min(self, e, extra_constraints=(), exact=None):
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.min(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False)
            er = self._solver.min(e, extra_constraints=self._adjust_constraint_list(extra_constraints))
            assert ar <= er
            return ar
        return self._solver.min(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def solution(self, e, v, extra_constraints=(), exact=None):
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.solution(e, v, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False)
            er = self._solver.solution(e, v, extra_constraints=self._adjust_constraint_list(extra_constraints))
            if er is True:
                assert ar is True
            return ar
        return self._solver.solution(e, v, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @concrete_path_bool
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def is_true(self, e, extra_constraints=(), exact=None):
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.is_true(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False)
            er = self._solver.is_true(e, extra_constraints=self._adjust_constraint_list(extra_constraints))
            if er is False:
                assert ar is False
            return ar
        return self._solver.is_true(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @concrete_path_not_bool
    @timed_function
    @ast_stripping_decorator
    @error_converter
    def is_false(self, e, extra_constraints=(), exact=None):
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            ar = self._solver.is_false(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False)
            er = self._solver.is_false(e, extra_constraints=self._adjust_constraint_list(extra_constraints))
            if er is False:
                assert ar is False
            return ar
        return self._solver.is_false(e, extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def solve(self, extra_constraints=(), exact=None):
        return self._solver.solve(extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def satisfiable(self, extra_constraints=(), exact=None):
        if exact is False and o.VALIDATE_APPROXIMATIONS in self.state.options:
            er = self._solver.satisfiable(extra_constraints=self._adjust_constraint_list(extra_constraints))
            ar = self._solver.satisfiable(extra_constraints=self._adjust_constraint_list(extra_constraints), exact=False)
            if er is True:
                assert ar is True
            return ar
        return self._solver.satisfiable(extra_constraints=self._adjust_constraint_list(extra_constraints), exact=exact)

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def add(self, *constraints):
        cc = self._adjust_constraint_list(constraints)
        return self._solver.add(cc)

    #
    # And some convenience stuff
    #

    @concrete_path_scalar
    def any_int(self, e, **kwargs):
        ans = self.eval(e, 1, **kwargs)
        if len(ans) > 0: return ans[0]
        else: raise SimUnsatError("Not satisfiable: %s" % e.shallow_repr())

    def any_str(self, e, **kwargs):
        ans = self.any_n_str(e, 1, **kwargs)
        if len(ans) > 0: return ans[0]
        else: raise SimUnsatError("Not satisfiable: %s" % e.shallow_repr())

    def any_n_str_iter(self, e, n, **kwargs):
        if len(e) == 0:
            yield ""
            return

        for s in self.eval(e, n, **kwargs):
            yield ("%x" % s).zfill(len(e)/4).decode('hex')

    def any_n_str(self, e, n, **kwargs):
        return list(self.any_n_str_iter(e, n, **kwargs))

    min_int = min
    max_int = max

    def any_n_int(self, e, n, **kwargs):
        try:
            return list(self.eval(e, n, **kwargs))
        except SimUnsatError:
            return [ ]

    def exactly_n(self, e, n, **kwargs):
        r = self.any_n_int(e, n, **kwargs)
        if len(r) != n:
            raise SimValueError("concretized %d values (%d required) in exactly_n" % (len(r), n))
        return r

    def exactly_n_int(self, e, n, **kwargs):
        r = self.any_n_int(e, n, **kwargs)
        if len(r) != n:
            raise SimValueError("concretized %d values (%d required) in exactly_n" % (len(r), n))
        return r

    def exactly_int(self, e, default=None, **kwargs):
        try:
            r = self.any_n_int(e, 1, **kwargs)
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

    @timed_function
    @ast_stripping_decorator
    def unique(self, e, **kwargs):
        if not isinstance(e, claripy.ast.Base):
            return True

        # if we don't want to do symbolic checks, assume symbolic variables are multivalued
        if o.SYMBOLIC not in self.state.options and self.symbolic(e):
            return False

        r = self.any_n_int(e, 2, **kwargs)
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

    def simplify(self, *args):
        if len(args) == 0:
            return self._solver.simplify()
        elif isinstance(args[0], (int, long, float, bool)):
            return args[0]
        elif isinstance(args[0], claripy.ast.Base) and args[0].op in claripy.operations.leaf_operations_concrete:
            return args[0]
        elif isinstance(args[0], SimActionObject) and args[0].op in claripy.operations.leaf_operations_concrete:
            return args[0].ast
        elif not isinstance(args[0], (SimActionObject, claripy.ast.Base)):
            return args[0]
        else:
            return self._claripy_simplify(*args)

    @timed_function
    @ast_stripping_decorator
    @error_converter
    def _claripy_simplify(self, *args): #pylint:disable=no-self-use
        return claripy.simplify(args[0])

    def variables(self, e): #pylint:disable=no-self-use
        return e.variables

SimStatePlugin.register_default('solver_engine', SimSolver)
from .. import s_options as o
from .inspect import BP_AFTER
from ..s_errors import SimValueError, SimUnsatError, SimSolverModeError

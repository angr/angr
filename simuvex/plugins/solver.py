#!/usr/bin/env python

from .plugin import SimStatePlugin
from .symbolic_memory import SimMemoryObject, SimMemoryObject

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

import claripy
class SimSolver(SimStatePlugin):
    def __init__(self, solver=None, claripy=None): #pylint:disable=redefined-outer-name
        l.debug("Creating SimSolverClaripy.")
        SimStatePlugin.__init__(self)

        self._claripy = claripy
        self._stored_solver = solver

    def set_state(self, state):
        SimStatePlugin.set_state(self, state)

        if self._claripy is None:
            if o.ABSTRACT_SOLVER in self.state.options:
                backend_vsa = claripy.backends.BackendVSA()
                backend_concrete = claripy.backends.BackendConcrete()

                self._claripy = claripy.init_standalone(model_backends=[backend_concrete, backend_vsa],
                                                        solver_backends=[]) # Don't initialize a solver backend
                backend_vsa.set_claripy_object(self._claripy)
                backend_concrete.set_claripy_object(self._claripy)
                claripy.set_claripy(self._claripy)
            else:
                self._claripy = claripy.set_claripy(claripy.ClaripyStandalone(parallel=o.PARALLEL_SOLVES in self.state.options))
        for op in claripy.operations.backend_operations_all | { 'ite_cases', 'ite_dict', 'true', 'false' }:
            setattr(self, op, getattr(self._claripy, op))

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
    # Various passthroughs
    #

    def add(self, *constraints): return self._solver.add(constraints)
    def downsize(self): return self._solver.downsize()

    @unsat_catcher
    def satisfiable(self): return self._solver.satisfiable()
    @unsat_catcher
    def check(self): return self._solver.check()
    @unsat_catcher
    def solution(self, *args, **kwargs): return self._solver.solution(*args, **kwargs)


    #
    # These solver routines return claripy expressions
    #

    @unsat_catcher
    def any_expr(self, e, extra_constraints=()):
        return self._claripy.wrap(self._solver.eval(e, 1, extra_constraints=extra_constraints)[0])

    def any_n_expr(self, e, n, extra_constraints=()):
        try:
            vals = self._solver.eval(e, n, extra_constraints=extra_constraints)
            return [ self._claripy.wrap(v) for v in vals ]
        except claripy.UnsatError:
            return [ ]

    @unsat_catcher
    def max_expr(self, *args, **kwargs):
        return self._claripy.wrap(self._solver.max(*args, **kwargs))
    @unsat_catcher
    def min_expr(self, *args, **kwargs):
        return self._claripy.wrap(self._solver.min(*args, **kwargs))

    #
    # And these return raw results
    #

    @unsat_catcher
    def any_raw(self, e, extra_constraints=()):
        return self._solver.eval(e, 1, extra_constraints=extra_constraints)[0]

    def any_n_raw(self, e, n, extra_constraints=()):
        try:
            return self._solver.eval(e, n, extra_constraints=extra_constraints)
        except claripy.UnsatError:
            return [ ]

    @unsat_catcher
    def min_raw(self, e, extra_constraints=()):
        return self._solver.min(e, extra_constraints=extra_constraints)

    @unsat_catcher
    def max_raw(self, e, extra_constraints=()):
        return self._solver.max(e, extra_constraints=extra_constraints)

    def symbolic(self, e): # pylint:disable=R0201
        if type(e) in (int, str, float, bool, long, claripy.BVV):
            return False
        return e.symbolic

    def simplify(self, *args):
        if len(args) == 0:
            return self._solver.simplify()
        elif type(args[0]) is claripy.E:
            return self._claripy.simplify(args[0])
        else:
            return args[0]

    def variables(self, e): #pylint:disable=no-self-use
        return e.variables

    #
    # Branching stuff
    #

    def copy(self):
        return SimSolver(self._solver.branch())

    def merge(self, others, merge_flag, flag_values): # pylint: disable=W0613
        #import ipdb; ipdb.set_trace()

        self._stored_solver = self._solver.merge([ oc._solver for oc in others ], merge_flag, flag_values)
        #import ipdb; ipdb.set_trace()
        return [ ]

    #
    # Other stuff
    #

    def any_str(self, e, extra_constraints=()): return self.any_n_str(e, 1, extra_constraints=extra_constraints)[0]
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

    def unique(self, e, extra_constraints=()):
        if type(e) is not claripy.E:
            return True

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
from ..s_errors import SimValueError, SimUnsatError

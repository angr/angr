#!/usr/bin/env python

from ..s_state import SimStatePlugin

import sys
import functools
import logging
l = logging.getLogger("simuvex.s_solver")

def unsat_catcher(f):
	@functools.wraps(f)
	def wrapped_f(self, *args, **kwargs):
		try:
			return f(self, *args, **kwargs)
		except self.UnsatError:
			e_type, value, traceback = sys.exc_info()
			raise SimUnsatError, ("Got an unsat result", e_type, value), traceback
	return wrapped_f

class SimSolver(SimStatePlugin):
	def __init__(self):
		SimStatePlugin.__init__(self)

	# Passthroughs
	def add(self, *constraints): raise NotImplementedError()
	def satisfiable(self): raise NotImplementedError()
	def check(self): raise NotImplementedError()
	def downsize(self): raise NotImplementedError()
	def solution(self, *args, **kwargs): raise NotImplementedError()

	def any(self, e, extra_constraints=None): raise NotImplementedError()
	def any_n(self, e, n, extra_constraints=None): raise NotImplementedError()
	def max(self, *args, **kwargs): raise NotImplementedError()
	def min(self, *args, **kwargs): raise NotImplementedError()

	def any_value(self, e, extra_constraints=None): raise NotImplementedError()
	def any_n_value(self, e, n, extra_constraints=None): raise NotImplementedError()
	def min_value(self, e, extra_constraints=None): raise NotImplementedError()
	def max_value(self, e, extra_constraints=None): raise NotImplementedError()

	# Other stuff

	def any_str(self, e, extra_constraints=None): return self.any_n_str(e, 1, extra_constraints=extra_constraints)[0]
	def any_n_str_iter(self, e, n, extra_constraints=None):
		for s in self.any_n_value(e, n, extra_constraints=extra_constraints):
			if type(s) not in (int, long):
				yield ("%x" % s.value).zfill(s.bits/4).decode('hex')
			else:
				ss = "%x"%s
				ss = ss.zfill(len(ss)%2+len(ss))
				yield ss.decode('hex')

	def any_n_str(self, e, n, extra_constraints=None):
		return list(self.any_n_str_iter(e, n, extra_constraints=extra_constraints))

	def any_int(self, e, extra_constraints=None):
		r = self.any_value(e, extra_constraints=extra_constraints)
		return r.value if type(r) is claripy.BVV else r

	def any_n_int(self, e, n, extra_constraints=None):
		rr = self.any_n_value(e, n, extra_constraints=extra_constraints)
		return [ r.value if type(r) is claripy.BVV else r for r in rr ]

	def min_int(self, e, extra_constraints=None):
		r = self.min_value(e, extra_constraints=extra_constraints)
		return r.value if type(r) is claripy.BVV else r

	def max_int(self, e, extra_constraints=None):
		r = self.max_value(e, extra_constraints=extra_constraints)
		return r.value if type(r) is claripy.BVV else r

	def exactly_n(self, e, n, extra_constraints=None):
		r = self.any_n(e, n, extra_constraints=extra_constraints)
		if len(r) != n:
			raise SimValueError("concretized %d values (%d required) in exactly_n" % (len(r), n))
		return r

	def exactly_n_int(self, e, n, extra_constraints=None):
		r = self.any_n_int(e, n, extra_constraints=extra_constraints)
		if len(r) != n:
			raise SimValueError("concretized %d values (%d required) in exactly_n" % (len(r), n))
		return r

	def unique(self, e, extra_constraints=None):
		if type(e) is not claripy.E:
			return True

		r = self.any_n(e, 2, extra_constraints=extra_constraints)
		if len(r) == 1:
			self.add(e == r[0])
			return True
		elif len(r) == 0:
			raise SimValueError("unsatness during uniqueness check(ness)")
		else:
			return False


import claripy
class SimSolverClaripy(SimSolver):
	def __init__(self, solver=None):
		l.debug("Creating SimSolverClaripy.")
		SimSolver.__init__(self)
		self._stored_solver = solver
		self.UnsatError = claripy.UnsatError

	def set_state(self, state):
		SimStatePlugin.set_state(self, state)
		for op in claripy.operations.backend_operations | { 'ite_cases', 'ite_dict', 'true', 'false' }:
			setattr(self, op, getattr(state._engine, op))

	@property
	def _solver(self):
		if self._stored_solver is not None:
			return self._stored_solver

		if o.COMPOSITE_SOLVER in self.state.options:
			self._stored_solver = self.state._engine.composite_solver()
		else:
			self._stored_solver = self.state._engine.solver()
		return self._stored_solver

	#
	# Various passthroughs
	#

	def add(self, *constraints): return self._solver.add(*constraints)
	def downsize(self): return self._solver.downsize()

	@unsat_catcher
	def satisfiable(self): return self._solver.satisfiable()
	@unsat_catcher
	def check(self): return self._solver.check()
	@unsat_catcher
	def solution(self, *args, **kwargs): return self._solver.solution(*args, **kwargs)

	# Passthroughs
	@unsat_catcher
	def any(self, e, extra_constraints=None): return self._solver.eval(e, 1, extra_constraints=extra_constraints)[0]

	def any_n(self, e, n, extra_constraints=None):
		try:
			return self._solver.eval(e, n, extra_constraints=extra_constraints)
		except self.UnsatError:
			return [ ]

	@unsat_catcher
	def max(self, *args, **kwargs): return self._solver.max(*args, **kwargs)
	@unsat_catcher
	def min(self, *args, **kwargs): return self._solver.min(*args, **kwargs)

	@unsat_catcher
	def any_value(self, e, extra_constraints=None): return self._solver.eval_value(e, 1, extra_constraints=extra_constraints)[0]

	def any_n_value(self, e, n, extra_constraints=None):
		try:
			return self._solver.eval_value(e, n, extra_constraints=extra_constraints)
		except self.UnsatError:
			return [ ]
	@unsat_catcher
	def min_value(self, e, extra_constraints=None): return self._solver.min_value(e, extra_constraints=extra_constraints)
	@unsat_catcher
	def max_value(self, e, extra_constraints=None): return self._solver.max_value(e, extra_constraints=extra_constraints)

	def symbolic(self, e): # pylint:disable=R0201
		if type(e) in (int, str, float, bool, long, claripy.BVV):
			return False
		return e.symbolic

	def simplify(self, *args):
		if len(args) == 0:
			return self._solver.simplify()
		elif type(args[0]) is claripy.E:
			return args[0].simplify()
		else:
			return args[0]

	def variables(self, e):
		return e.variables

	#
	# Branching stuff
	#

	def copy(self):
		return SimSolverClaripy(self._solver.branch())

	def merge(self, others, merge_flag, flag_values): # pylint: disable=W0613
		#import ipdb; ipdb.set_trace()

		self._stored_solver = self._solver.merge([ oc._solver for oc in others ], merge_flag, flag_values)
		#import ipdb; ipdb.set_trace()
		return [ ]

try:
	import symexec
	class SimSolverSymexec(SimSolver):
		def __init__(self, solver=None):
			l.debug("Creating SimSolverSymexec.")

			SimSolver.__init__(self)
			self._stored_solver = solver
			self.UnsatError = symexec.SymbolicError

			for op in claripy.backends.ops | { 'ite_cases', 'ite_dict' }:
				setattr(self, op, getattr(symexec, op))

		@property
		def _solver(self):
			if self._stored_solver is not None:
				return self._stored_solver

			#if o.CONSTRAINT_SETS in self.state.options:
			#	self._stored_solver = symexec.CompositeSolver()
			#else:
			self._stored_solver = symexec.Solver()
			return self._stored_solver

		#
		# Various passthroughs
		#

		def add(self, *constraints): return self._solver.add(*constraints)
		def downsize(self): return self._solver.downsize()

		@unsat_catcher
		def satisfiable(self): return self._solver.satisfiable()
		@unsat_catcher
		def check(self): return self._solver.check()
		@unsat_catcher
		def solution(self, *args, **kwargs): return self._solver.is_solution(*args, **kwargs)

		@unsat_catcher
		def any(self, e, extra_constraints=None): return self._solver.any_n(e, 1, extra_constraints=extra_constraints)[0]
		@unsat_catcher
		def any_n(self, e, n, extra_constraints=None): return self._solver.any_n(e, n, extra_constraints=extra_constraints)
		@unsat_catcher
		def max(self, *args, **kwargs): return self._solver.max(*args, **kwargs)
		@unsat_catcher
		def min(self, *args, **kwargs): return self._solver.min(*args, **kwargs)

		@unsat_catcher
		def any_value(self, e, extra_constraints=None): return symexec.unwrap(self.any(e, extra_constraints=extra_constraints))
		@unsat_catcher
		def any_n_value(self, e, n, extra_constraints=None): return symexec.unwrap(self.any_n(e, n, extra_constraints=extra_constraints))
		@unsat_catcher
		def min_value(self, e, extra_constraints=None): return symexec.unwrap(self.min(e, extra_constraints=extra_constraints))
		@unsat_catcher
		def max_value(self, e, extra_constraints=None): return symexec.unwrap(self.max(e, extra_constraints=extra_constraints))

		def symbolic(self, e): #pylint:disable=R0201
			return symexec.is_symbolic(e)

		def simplify(self, *args):
			if len(args) == 0:
				#if o.SPLIT_CONSTRAINTS in self.state.options and o.CONSTRAINT_SETS in self.state.options:
				#	return self._solver.simplify(split=True)
				#else:
				return self._solver.simplify()
			else:
				return symexec.simplify_expression(args[0])

		def variables(self, e):
			return symexec.variable_constituents(e)

		#
		# Branching stuff
		#

		def copy(self):
			return SimSolverSymexec(self._solver.branch())

		def merge(self, others, merge_flag, flag_values): # pylint: disable=W0613
			self._stored_solver = self._solver.merge([ oc._solver for oc in others ], merge_flag, flag_values)
			return [ ]
except ImportError:
	pass


SimStatePlugin.register_default('solver_engine', SimSolverClaripy)
from .. import s_options as o
from ..s_errors import SimValueError, SimUnsatError

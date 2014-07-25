#!/usr/bin/env python

from .s_state import SimStatePlugin

import logging
l = logging.getLogger("simuvex.constraints")

import claripy

class SimConstraints(SimStatePlugin):
	def __init__(self, solver=None):
		SimStatePlugin.__init__(self)
		self._stored_solver = solver

	@property
	def _solver(self):
		if self._stored_solver is not None:
			return self._stored_solver

		if o.CONSTRAINT_SETS in self.state.options:
			self._stored_solver = self.state.claripy.composite_solver()
		else:
			self._stored_solver = self.state.claripy.solver()
		return self._stored_solver

	#
	# Various passthroughs
	#

	def add(self, *constraints): return self._solver.add(*constraints)
	def satisfiable(self): return self._solver.satisfiable()
	def check(self): return self._solver.check()
	def downsize(self): return self._solver.downsize()
	def solution(self, *args, **kwargs): return self._solver.solution(*args, **kwargs)

	# Passthroughs
	def any(self, e, extra_constraints=None): return self._solver.eval(e, 1, extra_constraints=extra_constraints)[0]
	def any_n(self, e, n, extra_constraints=None): return self._solver.eval(e, n, extra_constraints=extra_constraints)
	def max(self, *args, **kwargs): return self._solver.max(*args, **kwargs)
	def min(self, *args, **kwargs): return self._solver.min(*args, **kwargs)

	def any_value(self, e, extra_constraints=None): return self._solver.eval_value(e, 1, extra_constraints=extra_constraints)[0]
	def any_n_value(self, e, n, extra_constraints=None): return self._solver.eval_value(e, n, extra_constraints=extra_constraints)
	def min_value(self, e, extra_constraints=None): return self._solver.min_value(e, extra_constraints=extra_constraints)
	def max_value(self, e, extra_constraints=None): return self._solver.max_value(e, extra_constraints=extra_constraints)

	def any_str(self, e): return self.any_n_str(e, 1)[0]
	def any_n_str(self, e, n): return [ ("%x" % s.value).zfill(s.bits/4).decode('hex') for s in self.any_n_value(e, n) ]

	def any_int(self, e, extra_constraints=None):
		r = self._solver.eval_value(e, 1, extra_constraints=extra_constraints)[0]
		return r.value if type(r) is claripy.BVV else r
	def any_n_int(self, e, n, extra_constraints=None):
		rr = self._solver.eval_value(e, n, extra_constraints=extra_constraints)
		return [ r.value if type(r) is claripy.BVV else r for r in rr ]
	def min_int(self, e, extra_constraints=None):
		r = self._solver.min_value(e, extra_constraints=extra_constraints)
		return r.value if type(r) is claripy.BVV else r
	def max_int(self, e, extra_constraints=None):
		r = self._solver.max_value(e, extra_constraints=extra_constraints)
		return r.value if type(r) is claripy.BVV else r

	def exactly_n(self, e, n, extra_constraints=None):
		r = self._solver.eval(e, n, extra_constraints=extra_constraints)
		if len(r) != n:
			raise SimValueError("concretized %d values (%d required) in exactly_n" % len(r), n)
		return r

	def exactly_n_int(self, e, n, extra_constraints=None):
		r = self.any_n_int(e, n, extra_constraints=extra_constraints)
		if len(r) != n:
			raise SimValueError("concretized %d values (%d required) in exactly_n" % len(r), n)
		return r

	def unique(self, e, extra_constraints=None):
		if type(e) is not claripy.E:
			return True

		r = self._solver.eval(e, 2, extra_constraints=extra_constraints)
		if len(r) == 1:
			self.add(e == r[0])
			return True
		else:
			return False

	def symbolic(self, e): # pylint:disable=R0201
		if type(e) in (int, str, float, bool, long, claripy.BVV):
			return False
		return e.symbolic




	def simplify(self):
		if o.SPLIT_CONSTRAINTS in self.state.options and o.CONSTRAINT_SETS in self.state.options:
			return self._solver.simplify(split=True)
		else: return self._solver.simplify()


	#
	# Branching stuff
	#

	def copy(self):
		return SimConstraints(self._solver.branch())

	def merge(self, others, merge_flag, flag_values): # pylint: disable=W0613


		#import ipdb; ipdb.set_trace()

		self._stored_solver = self._solver.merge([ oc._solver for oc in others ], merge_flag, flag_values)
		#import ipdb; ipdb.set_trace()
		return [ ]

SimStatePlugin.register_default('constraints', SimConstraints)
import simuvex.s_options as o
from .s_exception import SimValueError

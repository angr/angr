#!/usr/bin/env python

# pylint: disable=R0201

import logging
l = logging.getLogger("s_value")

from .s_exception import SimError
class ConcretizingException(SimError):
	pass

from .s_helpers import ondemand
class SimValue(object):
	def __init__(self, expr, state = None):
		self.expr = expr
		self.state = state

	@ondemand
	def size(self):
		return self.size_bits()

	@ondemand
	def size_bits(self):
		return self.expr.size()

	@ondemand
	def size_bytes(self):
		return (self.expr.size()+7) / 8

	def max_for_size(self):
		return 2 ** self.size() - 1

	def min_for_size(self):
		return 0

	def stringify(self, n):
		return ("%x" % n).zfill(self.size()/4).decode('hex')

	def any_str(self, extra_constraints=None):
		return self.stringify(self.any(extra_constraints=extra_constraints))

	def exactly_n_str(self, n = 1, extra_constraints=None):
		return [ self.stringify(n) for n in self.exactly_n(n, extra_constraints=extra_constraints) ]

	def any_n_str(self, n = 1, extra_constraints=None):
		return [ self.stringify(n) for n in self.any_n(n, extra_constraints=extra_constraints) ]

	def is_unique(self, extra_constraints = None):
		'''Checks to see if there is a unique solution to this SimValue. If
		there is, and the SimValue is bound to a state, add the constraint
		in case it helps in future solves.'''

		if not self.is_symbolic():
			return True

		answers = self.any_n(2, extra_constraints=extra_constraints)
		if len(answers) != 1:
			return False

		# add a constraint keeping this unique (so that we don't waste future solving time)
		if self.state is not None and extra_constraints is None:
			self.state.add_constraints(self.expr == answers[0])

		return True

	@ondemand
	def is_symbolic(self):
		return self.expr.symbolic

	def satisfiable(self):
		return self.state['constraints'].satisfiable()

	def any(self, extra_constraints=None):
		return self.exactly_n(1, extra_constraints=extra_constraints)[0]

	def exactly_n(self, n = 1, extra_constraints=None):
		results = self.any_n(n + 1, extra_constraints=extra_constraints)

		if len(results) == 0:
			raise ConcretizingException("Could not concretize any values.")
		elif len(results[:n]) != n:
			raise ConcretizingException("Could only concretize %d/%d values." % (len(results), n))

		if self.is_symbolic() and n == 1 and len(results) == 1 and self.state is not None:
			self.state.add_constraints(self.expr == results[0])

		return results[:n]

	def any_n(self, n = 1, extra_constraints=None):
		return self.state.constraints.any(self.expr, n, extra_constraints=extra_constraints)

	def min(self, extra_constraints=None):
		return self.state.constraints.min(self.expr, extra_constraints=extra_constraints)

	def max(self, extra_constraints=None):
		return self.state.constraints.min(self.expr, extra_constraints=extra_constraints)

	def is_solution(self, solution):
		if not se.is_symbolic(self.expr):
			return self.satisfiable() and se.concretize_constant(self.expr) == solution

		if self.state is not None and o.CONCRETE_STRICT in self.state.options:
			raise ConcretizingException("attempting to concretize symbolic value in concrete mode")

		# TODO: concrete optimizations
		self.state.constraints.push()
		self.state.constraints.add(self.expr == solution)
		s = self.satisfiable()
		self.state.constraints.pop()
		return s

import simuvex.s_options as o

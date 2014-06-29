#!/usr/bin/env python

# pylint: disable=R0201

import logging
l = logging.getLogger("s_value")

import symexec as se

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
		return se.is_symbolic(self.expr)

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
		if not self.is_symbolic():
			return [ se.concretize_constant(self.expr) ]

		if self.state is not None and o.CONCRETE_STRICT in self.state.options:
			raise ConcretizingException("attempting to concretize symbolic value in concrete mode")

		# handle constant variables
		#if hasattr(self.expr, "as_long"):
		#	 return [ self.expr.as_long() ]

		results = [ ]

		self.state.constraints.push()

		if extra_constraints is not None:
			self.state['constraints'].add(*extra_constraints)

		for _ in range(n):
			s = self.satisfiable()

			if s:
				v = se.concretize_constant(self.state['constraints'].eval(self.expr))
				results.append(v)
				self.state['constraints'].add(self.expr != v)
			else:
				break

		self.state['constraints'].pop()

		return results

	def min(self, lo = 0, hi = 2**64):
		lo = max(lo, self.min_for_size())
		hi = min(hi, self.max_for_size())

		if not self.satisfiable():
			raise ConcretizingException("Unable to concretize expression %s", str(self.expr))

		if self.is_unique():
			return self.any()

		numpop = 0

		while hi - lo > 1:
			middle = (lo + hi)/2
			l.debug("h/m/l/d: %d %d %d %d", hi, middle, lo, hi-lo)

			self.state.constraints.push()
			self.state.constraints.add(se.UGE(self.expr, lo), se.ULT(self.expr, middle))
			numpop += 1

			if self.satisfiable():
				hi = middle - 1
			else:
				lo = middle
				self.state.constraints.pop()
				numpop -= 1

		for _ in range(numpop):
			self.state.constraints.pop()

		if hi == lo:
			return lo
		if self.is_solution(lo):
			return lo
		return hi

	def max(self, lo = 0, hi = 2**64):
		lo = max(lo, self.min_for_size())
		hi = min(hi, self.max_for_size())

		if not self.satisfiable():
			raise ConcretizingException("Unable to concretize expression %s", str(self.expr))

		if self.is_unique():
			return self.any()

		numpop = 0

		while hi - lo > 1:
			middle = (lo + hi)/2
			l.debug("h/m/l/d: %d %d %d %d", hi, middle, lo, hi-lo)

			self.state.constraints.push()
			self.state['constraints'].add(se.UGT(self.expr, middle), se.ULE(self.expr, hi))
			numpop += 1

			if self.satisfiable():
				lo = middle + 1
			else:
				hi = middle
				self.state.constraints.pop()
				numpop -= 1

		for _ in range(numpop):
			self.state.constraints.pop()

		if hi == lo:
			return hi
		if self.is_solution(hi):
			return hi
		return lo

	# iterates over all possible values
	def iter(self, lo=0, hi=2**64):
		l.error("ITER called. This is insanely slow and should not be used.")

		lo = max(lo, self.min_for_size(), self.min())
		hi = min(hi, self.max_for_size(), self.max())

		current = lo
		while current <= hi:
			current = self.min(current, hi)
			yield current
			current += 1

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

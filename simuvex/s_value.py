#!/usr/bin/env python

# pylint: disable=R0201

import logging
l = logging.getLogger("s_value")

import symexec
import s_exception
import s_helpers
import s_options as o

class ConcretizingException(s_exception.SimError):
	pass

class SimValue(object):
	__slots__ = [ 'expr', 'solver', 'state', '_size' ]

	def __init__(self, expr, state = None, constraints = None):
		self.expr = expr

		self.state = state
		if self.state is None:
			self.solver = symexec.Solver()
			if constraints != None and len(constraints) != 0:
				self.solver.add(*constraints)
		else:
			self.solver = self.state.solver

	@s_helpers.ondemand
	def size(self):
		return self.expr.size()

	def max_for_size(self):
		return 2 ** self.size() - 1

	def min_for_size(self):
		return 0

	def any(self):
		return self.exactly_n(1)[0]

	def any_str(self):
		return ("%x" % self.any()).decode('hex')

	def any_n_str(self, n):
		return [ ("%x" % v).decode('hex') for v in self.any_n(n) ]

	def is_unique(self):
		'''Checks to see if there is a unique solution to this SimValue. If
		there is, and the SimValue is bound to a state, add the constraint
		in case it helps in future solves.'''

		if not self.is_symbolic():
			return True

		answers = self.any_n(2)
		if len(answers) != 1:
			return False
		else:
			# add a constraint keeping this unique (so that we don't waste future solving time)
			if self.state is not None:
				self.state.add_constraints(self.expr == answers[0])
			return True

	def is_symbolic(self):
		return symexec.is_symbolic(self.expr)

	def satisfiable(self):
		return self.solver.check() == symexec.sat

	def exactly_n(self, n = 1):
		results = self.any_n(n)
		if len(results) != n:
			#print "=-========================================="
			#print self.expr
			#print "-------------------------------------------"
			#import pprint
			#pprint.pprint(self._constraints)
			#print "=========================================-="
			raise ConcretizingException("Could only concretize %d/%d values." % (len(results), n))
		return results

	def any_n(self, n = 1):
		if not self.is_symbolic():
			return [ symexec.concretize_constant(self.expr) ]

		if self.state is not None and o.SYMBOLIC not in self.state.options:
			raise ConcretizingException("attempting to concretize symbolic value in concrete mode")

		# handle constant variables
		#if hasattr(self.expr, "as_long"):
		#	 return [ self.expr.as_long() ]

		results = [ ]

		self.solver.push()

		for _ in range(n):
			s = self.satisfiable()

			if s:
				v = self.solver.eval(self.expr).as_long()
				if v is None: break

				results.append(v)

				self.solver.add(self.expr != v)
			else:
				break

		self.solver.pop()

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
			l.debug("h/m/l/d: %d %d %d %d" % (hi, middle, lo, hi-lo))

			self.solver.push()
			self.solver.add(symexec.UGE(self.expr, lo), symexec.ULT(self.expr, middle))
			numpop += 1

			if self.satisfiable():
				hi = middle - 1
			else:
				lo = middle
				self.solver.pop()
				numpop -= 1

		for _ in range(numpop):
			self.solver.pop()

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
			l.debug("h/m/l/d: %d %d %d %d" % (hi, middle, lo, hi-lo))

			self.solver.push()
			self.solver.add(symexec.UGT(self.expr, middle), symexec.ULE(self.expr, hi))
			numpop += 1

			if self.satisfiable():
				lo = middle + 1
			else:
				hi = middle
				self.solver.pop()
				numpop -= 1

		for _ in range(numpop):
			self.solver.pop()

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
		# TODO: concrete optimizations
		self.solver.push()
		self.solver.add(self.expr == solution)
		s = self.satisfiable()
		self.solver.pop()
		return s

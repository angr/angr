#!/usr/bin/env python

# pylint: disable=R0201

import logging
l = logging.getLogger("s_value")

import symexec
import s_exception
import s_helpers

class ConcretizingException(s_exception.SimError):
	pass

class SimValue:
	def __init__(self, expr, constraints = None):
		self.expr = expr
		self.constraints = [ ]
		self.constraint_indexes = [ ]

		self.solver = symexec.Solver()
		if constraints != None and len(constraints) != 0:
			self.push_constraints(*constraints)

	@s_helpers.ondemand
	def size(self):
		return self.expr.size()

	@s_helpers.ondemand
	def max_for_size(self):
		return 2 ** self.size() - 1

	@s_helpers.ondemand
	def min_for_size(self):
		return 0

	def any(self):
		return self.exactly_n(1)[0]

	def is_unique(self):
		if not self.is_symbolic():
			return True

		return len(self.any_n(2)) == 1

	def is_symbolic(self):
		return symexec.is_symbolic(self.expr)

	def satisfiable(self):
		return self.solver.check() == symexec.sat

	def push_constraints(self, *new_constraints):
		self.solver.push()
		self.constraint_indexes += [ len(self.constraints) ]
		self.constraints += new_constraints
		self.solver.add(*new_constraints)

	def pop_constraints(self):
		self.solver.pop()
		self.constraints = self.constraints[0:self.constraint_indexes.pop()]

	def howmany_satisfiable(self):
		valid = [ ]
		trying = [ ]
		for c in self.constraints:
			trying.append(c)
			l.debug("Trying %d constraints" % len(trying))
			if not SimValue(self.expr, trying).satisfiable():
				l.debug("Failed: %s" % str(c))
				break
			valid = [ t for t in trying ]

		l.debug("Valid: %d" % len(valid))
		return len(valid)

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

		# handle constant variables
		#if hasattr(self.expr, "as_long"):
		#	return [ self.expr.as_long() ]

		results = [ ]
		excluded = [ ]

		for _ in range(n):
			s = self.satisfiable()

			if s:
				v = self.solver.eval(self.expr).as_long()
				if v is None: break

				results.append(v)

				self.push_constraints(self.expr != v)
				excluded.append(self.expr != v)
			else:
				break

		for _ in excluded:
			self.pop_constraints()

		return results

	def min(self, lo = 0, hi = 2**64):
		lo = max(lo, self.min_for_size())
		hi = min(hi, self.max_for_size())

		if not self.satisfiable():
			raise ConcretizingException("Unable to concretize expression %s", str(self.expr))

		if self.is_unique():
			return self.any()

		while hi - lo > 1:
			middle = (lo + hi)/2
			l.debug("h/m/l/d: %d %d %d %d" % (hi, middle, lo, hi-lo))

			self.push_constraints(symexec.UGE(self.expr, lo), symexec.ULT(self.expr, middle))
			if self.satisfiable():
				hi = middle - 1
			else:
				lo = middle
			self.pop_constraints()

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

		while hi - lo > 1:
			middle = (lo + hi)/2
			l.debug("h/m/l/d: %d %d %d %d" % (hi, middle, lo, hi-lo))

			self.push_constraints(symexec.UGT(self.expr, middle), symexec.ULE(self.expr, hi))
			if self.satisfiable():
				lo = middle + 1
			else:
				hi = middle
			self.pop_constraints()

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
		self.push_constraints(self.expr == solution)
		s = self.satisfiable()
		self.pop_constraints()
		return s

	# def _get_step(self, expr, start, stop, incr):
	#	lo = 0 if (start < 0) else start
	#	hi = ((1 << self.arch_bits) - 1) if (stop < 0) else stop
	#	incr = 1 if (incr <= 0) else incr
	#	s = Solver()

	#	gcd = -1
	#	unsat_steps = 0

	#	while lo <= hi:
	#		s.add(expr == lo)
	#		if  s.check() == sat:
	#			gcd = unsat_steps if (gcd == -1) else fractions.gcd(gcd, unsat_steps)
	#			if gcd == 1:
	#				break
	#			unsat_steps = 1
	#		else:
	#			unsat_steps += 1
	#			s.reset()
	#		lo = lo + incr

	#	return gcd

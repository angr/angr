#!/usr/bin/env python

import z3
import os
#import s_helpers
import logging
import time

l = logging.getLogger("s_value")

import s_exception

class ConcretizingException(s_exception.SimError):
	pass

workaround_counter = 0

try:
	z3_path = os.environ["Z3PATH"]
except Exception:
	z3_path = "/opt/python/lib/"
z3.init(z3_path + "libz3.so")


class SimValue:
	def __init__(self, expr, constraints = None, lo = 0, hi = 2**64):
		self.expr = expr
		self.constraints = [ ]
		self.constraint_indexes = [ ]

		self.max_for_size = (2 ** self.expr.size() - 1) if z3.is_expr(expr) else 2**64
		self.min_for_size = 0
		self.prev_sat = None

		self.solver = z3.Solver()
		if constraints != None:
			self.push_constraints(constraints)


	def any(self):
		return self.exactly_n(1)[0]

	def is_unique(self):
		return len(self.any_n(2)) == 1

	def satisfiable(self):
		try:
			self.any()
			return True
		except ConcretizingException:
			return False

	def push_constraints(self, new_constraints):
		self.prev_sat = None

		self.solver.push()
		self.constraint_indexes += [ len(self.constraints) ]
		self.constraints += new_constraints
		self.solver.add(*new_constraints)

	def pop_constraints(self):
		self.prev_sat = None

		self.solver.pop()
		self.constraints = self.constraints[0:self.constraint_indexes.pop()]

	def check(self):
		if self.prev_sat is None:
			l.debug("Checking SATness of %d constraints" % len(self.constraints))
			a = time.time()
			self.prev_sat = self.solver.check()
			b = time.time()
			l.debug("... done in %s seconds" % (b - a))
		return self.prev_sat

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
		global workaround_counter

		# handle constant variables
		#if hasattr(self.expr, "as_long"):
		#	return [ self.expr.as_long() ]

		results = [ ]
		excluded = [ ]

		# workaround for z3 sometimes not giving value of BitVecRef
		w_vec = z3.BitVec("w_%d" % workaround_counter, self.expr.size())
		workaround_counter += 1
		self.push_constraints([ self.expr == w_vec ])

		for i in range(n):
			if excluded: self.push_constraints(excluded)
			s = self.check()
			if excluded: self.pop_constraints()

			if s == z3.sat:
				v = self.solver.model().get_interp(w_vec).as_long()
				if v is None: break

				results.append(v)
                                excluded.append(self.expr != v)
			else:
				break

		# pop the workaround
		self.pop_constraints()
		return results

	def min(self, lo = 0, hi = 2**64):
		lo = max(lo, self.min_for_size)
		hi = min(hi, self.max_for_size)

		if not self.satisfiable():
			raise ConcretizingException("Unable to concretize expression %s", str(self.expr))

		if self.is_unique():
			return self.any()

		while hi - lo > 1:
			middle = (lo + hi)/2
			l.debug("h/m/l/d: %d %d %d %d" % (hi, middle, lo, hi-lo))

			self.push_constraints([ z3.UGE(self.expr, lo), z3.ULT(self.expr, middle) ])
			if self.check() == z3.sat:
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
		lo = max(lo, self.min_for_size)
		hi = min(hi, self.max_for_size)

		if not self.satisfiable():
			raise ConcretizingException("Unable to concretize expression %s", str(self.expr))

		if self.is_unique():
			return self.any()

		while hi - lo > 1:
			middle = (lo + hi)/2
			l.debug("h/m/l/d: %d %d %d %d" % (hi, middle, lo, hi-lo))

			self.push_constraints([ z3.UGT(self.expr, middle), z3.ULE(self.expr, hi) ])
			if self.check() == z3.sat:
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
		lo = max(lo, self.min_for_size, self.min())
		hi = min(hi, self.max_for_size, self.max())

		self.current = lo
		while self.current <= hi:
			self.current = self.min(self.current, hi)
			yield self.current
			self.current += 1

	def is_solution(self, solution):
		self.push_constraints([ self.expr == solution ])
		s = self.check()
		self.pop_constraints()
		return s == z3.sat

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

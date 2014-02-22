#!/usr/bin/env python
'''This module includes some helper functions to avoid recursive imports.'''

import symexec as se
import functools
import simuvex
import itertools

import logging
l = logging.getLogger("s_helpers")
#l.setLevel(logging.DEBUG)

########################
### Helper functions ###
########################

sim_ite_counter = itertools.count()
def sim_ite(i, t, e, sym_name=None, sym_size=None):
	'''
	Returns an expression and a sequence of constraints that carry
	out an ITE, depending on if the condition is symbolic or concrete.
	'''
	sym_name = "sim_ite_%d" % sim_ite_counter.next() if sym_name is None else sym_name
	sym_size = t.size() if sym_size is None else sym_size

	if se.is_symbolic(i):
		print "SYMBOLIC:", i
		r = se.BitVec(sym_name, sym_size)
		c = [ se.Or(se.And(i, r == t), se.And(se.Not(i), r == e)) ]
	else:
		print "NOT SYMBOLIC:", i
		r = se.If(i, t, e)
		c = [ ]

	return r, c


def size_bits(t):
	'''Returns size, in BITS, of a type.'''
	for s in 256, 128, 64, 32, 16, 8, 1:
		if str(s) in t:
			return s
	raise Exception("Unable to determine length of %s." % t)

def size_bytes(t):
	'''Returns size, in BYTES, of a type.'''
	s = size_bits(t)
	if s == 1:
		raise Exception("size_bytes() is seeing a bit!")
	return s/8

def translate_irconst(c):
	size = size_bits(c.type)
	t = type(c.value)
	if t in (int, long):
		return se.BitVecVal(c.value, size)
	raise Exception("Unsupported constant type: %s" % type(c.value))

def flip_bytes(mem_expr):
	if mem_expr.size() == 8:
		return mem_expr

	buff = [ se.Extract(mem_expr.size() - n - 1, mem_expr.size() - n - 8, mem_expr) for n in range(0, mem_expr.size(), 8) ]
	return se.Concat(*reversed(buff))

def fix_endian(endness, mem_expr):
	if endness == "Iend_LE":
		return flip_bytes(mem_expr)
	else:
		return mem_expr

# Gets and removes a value from a dict. Returns a default value if it's not there
def get_and_remove(kwargs, what, default=None):
	if what in kwargs:
		v = kwargs[what]
		del kwargs[what]
		return v
	else:
		return default


#####################################
### Various decorators for tricks ###
#####################################

def flagged(f):
	f.flagged = True
	return f

def ondemand(f):
	name = f.__name__

	@functools.wraps(f)
	def func(self, *args, **kwargs):
		# only cache default calls
		if len(args) + len(kwargs) == 0:
			if hasattr(self, "_" + name):
				return getattr(self, "_" + name)

			a = f(self, *args, **kwargs)
			setattr(self, "_" + name, a)
			return a
		return f(self, *args, **kwargs)

	return func

def concretize_anything(state, a):
	if a.__class__ == simuvex.SimValue:
		if not a.is_symbolic():
			return a.any()
		else:
			# TODO: consider SimValue constraints
			v = state.make_concretized_int(a.expr)
			return v
	elif a.__class__.__name__.startswith('BitVec'):
		if not se.is_symbolic(a):
			return se.concretize_constant(a)
		else:
			v = state.make_concretized_int(a)
			return v
	else:
		return a

# TODO: account for not being in symbolic mode
def concretize_args(f):
	@functools.wraps(f)
	def func(self, *args, **kwargs):
		new_args = [ concretize_anything(self, a) for a in args ]
		return f(self, *new_args, **kwargs)

	return func

#!/usr/bin/env python
'''This module includes some helper functions to avoid recursive imports.'''

import symexec as se
import functools
import simuvex

import logging
l = logging.getLogger("s_helpers")
#l.setLevel(logging.DEBUG)

########################
### Helper functions ###
########################

def sim_ite(state, i, t, e, sym_name=None, sym_size=None):
	'''
	Returns an expression and a sequence of constraints that carry
	out an ITE, depending on if the condition is symbolic or concrete.
	'''
	sym_name = "sim_ite" if sym_name is None else sym_name
	if sym_size is None:
		if hasattr(t, 'size'): sym_size = t.size()
		else: sym_size = state.arch.bits

	# There are two modes to this operation. In symbolic mode, it makes a symbolic variable
	# and a set of constraints defining which value that variable has. In concrete mode,
	# it uses an If expression. The reason for this is that If is not Iff, and so if
	# the expression turns out to equal a specific value later in symbolic mode, an If
	# would not be sufficient to bind the condition accordingly.
	if se.is_symbolic(i):
		#print "SYMBOLIC:", i
		r = state.new_symbolic(sym_name, sym_size)
		c = [ se.Or(se.And(i, r == t), se.And(se.Not(i), r == e)) ]
	else:
		#print "NOT SYMBOLIC:", i
		if se.concretize_constant(i):
			r = t
		else:
			r = e
		#r = se.If(i, t, e)
		c = [ ]

	return r, c

def sim_ite_autoadd(state, i, t, e, sym_name=None, sym_size=None):
	'''
	Does an ITE, automatically adds constraints, and returns just the expression.
	'''
	r,c = sim_ite(state, i, t, e, sym_name=sym_name, sym_size=sym_size)

	#print "SDFJSDGFYUIGKSDFSUDFGVSUYDGFKSUDYGFUSDGFOAFYGAUSODFGSDF"
	#print "SDFJSDGFYUIGKSDFSUDFGVSUYDGFKSUDYGFUSDGFOAFYGAUSODFGSDF"
	#print "SDFJSDGFYUIGKSDFSUDFGVSUYDGFKSUDYGFUSDGFOAFYGAUSODFGSDF"
	#print r, se.variable_constituents(r)
	#if len(c): print c[0], se.variable_constituents(c[0])

	state.add_constraints(*c)
	return r

def sim_ite_dict(state, i, d, sym_name=None, sym_size=None):
	'''
	Returns an expression and a sequence of constraints that carry
	out an ITE, depending on if the condition is symbolic or concrete.
	'''
	sym_name = "sim_ite_dict" if sym_name is None else sym_name
	if sym_size is None:
		if hasattr(d.itervalues().next(), 'size'): sym_size = d.itervalues().next().size()
		else: sym_size = state.arch.bits

	if se.is_symbolic(i):
		r = state.new_symbolic(sym_name, sym_size)
		c = [ se.Or(*[se.And(i == k, r == v) for k,v in d.iteritems()]) ]
		return r,c
	else:
		return d[se.concretize_constant(i)], [ ]

def sim_ite_dict_autoadd(state, i, d, sym_name=None, sym_size=None):
	'''
	Does an ITE, automatically adds constraints, and returns just the expression.
	'''
	r,c = sim_ite_dict(state, i, d, sym_name=sym_name, sym_size=sym_size)
	state.add_constraints(*c)

	#print "SDFJSDGFYUIGKSDFSUDFGVSUYDGFKSUDYGFUSDGFOAFYGAUSODFGSDF"
	#print "SDFJSDGFYUIGKSDFSUDFGVSUYDGFKSUDYGFUSDGFOAFYGAUSODFGSDF"
	#print "SDFJSDGFYUIGKSDFSUDFGVSUYDGFKSUDYGFUSDGFOAFYGAUSODFGSDF"
	#print r, se.variable_constituents(r)
	#if len(c): print c[0], se.variable_constituents(c[0])

	return r

def sim_cases(state, cases, sym_name=None, sym_size=None):
	sym_name = "sim_cases" if sym_name is None else sym_name
	if sym_size is None:
		if hasattr(cases[0][1], 'size'): sym_size = cases[0][1].size()
		else: sym_size = state.arch.bits

	if all(not se.is_symbolic(c) for c,_ in cases):
		r = ( r for c,r in cases if se.concretize_constant(c) ).next()
		return r, [ ]
	else:
		e = state.new_symbolic(sym_name, sym_size)
		#for c,r in cases:
		#	print "##### CASE"
		#	print "#####",c
		#	print "#####",r
		constraints = [ se.Or(*[ se.And(c, e == r) for c,r in cases ]) ]
		return e, constraints

def sim_cases_autoadd(state, cases, sym_name=None, sym_size=None):
	r,c = sim_cases(state, cases, sym_name=sym_name, sym_size=sym_size)
	state.add_constraints(*c)

	#print "SDFJSDGFYUIGKSDFSUDFGVSUYDGFKSUDYGFUSDGFOAFYGAUSODFGSDF"
	#print "SDFJSDGFYUIGKSDFSUDFGVSUYDGFKSUDYGFUSDGFOAFYGAUSODFGSDF"
	#print "SDFJSDGFYUIGKSDFSUDFGVSUYDGFKSUDYGFUSDGFOAFYGAUSODFGSDF"
	#print r, se.variable_constituents(r)
	#if len(c): print c[0], se.variable_constituents(c[0])

	return r

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

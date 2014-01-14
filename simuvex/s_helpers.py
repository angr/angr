#!/usr/bin/env python
'''This module includes some helper functions to avoid recursive imports.'''

import symexec
import functools
import simuvex

import logging
l = logging.getLogger("s_helpers")
#l.setLevel(logging.DEBUG)

########################
### Helper functions ###
########################

# Returns size, in BYTES, of a type
def get_size(t):
	for s in 256, 128, 64, 32, 16, 8, 1:
		if str(s) in t:
			return s/8
	raise Exception("Unable to determine length of %s." % t)

def translate_irconst(c):
	size = get_size(c.type)
	t = type(c.value)
	if t == int or t == long:
		return symexec.BitVecVal(c.value, size*8)
	raise Exception("Unsupported constant type: %s" % type(c.value))

def fix_endian(endness, mem_expr):
	if mem_expr.size() == 8:
		return mem_expr

	if endness == "Iend_LE":
		buff = [ symexec.Extract(mem_expr.size() - n - 1, mem_expr.size() - n - 8, mem_expr) for n in range(0, mem_expr.size(), 8) ]
		return symexec.Concat(*reversed(buff))
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
		if not symexec.utils.is_symbolic(a):
			return symexec.utils.concretize_constant(a)
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

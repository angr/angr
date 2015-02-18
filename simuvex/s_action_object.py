import logging
l = logging.getLogger('simuvex.s_action')

import claripy
import collections
import functools

_noneset = frozenset()

def _raw_ast(a):
	if isinstance(a, SimActionObject):
		return a.ast
	elif isinstance(a, collections.Mapping):
		return { k:_raw_ast(a[k]) for k in a }
	elif isinstance(a, collections.Container):
		return type(a)(_raw_ast(b) for b in a)
	else:
		return a

def _all_objects(a):
	if isinstance(a, SimActionObject):
		yield a
	elif isinstance(a, collections.Mapping):
		for b in a.itervalues():
			for o in _all_objects(b):
				yield o
	elif isinstance(a, collections.Container):
		for b in a:
			for o in _all_objects(b):
				yield o

def ast_stripping_op(f, *args, **kwargs):
	new_args = _raw_ast(args)
	new_kwargs = _raw_ast(kwargs)
	return f(*new_args, **new_kwargs)

def ast_preserving_op(f, *args, **kwargs):
	tmp_deps = frozenset.union(_noneset, *(a.tmp_deps for a in _all_objects(args)))
	reg_deps = frozenset.union(_noneset, *(a.reg_deps for a in _all_objects(args)))

	a = ast_stripping_op(f, *args, **kwargs)
	if isinstance(a, claripy.A):
		return SimActionObject(a, reg_deps=reg_deps, tmp_deps=tmp_deps)
	else:
		return a

class SimActionObject(object):
	'''
	A SimActionObject tracks an AST and its dependencies.
	'''
	def __init__(self, ast, reg_deps=None, tmp_deps=None):
		if isinstance(ast, SimActionObject):
			raise SimActionError("SimActionObject inception!!!")
		self.ast = ast
		self.reg_deps = _noneset if reg_deps is None else reg_deps
		self.tmp_deps = _noneset if tmp_deps is None else tmp_deps

	def _preserving_unbound(self, f, *args, **kwargs):
		return ast_preserving_op(f, *((self,) + tuple(args)), **kwargs)

	def _preserving_bound(self, f, *args, **kwargs): #pylint:disable=no-self-use
		return ast_preserving_op(f, *args, **kwargs)

	def __getattr__(self, attr):
		f = getattr(self.ast, attr)
		if isinstance(f, collections.Callable):
			return functools.partial(self._preserving_bound, f)
		elif isinstance(f, claripy.A):
			return SimActionObject(f, reg_deps=self.reg_deps, tmp_deps=self.tmp_deps)
		else:
			return f

#
# Overload the operators
#

def _operator(cls, op_name):
	def wrapper(self, *args, **kwargs):
		return self._preserving_unbound(getattr(claripy.A, op_name), *args, **kwargs)
	wrapper.__name__ = op_name
	setattr(cls, op_name, wrapper)

def make_methods():
	for name in claripy.operations.expression_operations:
		_operator(SimActionObject, name)
make_methods()

from .s_errors import SimActionError

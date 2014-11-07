import functools

import claripy

def _raw_ast(a, info):
    t = type(a)
    if t in (tuple, list, set):
        return t(_raw_ast(e, info) for e in a)
    elif t is dict:
        return { k:_raw_ast(a[k], info) for k in a }
    elif isinstance(a, SimAST):
        for k in info:
            if k in a._info:
                info[k] |= a._info[k]

        for k in a._info:
            if k not in info:
                info[k] = set(a._info[k])

        return a._a
    else:
        return a

def ast_preserving_op(f, *args, **kwargs):
    new_info = kwargs.pop('info', set())
    new_args = _raw_ast(args, new_info)
    new_kwargs = _raw_ast(kwargs, new_info)
    a = f(*new_args, **new_kwargs)
    if isinstance(a, claripy.A):
        return SimAST(a, info=new_info)
    else:
        return a

class SimAST(claripy.A):
    __slots__ = [ '_a', '_info' ]
    __allowed__ = [ '_preserving_unbound', '_preserving_bound', '_copy_info', '__getstate__', '__setstate__' ]

    def __new__(cls, *args, **kwargs):
        return object.__new__(cls, *args, **kwargs)

    def __init__(self, a, info=None): #pylint:disable=super-init-not-called
        if isinstance(a, SimAST):
            raise Exception("wrapping a SimAST inside a SimAST!")
        if not isinstance(a, claripy.A):
            raise Exception("trying to wrap something that's not an A in a SimAST!")

        self._a = a
        self._info = { } if info is None else info

    def _copy_info(self):
        return { k:set(v) for k,v in self._info.iteritems() }

    def _preserving_unbound(self, f, *args, **kwargs):
        return ast_preserving_op(f, *((self,) + tuple(args)), info=self._info, **kwargs)

    def _preserving_bound(self, f, *args, **kwargs):
        return ast_preserving_op(f, *args, info=self._info, **kwargs)

    def __dir__(self):
        return sorted(tuple(set(dir(self._a) + SimAST.__slots__ + SimAST.__allowed__)))

    def __getattribute__(self, attr):
        if attr in SimAST.__slots__ + SimAST.__allowed__:
            return object.__getattribute__(self, attr)

        f = getattr(self._a, attr)
        if hasattr(f, '__call__'):
            return functools.partial(self._preserving_bound, f)
        else:
            return f

    def __getstate__(self): #pylint:disable=no-self-use
        raise SimASTError("SimAST objects should not be pickled.")
    def __setstate__(self, s): #pylint:disable=no-self-use,unused-argument
        raise SimASTError("SimAST objects should not be pickled.")

#
# Overload the operators
#

def _operator(cls, op_name):
    def wrapper(self, *args, **kwargs):
        return self._preserving_unbound(getattr(claripy.A, op_name), *args, **kwargs)
    wrapper.__name__ = op_name
    setattr(cls, op_name, wrapper)
    cls.__allowed__.append(op_name)

def make_methods():
    for name in claripy.operations.expression_operations:
        _operator(SimAST, name)
make_methods()

from .s_errors import SimASTError

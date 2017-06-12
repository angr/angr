import logging
l = logging.getLogger('simuvex.s_action')

import claripy
import functools

#pylint:disable=unidiomatic-typecheck

_noneset = frozenset()

def _raw_ast(a):
    if type(a) is SimActionObject:
        return a.ast
    elif type(a) is dict:
        return { k:_raw_ast(a[k]) for k in a }
    elif type(a) in (tuple, list, set, frozenset):
        return type(a)((_raw_ast(b) for b in a))
    else:
        return a

def _all_objects(a):
    if type(a) is SimActionObject:
        yield a
    elif type(a) is dict:
        for b in a.itervalues():
            for o in _all_objects(b):
                yield o
    elif type(a) is (tuple, list, set, frozenset):
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
    if isinstance(a, claripy.ast.Base):
        return SimActionObject(a, reg_deps=reg_deps, tmp_deps=tmp_deps)
    else:
        return a

def ast_stripping_decorator(f):
    @functools.wraps(f)
    def ast_stripper(*args, **kwargs):
        new_args = _raw_ast(args)
        new_kwargs = _raw_ast(kwargs)
        return f(*new_args, **new_kwargs)
    return ast_stripper


class SimActionObject(object):
    """
    A SimActionObject tracks an AST and its dependencies.
    """
    def __init__(self, ast, reg_deps=None, tmp_deps=None):
        if type(ast) is SimActionObject:
            raise SimActionError("SimActionObject inception!!!")
        self.ast = ast
        self.reg_deps = _noneset if reg_deps is None else reg_deps
        self.tmp_deps = _noneset if tmp_deps is None else tmp_deps

    def __repr__(self):
        return '<SAO {}>'.format(self.ast)

    def __getstate__(self):
        return self.ast, self.reg_deps, self.tmp_deps

    def __setstate__(self, data):
        self.ast, self.reg_deps, self.tmp_deps = data

    def _preserving_unbound(self, f, *args, **kwargs):
        return ast_preserving_op(f, *((self,) + tuple(args)), **kwargs)

    def _preserving_bound(self, f, *args, **kwargs): #pylint:disable=no-self-use
        return ast_preserving_op(f, *args, **kwargs)

    def __getattr__(self, attr):
        if attr == '__slots__':
            raise AttributeError("not forwarding __slots__ to AST")

        f = getattr(self.ast, attr)
        if hasattr(f, '__call__'):
            return functools.partial(self._preserving_bound, f)
        elif isinstance(f, claripy.ast.Base):
            return SimActionObject(f, reg_deps=self.reg_deps, tmp_deps=self.tmp_deps)
        else:
            return f

    def __len__(self):
        return len(self.ast)

    def to_claripy(self):
        return self.ast

    def copy(self):
        return SimActionObject(self.ast, self.reg_deps, self.tmp_deps)

#
# Overload the operators
#

def _operator(cls, op_name):
    def wrapper(self, *args, **kwargs):
        # TODO: don't always get from BV, we'll run into issues...
        return self._preserving_unbound(getattr(claripy.ast.BV, op_name), *args, **kwargs)
    wrapper.__name__ = op_name
    setattr(cls, op_name, wrapper)

def make_methods():
    for name in claripy.operations.expression_operations | { '__getitem__' } :
        _operator(SimActionObject, name)
make_methods()

from .s_errors import SimActionError

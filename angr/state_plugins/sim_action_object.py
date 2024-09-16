from __future__ import annotations

import functools
from itertools import chain
import typing

import claripy

from angr import sim_options as o
from angr.errors import SimActionError
from .sim_action import SimActionData, SimActionOperation
from ..sim_state import SimState

if typing.TYPE_CHECKING:
    from claripy.annotation import Annotation
    from claripy.ast.base import ArgType


def _raw_ast(a):
    if isinstance(a, SimActionObject):
        return a.ast
    if isinstance(a, dict):
        return {k: _raw_ast(v) for k, v in a.items()}
    if isinstance(a, tuple | list | set | frozenset):
        return type(a)(_raw_ast(b) for b in a)
    if isinstance(a, zip | filter | map):
        return (_raw_ast(i) for i in a)
    return a


def _all_objects(a):
    if isinstance(a, SimActionObject):
        yield a
    elif isinstance(a, dict):
        yield from chain(*(_all_objects(b) for b in a.values()))
    elif isinstance(a, tuple | list | set | frozenset):
        yield from chain(*(_all_objects(b) for b in a))


def ast_preserving_op(f, *args):
    a = f(_raw_ast(*args)) if len(args) else f()

    if isinstance(a, claripy.ast.Base):
        tmp_deps = frozenset.union(frozenset(), *(a.tmp_deps for a in _all_objects(args)))
        reg_deps = frozenset.union(frozenset(), *(a.reg_deps for a in _all_objects(args)))

        return SimActionObject(a, reg_deps=reg_deps, tmp_deps=tmp_deps)

    return a


def ast_stripping_decorator(f):
    @functools.wraps(f)
    def ast_stripper(*args, **kwargs):
        new_args = _raw_ast(args)
        new_kwargs = _raw_ast(kwargs)
        return f(*new_args, **new_kwargs)

    return ast_stripper


class SimActionObject:
    """
    A SimActionObject tracks an AST and its dependencies.
    """

    ast: claripy.ast.Base
    reg_deps: frozenset[SimActionData | SimActionOperation]
    tmp_deps: frozenset[SimActionData | SimActionOperation]

    def __init__(
        self,
        ast: claripy.ast.Base,
        reg_deps: frozenset[SimActionData | SimActionOperation] = frozenset(),
        tmp_deps: frozenset[SimActionData | SimActionOperation] = frozenset(),
        deps: frozenset = frozenset(),
        state: SimState | None = None,
    ):
        if isinstance(ast, SimActionObject):
            raise SimActionError("SimActionObject inception!!!")

        self.ast = ast
        if len(deps) != 0 and (state is None or o.ACTION_DEPS in state.options):
            self.reg_deps = frozenset.union(
                *[r.reg_deps for r in deps if isinstance(r, SimActionData | SimActionOperation)]
            )
            self.tmp_deps = frozenset.union(
                *[r.tmp_deps for r in deps if isinstance(r, SimActionData | SimActionOperation)]
            )
        else:
            self.reg_deps = reg_deps
            self.tmp_deps = tmp_deps

    def __repr__(self):
        return f"<SAO {self.ast}>"

    def __getstate__(self):
        return self.ast, self.reg_deps, self.tmp_deps

    def __setstate__(self, data):
        self.ast, self.reg_deps, self.tmp_deps = data

    def __len__(self) -> int | None:
        return len(self.ast)

    def __getitem__(self, k: int):
        return self.ast[k]

    def to_claripy(self) -> claripy.ast.Base:
        return self.ast

    def copy(self) -> SimActionObject:
        return SimActionObject(self.ast, self.reg_deps, self.tmp_deps)

    def is_leaf(self) -> bool:
        return self.ast.is_leaf()

    # Forwarding to ast

    @property
    def op(self) -> str:
        return self.ast.op

    @property
    def args(self) -> tuple[ArgType, ...]:
        return self.ast.args

    @property
    def length(self) -> int | None:
        return self.ast.length

    @property
    def variables(self) -> frozenset[str]:
        return self.ast.variables

    @property
    def symbolic(self) -> bool:
        return self.ast.symbolic

    @property
    def annotations(self) -> tuple[Annotation, ...]:
        return self.ast.annotations

    @property
    def depth(self) -> int:
        return self.ast.depth

    # Arithmetic operations
    def __add__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__add__, other)

    def __radd__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__radd__, other)

    def __truediv__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__truediv__, other)

    def __rtruediv__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rtruediv__, other)

    def __floordiv__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__floordiv__, other)

    def __rfloordiv__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rfloordiv__, other)

    def __mul__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__mul__, other)

    def __rmul__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rmul__, other)

    def __sub__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__sub__, other)

    def __rsub__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rsub__, other)

    def __pow__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__pow__, other)

    def __rpow__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rpow__, other)

    def __mod__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__mod__, other)

    def __rmod__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rmod__, other)

    def SDiv(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.SDiv, other)

    def SMod(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.SMod, other)

    def __neg__(self) -> SimActionObject:
        return ast_preserving_op(self.ast.__neg__)

    def __abs__(self) -> SimActionObject:
        return ast_preserving_op(self.ast.__abs__)

    # Comparison -> SimActionObjects
    def __eq__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__eq__, other)

    def __ne__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__ne__, other)

    def __ge__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__ge__, other)

    def __le__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__le__, other)

    def __gt__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__gt__, other)

    def __lt__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__lt__, other)

    # Bitwise operations
    def __invert__(self) -> SimActionObject:
        return ast_preserving_op(self.ast.__invert__)

    def __or__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__or__, other)

    def __ror__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__ror__, other)

    def __and__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__and__, other)

    def __rand__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rand__, other)

    def __xor__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__xor__, other)

    def __rxor__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rxor__, other)

    def __lshift__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__lshift__, other)

    def __rlshift__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rlshift__, other)

    def __rshift__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rshift__, other)

    def __rrshift__(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.__rrshift__, other)

    # Set operations
    def union(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.union, other)

    def intersection(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.intersection, other)

    def widen(self, other) -> SimActionObject:
        return ast_preserving_op(self.ast.widen, other)

    # Bits-specific methods
    def raw_to_bv(self) -> SimActionObject:
        return ast_preserving_op(self.ast.raw_to_bv)

    def bv_to_fp(self) -> SimActionObject:
        return ast_preserving_op(self.ast.raw_to_fp)

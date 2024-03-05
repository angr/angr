# pylint:disable=missing-class-docstring
"""
All type constants used in type inference. They can be mapped, translated, or rewritten to C-style types.
"""

from typing import List, Optional, Set
import functools


def memoize(f):
    @functools.wraps(f)
    def wrapped_repr(self, *args, **kwargs):
        if not kwargs or "memo" not in kwargs:
            memo = set()
        else:
            memo = kwargs.pop("memo")
        if self in memo:
            return "..."
        memo.add(self)
        r = f(self, *args, memo=memo, **kwargs)
        memo.remove(self)
        return r

    return wrapped_repr


class TypeConstant:
    SIZE = None

    def pp_str(self, mapping) -> str:  # pylint:disable=unused-argument
        return repr(self)

    def _hash(self, visited: Set[int]):  # pylint:disable=unused-argument
        return hash(type(self))

    def __eq__(self, other):
        return type(self) is type(other)

    def __hash__(self):
        return self._hash(set())

    @property
    def size(self) -> int:
        if self.SIZE is None:
            raise NotImplementedError()
        return self.SIZE

    def __repr__(self, memo=None):
        raise NotImplementedError()


class TopType(TypeConstant):
    def __repr__(self, memo=None):
        return "TOP"


class BottomType(TypeConstant):
    def __repr__(self, memo=None):
        return "BOT"


class Int(TypeConstant):
    def __repr__(self, memo=None):
        return "intbase"


class Int1(Int):
    SIZE = 1


class Int8(Int):
    SIZE = 1

    def __repr__(self, memo=None):
        return "int8"


class Int16(Int):
    SIZE = 2

    def __repr__(self, memo=None):
        return "int16"


class Int32(Int):
    SIZE = 4

    def __repr__(self, memo=None):
        return "int32"


class Int64(Int):
    SIZE = 8

    def __repr__(self, memo=None):
        return "int64"


class Int128(Int):
    SIZE = 16

    def __repr__(self, memo=None):
        return "int128"


class FloatBase(TypeConstant):
    def __repr__(self, memo=None):
        return "floatbase"


class Float(FloatBase):
    SIZE = 4

    def __repr__(self, memo=None):
        return "float"


class Double(FloatBase):
    SIZE = 8

    def __repr__(self, memo=None):
        return "double"


class Pointer(TypeConstant):
    def __init__(self, basetype: Optional[TypeConstant]):
        self.basetype: Optional[TypeConstant] = basetype

    def __eq__(self, other):
        return type(self) is type(other) and self.basetype == other.basetype

    def _hash(self, visited: Set[int]):
        if self.basetype is None:
            return hash(type(self))
        return hash((type(self), self.basetype._hash(visited)))

    def new(self, basetype):
        return self.__class__(basetype)

    def __hash__(self):
        return self._hash(set())


class Pointer32(Pointer, Int32):
    """
    32-bit pointers.
    """

    def __init__(self, basetype=None):
        Pointer.__init__(self, basetype)

    @memoize
    def __repr__(self, memo=None):
        bt = self.basetype.__repr__(memo=memo) if isinstance(self.basetype, TypeConstant) else repr(self.basetype)
        return f"ptr32({bt})"


class Pointer64(Pointer, Int64):
    """
    64-bit pointers.
    """

    def __init__(self, basetype=None):
        Pointer.__init__(self, basetype)

    @memoize
    def __repr__(self, memo=None):
        bt = self.basetype.__repr__(memo=memo) if isinstance(self.basetype, TypeConstant) else repr(self.basetype)
        return f"ptr64({bt})"


class Array(TypeConstant):
    def __init__(self, element=None, count=None):
        self.element: Optional[TypeConstant] = element
        self.count: Optional[int] = count

    @memoize
    def __repr__(self, memo=None):
        if self.count is None:
            return "%r[?]" % self.element
        else:
            return "%r[%d]" % (self.element, self.count)

    def __eq__(self, other):
        return type(other) is type(self) and self.element == other.element and self.count == other.count

    def _hash(self, visited: Set[int]):
        if id(self) in visited:
            return 0
        visited.add(id(self))
        return hash((type(self), self.element, self.count))

    def __hash__(self):
        return self._hash(set())


class Struct(TypeConstant):
    def __init__(self, fields=None, name=None, field_names=None):
        self.fields = {} if fields is None else fields  # offset to type
        self.name = name
        self.field_names = field_names

    def _hash(self, visited: Set[int]):
        if id(self) in visited:
            return 0
        visited.add(id(self))
        return hash((type(self), self._hash_fields(visited)))

    def _hash_fields(self, visited: Set[int]):
        keys = sorted(self.fields.keys())
        tpl = tuple((k, self.fields[k]._hash(visited) if self.fields[k] is not None else None) for k in keys)
        return hash(tpl)

    @memoize
    def __repr__(self, memo=None):
        prefix = "struct"
        if self.name:
            prefix = f"struct {self.name}"
        return prefix + "{" + ", ".join(f"{k}:{v.__repr__(memo=memo)}" for k, v in self.fields.items()) + "}"

    def __eq__(self, other):
        return type(other) is type(self) and hash(self) == hash(other)

    def __hash__(self):
        return self._hash(set())


class Function(TypeConstant):
    def __init__(self, params: List, outputs: List):
        self.params = params
        self.outputs = outputs

    @memoize
    def __repr__(self, memo=None):
        param_str = ", ".join(repr(param) for param in self.params)
        outputs_str = ", ".join(repr(output) for output in self.outputs)
        return f"func({param_str}) -> {outputs_str}"

    def __eq__(self, other):
        if not isinstance(other, Function):
            return False
        return self.params == other.params and self.outputs == other.outputs

    def _hash(self, visited: Set[int]):
        if id(self) in visited:
            return 0
        visited.add(id(self))

        params_hash = tuple(param._hash(visited) for param in self.params)
        outputs_hash = tuple(out._hash(visited) for out in self.outputs)
        return hash((Function, params_hash, outputs_hash))

    def __hash__(self):
        return self._hash(set())


class TypeVariableReference(TypeConstant):
    def __init__(self, typevar):
        self.typevar = typevar

    def __repr__(self, memo=None):
        return "ref(%s)" % self.typevar

    def __eq__(self, other):
        return type(other) is type(self) and self.typevar == other.typevar

    def __hash__(self):
        return hash((type(self), self.typevar))


#
# Methods
#


def int_type(bits: int) -> Optional[Int]:
    mapping = {
        1: Int1,
        8: Int8,
        16: Int16,
        32: Int32,
        64: Int64,
        128: Int128,
    }
    if bits in mapping:
        return mapping[bits]()
    return None


def float_type(bits: int) -> Optional[FloatBase]:
    if bits == 32:
        return Float()
    elif bits == 64:
        return Double()
    return None

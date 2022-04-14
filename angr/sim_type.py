# pylint:disable=abstract-method
from collections import OrderedDict, defaultdict, ChainMap

from archinfo import Endness
from .misc.ux import deprecated
import copy
import re
import logging
from typing import Optional, Dict, Any, Tuple, List, Union

import claripy

l = logging.getLogger(name=__name__)

# pycparser hack to parse type expressions
errorlog = logging.getLogger(name=__name__ + ".yacc")
errorlog.setLevel(logging.ERROR)

try:
    import pycparser
except ImportError:
    pycparser = None

try:
    import CppHeaderParser
except ImportError:
    CppHeaderParser = None


class SimType:
    """
    SimType exists to track type information for SimProcedures.
    """

    _fields = ()
    _arch = None
    _size = None
    _can_refine_int = False
    _base_name = None
    base = True

    def __init__(self, label=None):
        """
        :param label: the type label.
        """
        self.label = label

    def __eq__(self, other):
        if type(self) != type(other):
            return False

        for attr in self._fields:
            if attr == 'size' and self._arch is None and other._arch is None:
                continue
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        # wow many efficient
        return not self == other

    def __hash__(self):
        # very hashing algorithm many secure wow
        out = hash(type(self))
        for attr in self._fields:
            out ^= hash(getattr(self, attr))
        return out

    def _refine_dir(self): # pylint: disable=no-self-use
        return []

    def _refine(self, view, k): # pylint: disable=unused-argument,no-self-use
        raise KeyError(f"{k} is not a valid refinement")

    @property
    def size(self):
        """
        The size of the type in bits.
        """
        if self._size is not None:
            return self._size
        return NotImplemented

    @property
    def alignment(self):
        """
        The alignment of the type in bytes.
        """
        if self._arch is None:
            return NotImplemented
        if self.size is NotImplemented:
            return NotImplemented
        return self.size // self._arch.byte_width

    def with_arch(self, arch):
        if arch is None:
            return self
        if self._arch is not None and self._arch == arch:
            return self
        else:
            return self._with_arch(arch)

    def _with_arch(self, arch):
        cp = copy.copy(self)
        cp._arch = arch
        return cp

    def _init_str(self):
        return f"NotImplemented({self.__class__.__name__})"

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        if name is None:
            return repr(self)
        else:
            return f'{str(self) if self.label is None else self.label} {name}'

    def copy(self):
        raise NotImplementedError()

    def extract_claripy(self, bits):
        """
        Given a bitvector `bits` which was loaded from memory in a big-endian fashion, return a more appropriate or
        structured representation of the data.

        A type must have an arch associated in order to use this method.
        """
        raise NotImplementedError(f"extract_claripy is not implemented for {self}")

class TypeRef(SimType):
    """
    A TypeRef is a reference to a type with a name. This allows for interactivity in type analysis, by storing a type
    and having the option to update it later and have all references to it automatically update as well.
    """

    def __init__(self, name, ty):
        super().__init__()

        self.type = ty
        self._name = name

    @property
    def name(self):
        """
        This is a read-only property because it is desirable to store typerefs in a mapping from name to type, and we
        want the mapping to be in the loop for any updates.
        """
        return self._name

    def __eq__(self, other):
        return type(other) is TypeRef and self.type == other.type

    def __hash__(self):
        return hash(self.type)

    def __repr__(self):
        return self.name

    @property
    def _arch(self):
        return self.type._arch

    @property
    def size(self):
        return self.type.size

    @property
    def alignment(self):
        return self.type.alignment

    def with_arch(self, arch):
        self.type = self.type.with_arch(arch)
        return self

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        if not full:
            if name is not None:
                return f'{self.name} {name}'
            else:
                return self.name
        else:
            return self.type.c_repr(name=name, full=full, memo=memo, indent=indent)

    def copy(self):
        raise NotImplementedError("copy() for TypeRef is ill-defined. What do you want this to do?")

class NamedTypeMixin:
    """
    SimType classes with this mixin in the class hierarchy allows setting custom class names. A typical use case is
    to represent same or similar type classes with different qualified names, such as "std::basic_string" vs
    "std::__cxx11::basic_string". In such cases, .name stores the qualified name, and .unqualified_name() returns the
    unqualified name of the type.
    """
    def __init__(self, *args, name: Optional[str]=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._name = name

    @property
    def name(self) -> str:
        if self._name is None:
            self._name = repr(self)
        return self._name

    @name.setter
    def name(self, v):
        self._name = v

    def unqualified_name(self, lang: str = "c++") -> str:
        if lang == "c++":
            splitter = "::"
            n = self.name.split(splitter)
            return n[-1]
        raise NotImplementedError(f"Unsupported language {lang}.")


class SimTypeBottom(SimType):
    """
    SimTypeBottom basically represents a type error.
    """

    _base_name = 'bot'

    def __init__(self, label=None):
        super().__init__(label)

    def __repr__(self):
        return self.label or 'BOT'

    def _init_str(self):
        return "%s(%s)" % (
            self.__class__.__name__,
            ("label=\"%s\"" % self.label) if self.label else ""
        )

    def copy(self):
        return SimTypeBottom(self.label)


class SimTypeTop(SimType):
    """
    SimTypeTop represents any type (mostly used with a pointer for void*).
    """

    _fields = ('size',)

    def __init__(self, size=None, label=None):
        SimType.__init__(self, label)
        self._size = size

    def __repr__(self):
        return 'TOP'

    def copy(self):
        return SimTypeTop(size=self.size, label=self.label)


class SimTypeReg(SimType):
    """
    SimTypeReg is the base type for all types that are register-sized.
    """

    _fields = ('size',)

    def __init__(self, size, label=None):
        """
        :param label: the type label.
        :param size: the size of the type (e.g. 32bit, 8bit, etc.).
        """
        SimType.__init__(self, label=label)
        self._size = size

    def __repr__(self):
        return "reg{}_t".format(self.size)

    def extract(self, state, addr, concrete=False):
        # TODO: EDG says this looks dangerously closed-minded. Just in case...
        assert self.size % state.arch.byte_width == 0

        out = state.memory.load(addr, self.size // state.arch.byte_width, endness=state.arch.memory_endness)
        if not concrete:
            return out
        return state.solver.eval(out)

    def store(self, state, addr, value):
        store_endness = state.arch.memory_endness
        try:
            value = value.ast
        except AttributeError:
            pass
        if isinstance(value, claripy.ast.Bits):  # pylint:disable=isinstance-second-argument-not-valid-type
            if value.size() != self.size:
                raise ValueError("size of expression is wrong size for type")
        elif isinstance(value, int):
            value = state.solver.BVV(value, self.size)
        elif isinstance(value, bytes):
            store_endness = 'Iend_BE'
        else:
            raise TypeError("unrecognized expression type for SimType {}".format(type(self).__name__))

        state.memory.store(addr, value, endness=store_endness)

    def copy(self):
        return self.__class__(self.size, label=self.label)


class SimTypeNum(SimType):
    """
    SimTypeNum is a numeric type of arbitrary length
    """

    _fields = SimType._fields + ('signed', 'size')

    def __init__(self, size, signed=True, label=None):
        """
        :param size:        The size of the integer, in bits
        :param signed:      Whether the integer is signed or not
        :param label:       A label for the type
        """
        super().__init__(label)
        self._size = size
        self.signed = signed

    def __repr__(self):
        return "{}int{}_t".format('' if self.signed else 'u', self.size)

    def extract(self, state, addr, concrete=False):
        out = state.memory.load(addr, self.size // state.arch.byte_width, endness=state.arch.memory_endness)
        if not concrete:
            return out
        n = state.solver.eval(out)
        if self.signed and n >= 1 << (self.size-1):
            n -= 1 << (self.size)
        return n

    def store(self, state, addr, value):
        store_endness = state.arch.memory_endness

        if isinstance(value, claripy.ast.Bits):  # pylint:disable=isinstance-second-argument-not-valid-type
            if value.size() != self.size:
                raise ValueError("size of expression is wrong size for type")
        elif isinstance(value, int):
            value = state.solver.BVV(value, self.size)
        elif isinstance(value, bytes):
            store_endness = 'Iend_BE'
        else:
            raise TypeError("unrecognized expression type for SimType {}".format(type(self).__name__))

        state.memory.store(addr, value, endness=store_endness)

    def copy(self):
        return SimTypeNum(self.size, signed=self.signed, label=self.label)


class SimTypeInt(SimTypeReg):
    """
    SimTypeInt is a type that specifies a signed or unsigned C integer.
    """

    _fields = tuple(x for x in SimTypeReg._fields if x != 'size') + ('signed',)
    _base_name = 'int'

    def __init__(self, signed=True, label=None):
        """
        :param signed:  True if signed, False if unsigned
        :param label:   The type label
        """
        super().__init__(None, label=label)
        self.signed = signed

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        out = self._base_name
        if not self.signed:
            out = 'unsigned ' + out
        if name is None:
            return out
        return '%s %s' % (out, name)

    def __repr__(self):
        name = self._base_name
        if not self.signed:
            name = 'unsigned ' + name

        try:
            return name + ' (%d bits)' % self.size
        except ValueError:
            return name

    @property
    def size(self):
        if self._arch is None:
            raise ValueError("Can't tell my size without an arch!")
        try:
            return self._arch.sizeof[self._base_name]
        except KeyError:
            raise ValueError("Arch %s doesn't have its %s type defined!" % (self._arch.name, self._base_name))

    def extract(self, state, addr, concrete=False):
        out = state.memory.load(addr, self.size // state.arch.byte_width, endness=state.arch.memory_endness)
        if not concrete:
            return out
        n = state.solver.eval(out)
        if self.signed and n >= 1 << (self.size-1):
            n -= 1 << self.size
        return n

    def _init_str(self):
        return "%s(signed=%s%s)" % (
            self.__class__.__name__,
            self.signed,
            (', label="%s"' % self.label) if self.label is not None else "",
        )

    def _refine_dir(self):
        return ['signed', 'unsigned']

    def _refine(self, view, k):
        if k == 'signed':
            ty = copy.copy(self)
            ty.signed = True
        elif k == 'unsigned':
            ty = copy.copy(self)
            ty.signed = False
        else:
            raise KeyError(k)
        return view._deeper(ty=ty)

    def copy(self):
        return self.__class__(signed=self.signed, label=self.label)


class SimTypeShort(SimTypeInt):
    _base_name = 'short'


class SimTypeLong(SimTypeInt):
    _base_name = 'long'


class SimTypeLongLong(SimTypeInt):
    _base_name = 'long long'


class SimTypeChar(SimTypeReg):
    """
    SimTypeChar is a type that specifies a character;
    this could be represented by a byte, but this is meant to be interpreted as a character.
    """

    _base_name = 'char'

    def __init__(self, signed=True, label=None):
        """
        :param label: the type label.
        """
        # FIXME: Now the size of a char is state-dependent.
        SimTypeReg.__init__(self, 8, label=label)
        self.signed = signed

    def __repr__(self):
        return 'char'

    def store(self, state, addr, value):
        # FIXME: This is a hack.
        self._size = state.arch.byte_width
        try:
            super().store(state, addr, value)
        except TypeError:
            if isinstance(value, bytes) and len(value) == 1:
                value = state.solver.BVV(value[0], state.arch.byte_width)
                super().store(state, addr, value)
            else:
                raise

    def extract(self, state, addr, concrete=False):
        # FIXME: This is a hack.
        self._size = state.arch.byte_width

        out = super().extract(state, addr, concrete)
        if concrete:
            return bytes([out])
        return out

    def _init_str(self):
        return "%s(%s)" % (
            self.__class__.__name__,
            ('label="%s"' % self.label) if self.label is not None else "",
        )

    def copy(self):
        return self.__class__(signed=self.signed, label=self.label)


class SimTypeBool(SimTypeChar):

    _base_name = "bool"

    def __repr__(self):
        return 'bool'

    def store(self, state, addr, value):
        return super().store(state, addr, int(value))

    def extract(self, state, addr, concrete=False):
        ver = super().extract(state, addr, concrete)
        if concrete:
            return ver != b'\0'
        return ver != 0

    def _init_str(self):
        return f"{self.__class__.__name__}()"


class SimTypeFd(SimTypeReg):
    """
    SimTypeFd is a type that specifies a file descriptor.
    """

    _fields = SimTypeReg._fields

    def __init__(self, label=None):
        """
        :param label: the type label
        """
        # file descriptors are always 32 bits, right?
        # TODO: That's so closed-minded!
        super().__init__(32, label=label)

    def __repr__(self):
        return 'fd_t'

    def copy(self):
        return SimTypeFd(label=self.label)

    def _init_str(self):
        return "%s(%s)" % (
            self.__class__.__name__,
            ('label="%s"' % self.label) if self.label is not None else "",
        )


class SimTypePointer(SimTypeReg):
    """
    SimTypePointer is a type that specifies a pointer to some other type.
    """

    _fields = tuple(x for x in SimTypeReg._fields if x != 'size') + ('pts_to',)

    def __init__(self, pts_to, label=None, offset=0):
        """
        :param label:   The type label.
        :param pts_to:  The type to which this pointer points.
        """
        super().__init__(None, label=label)
        self.pts_to = pts_to
        self.signed = False
        self.offset = offset

    def __repr__(self):
        return '{}*'.format(self.pts_to)

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        # if it points to an array, we do not need to add a *
        deref_chr = '*' if not isinstance(self.pts_to, SimTypeArray) else ''
        name_with_deref = deref_chr if name is None else '%s%s' % (deref_chr, name)
        return self.pts_to.c_repr(name_with_deref, full, memo, indent)

    def make(self, pts_to):
        new = type(self)(pts_to)
        new._arch = self._arch
        return new

    @property
    def size(self):
        if self._arch is None:
            raise ValueError("Can't tell my size without an arch!")
        return self._arch.bits

    def _with_arch(self, arch):
        out = SimTypePointer(self.pts_to.with_arch(arch), self.label)
        out._arch = arch
        return out

    def _init_str(self):
        return "%s(%s%s, offset=%d)" % (
            self.__class__.__name__,
            self.pts_to._init_str(),
            (', label="%s"' % self.label) if self.label is not None else "",
            self.offset
        )

    def copy(self):
        return SimTypePointer(self.pts_to, label=self.label, offset=self.offset)


class SimTypeReference(SimTypeReg):
    """
    SimTypeReference is a type that specifies a reference to some other type.
    """
    def __init__(self, refs, label=None):
        super().__init__(None, label=label)
        self.refs: SimType = refs

    def __repr__(self):
        return f"{self.refs}&"

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        name = '&' if name is None else '&%s' % name
        return self.refs.c_repr(name, full, memo, indent)

    def make(self, refs):
        new = type(self)(refs)
        new._arch = self._arch
        return new

    @property
    def size(self):
        if self._arch is None:
            raise ValueError("Can't tell my size without an arch!")
        return self._arch.bits

    def _with_arch(self, arch):
        out = SimTypeReference(self.refs.with_arch(arch), label=self.label)
        out._arch = arch
        return out

    def _init_str(self):
        return "%s(%s%s)" % (
            self.__class__.__name__,
            self.refs._init_str(),
            (', label="%s"' % self.label) if self.label is not None else "",
        )

    def copy(self):
        return SimTypeReference(self.refs, label=self.label)


class SimTypeFixedSizeArray(SimType):
    """
    SimTypeFixedSizeArray is a literal (i.e. not a pointer) fixed-size array.
    """

    def __init__(self, elem_type, length):
        super().__init__()
        self.elem_type = elem_type
        self.length = length

    def __repr__(self):
        return '{}[{}]'.format(self.elem_type, self.length)

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        if name is None:
            return repr(self)

        name = '%s[%s]' % (name, self.length)
        return self.elem_type.c_repr(name, full, memo, indent)

    _can_refine_int = True

    def _refine(self, view, k):
        return view._deeper(addr=view._addr + k * (self.elem_type.size//view.state.arch.byte_width), ty=self.elem_type)

    def extract(self, state, addr, concrete=False):
        return [self.elem_type.extract(state, addr + i*(self.elem_type.size//state.arch.byte_width), concrete) for i in range(self.length)]

    def store(self, state, addr, values):
        for i, val in enumerate(values):
            self.elem_type.store(state, addr + i * (self.elem_type.size // state.arch.byte_width), val)

    @property
    def size(self):
        return self.elem_type.size * self.length

    @property
    def alignment(self):
        return self.elem_type.alignment

    def _with_arch(self, arch):
        out = SimTypeFixedSizeArray(self.elem_type.with_arch(arch), self.length)
        out._arch = arch
        return out

    def _init_str(self):
        return "%s(%s, %d)" % (
            self.__class__.__name__,
            self.elem_type._init_str(),
            self.length,
        )

    def copy(self):
        return SimTypeFixedSizeArray(self.elem_type, self.length)


class SimTypeArray(SimType):
    """
    SimTypeArray is a type that specifies a pointer to an array; while it is a pointer, it has a semantic difference.
    """

    _fields = ('elem_type', 'length')

    def __init__(self, elem_type, length=None, label=None):
        """
        :param label:       The type label.
        :param elem_type:   The type of each element in the array.
        :param length:      An expression of the length of the array, if known.
        """
        super().__init__(label=label)
        self.elem_type: SimType = elem_type
        self.length: Optional[int] = length

    def __repr__(self):
        return '{}[{}]'.format(self.elem_type, '' if self.length is None else self.length)

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        if name is None:
            return repr(self)

        name = '%s[%s]' % (name, self.length if self.length is not None else '')
        return self.elem_type.c_repr(name, full, memo, indent)

    @property
    def size(self):
        if self._arch is None:
            raise ValueError("I can't tell my size without an arch!")
        return self._arch.bits

    @property
    def alignment(self):
        return self.elem_type.alignment

    def _with_arch(self, arch):
        out = SimTypeArray(self.elem_type.with_arch(arch), self.length, self.label)
        out._arch = arch
        return out

    def copy(self):
        return SimTypeArray(self.elem_type, length=self.length, label=self.label)


class SimTypeString(NamedTypeMixin, SimTypeArray):
    """
    SimTypeString is a type that represents a C-style string,
    i.e. a NUL-terminated array of bytes.
    """

    _fields = SimTypeArray._fields + ('length',)

    def __init__(self, length=None, label=None, name: Optional[str]=None):
        """
        :param label:   The type label.
        :param length:  An expression of the length of the string, if known.
        """
        super().__init__(SimTypeChar(), label=label, length=length, name=name)

    def __repr__(self):
        return 'string_t'

    def extract(self, state: "SimState", addr, concrete=False):
        if self.length is None:
            out = None
            last_byte = state.memory.load(addr, size=1)
            # if we try to extract a symbolic string, it's likely that we are going to be trapped in a very large loop.
            if state.solver.symbolic(last_byte):
                raise ValueError("Trying to extract a symbolic string at %#x" % state.solver.eval(addr))
            addr += 1
            while not (claripy.is_true(last_byte == 0) or state.solver.symbolic(last_byte)):
                out = last_byte if out is None else out.concat(last_byte)
                last_byte = state.memory.load(addr, size=1)
                addr += 1
        else:
            out = state.memory.load(addr, size=self.length)
        if not concrete:
            return out if out is not None else claripy.BVV(0, 0)
        else:
            return state.solver.eval(out, cast_to=bytes) if out is not None else b''

    _can_refine_int = True

    def _refine(self, view, k):
        return view._deeper(addr=view._addr + k, ty=SimTypeChar())

    @property
    def size(self):
        if self.length is None:
            return 4096         # :/
        return (self.length + 1) * 8

    @property
    def alignment(self):
        return 1

    def _with_arch(self, arch):
        return self

    def copy(self):
        return SimTypeString(length=self.length, label=self.label, name=self.name)


class SimTypeWString(NamedTypeMixin, SimTypeArray):
    """
    A wide-character null-terminated string, where each character is 2 bytes.
    """

    _fields = SimTypeArray._fields + ('length',)

    def __init__(self, length=None, label=None, name: Optional[str]=None):
        super().__init__(SimTypeNum(16, False), label=label, length=length, name=name)

    def __repr__(self):
        return 'wstring_t'

    def extract(self, state, addr, concrete=False):
        if self.length is None:
            out = None
            last_byte = state.memory.load(addr, 2)
            # if we try to extract a symbolic string, it's likely that we are going to be trapped in a very large loop.
            if state.solver.symbolic(last_byte):
                raise ValueError("Trying to extract a symbolic string at %#x" % state.solver.eval(addr))
            addr += 2
            while not (claripy.is_true(last_byte == 0) or state.solver.symbolic(last_byte)):
                out = last_byte if out is None else out.concat(last_byte)
                last_byte = state.memory.load(addr, 2)
                addr += 2
        else:
            out = state.memory.load(addr, self.length*2)
        if out is None: out = claripy.BVV(0, 0)
        if not concrete:
            return out
        else:
            return u''.join(chr(state.solver.eval(x.reversed if state.arch.memory_endness == 'Iend_LE' else x)) for x in out.chop(16))

    _can_refine_int = True

    def _refine(self, view, k):
        return view._deeper(addr=view._addr + k * 2, ty=SimTypeNum(16, False))

    @property
    def size(self):
        if self.length is None:
            return 4096
        return (self.length * 2 + 2) * 8

    @property
    def alignment(self):
        return 2

    def _with_arch(self, arch):
        return self

    def copy(self):
        return SimTypeWString(length=self.length, label=self.label, name=self.name)


class SimTypeFunction(SimType):
    """
    SimTypeFunction is a type that specifies an actual function (i.e. not a pointer) with certain types of arguments and
    a certain return value.
    """

    _fields = ('args', 'returnty')
    base = False

    def __init__(self, args, returnty, label=None, arg_names=None, variadic=False):
        """
        :param label:    The type label
        :param args:     A tuple of types representing the arguments to the function
        :param returnty: The return type of the function, or none for void
        :param variadic: Whether the function accepts varargs
        """
        super().__init__(label=label)
        self.args = args
        self.returnty: Optional[SimType] = returnty
        self.arg_names = arg_names if arg_names else ()
        self.variadic = variadic

    def __repr__(self):
        argstrs = [str(a) for a in self.args]
        if self.variadic:
            argstrs.append('...')
        return '({}) -> {}'.format(', '.join(argstrs), self.returnty)

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        name2 = name or ''
        name3 = '(%s)(%s)' % (name2, ', '.join(a.c_repr(n, full-1, memo, indent) for a, n in zip(self.args, self.arg_names if self.arg_names is not None and full else (None,)*len(self.args))))
        name4 = self.returnty.c_repr(name3, full, memo, indent) if self.returnty is not None else 'void %s' % name3
        return name4

    @property
    def size(self):
        return 4096     # ???????????

    def _with_arch(self, arch):
        out = SimTypeFunction([a.with_arch(arch) for a in self.args],
                              self.returnty.with_arch(arch) if self.returnty is not None else None,
                              label=self.label,
                              arg_names=self.arg_names,
                              variadic=self.variadic
                              )
        out._arch = arch
        return out

    def _arg_names_str(self, show_variadic=True):
        argnames = list(self.arg_names)
        if self.variadic and show_variadic:
            argnames.append('...')
        return ", ".join('"%s"' % arg_name for arg_name in argnames)

    def _init_str(self):
        return "%s([%s], %s%s%s%s)" % (
            self.__class__.__name__,
            ", ".join([arg._init_str() for arg in self.args]),
            self.returnty._init_str(),
            (", label=\"%s\"" % self.label) if self.label else "",
            (", arg_names=[%s]" % self._arg_names_str(show_variadic=False)) if self.arg_names else "",
            ", variadic=True" if self.variadic else "",
        )

    def copy(self):
        return SimTypeFunction(self.args, self.returnty, label=self.label, arg_names=self.arg_names,
                               variadic=self.variadic)


class SimTypeCppFunction(SimTypeFunction):
    """
    SimTypeCppFunction is a type that specifies an actual C++-style function with information about arguments, return
    value, and more C++-specific properties.

    :ivar ctor: Whether the function is a constructor or not.
    :ivar dtor: Whether the function is a destructor or not.
    """
    def __init__(self, args, returnty, label=None, arg_names: Tuple[str]=None, ctor: bool=False, dtor: bool=False):
        super().__init__(args, returnty, label=label, arg_names=arg_names, variadic=False)
        self.ctor = ctor
        self.dtor = dtor

    def __repr__(self):
        argstrs = [str(a) for a in self.args]
        if self.variadic:
            argstrs.append('...')
        return str(self.label)+'({}) -> {}'.format(', '.join(argstrs), self.returnty)

    def _init_str(self):
        return "%s([%s], %s%s%s%s)" % (
            self.__class__.__name__,
            ", ".join([arg._init_str() for arg in self.args]),
            self.returnty,
            (", label=%s" % self.label) if self.label else "",
            (", arg_names=[%s]" % self._arg_names_str(show_variadic=False)) if self.arg_names else "",
            ", variadic=True" if self.variadic else "",
        )

    def copy(self):
        return SimTypeCppFunction(
            self.args,
            self.returnty,
            label=self.label,
            arg_names=self.arg_names,
            ctor=self.ctor,
            dtor=self.dtor,
        )


class SimTypeLength(SimTypeLong):
    """
    SimTypeLength is a type that specifies the length of some buffer in memory.

    ...I'm not really sure what the original design of this class was going for
    """

    _fields = tuple(x for x in SimTypeReg._fields if x != 'size') + ('addr', 'length') # ?

    def __init__(self, signed=False, addr=None, length=None, label=None):
        """
        :param signed:  Whether the value is signed or not
        :param label:   The type label.
        :param addr:    The memory address (expression).
        :param length:  The length (expression).
        """
        super().__init__(signed=signed, label=label)
        self.addr = addr
        self.length = length

    def __repr__(self):
        return 'size_t'

    @property
    def size(self):
        if self._arch is None:
            raise ValueError("I can't tell my size without an arch!")
        return self._arch.bits

    def _init_str(self):
        return "%s(size=%d)" % (
            self.__class__.__name__,
            self.size
        )

    def copy(self):
        return SimTypeLength(signed=self.signed, addr=self.addr, length=self.length, label=self.label)


class SimTypeFloat(SimTypeReg):
    """
    An IEEE754 single-precision floating point number
    """

    _base_name = 'float'

    def __init__(self, size=32):
        super().__init__(size)

    sort = claripy.FSORT_FLOAT
    signed = True

    def extract(self, state, addr, concrete=False):
        itype = claripy.fpToFP(super().extract(state, addr, False), self.sort)
        if concrete:
            return state.solver.eval(itype)
        return itype

    def store(self, state, addr, value):
        if type(value) in (int, float):
            value = claripy.FPV(float(value), self.sort)
        return super().store(state, addr, value)

    def __repr__(self):
        return 'float'

    def _init_str(self):
        return "%s(size=%d)" % (
            self.__class__.__name__,
            self.size
        )

    def copy(self):
        return SimTypeFloat(self.size)


class SimTypeDouble(SimTypeFloat):
    """
    An IEEE754 double-precision floating point number
    """

    _base_name = 'double'

    def __init__(self, align_double=True):
        self.align_double = align_double
        super().__init__(64)

    sort = claripy.FSORT_DOUBLE

    def __repr__(self):
        return 'double'

    @property
    def alignment(self):
        return 8 if self.align_double else 4

    def _init_str(self):
        return "%s(align_double=%s)" % (
            self.__class__.__name__,
            self.align_double
        )

    def copy(self):
        return SimTypeDouble(align_double=self.align_double)


class SimStruct(NamedTypeMixin, SimType):
    _fields = ('name', 'fields')

    def __init__(self, fields: Union[Dict[str,SimType], OrderedDict], name=None, pack=False, align=None):
        super().__init__(None, name='<anon>' if name is None else name)

        self._pack = pack
        self._align = align
        self._pack = pack
        self.fields = fields

        self._arch_memo = {}

    @property
    def packed(self):
        return self._pack

    @property
    def offsets(self) -> Dict[str,int]:
        offsets = {}
        offset_so_far = 0
        for name, ty in self.fields.items():
            if isinstance(ty, SimTypeBottom):
                l.warning("Found a bottom field in struct %s. Ignore and increment the offset using the default "
                          "element size.", self.name)
                continue
            if not self._pack:
                align = ty.alignment
                if align is NotImplemented:
                    # hack!
                    align = 1
                if offset_so_far % align != 0:
                    offset_so_far += (align - offset_so_far % align)
                offsets[name] = offset_so_far
                offset_so_far += ty.size // self._arch.byte_width
            else:
                offsets[name] = offset_so_far // self._arch.byte_width
                offset_so_far += ty.size

        return offsets

    def extract(self, state, addr, concrete=False):
        values = {}
        for name, offset in self.offsets.items():
            ty = self.fields[name]
            v = SimMemView(ty=ty, addr=addr+offset, state=state)
            if concrete:
                values[name] = v.concrete
            else:
                values[name] = v.resolved

        return SimStructValue(self, values=values)

    def _with_arch(self, arch):
        if arch.name in self._arch_memo:
            return self._arch_memo[arch.name]

        out = SimStruct(None, name=self.name, pack=self._pack, align=self._align)
        out._arch = arch
        self._arch_memo[arch.name] = out


        out.fields = OrderedDict((k, v.with_arch(arch)) for k, v in self.fields.items())

        # Fixup the offsets to byte aligned addresses for all SimTypeNumOffset types
        offset_so_far = 0
        for name, ty in out.fields.items():
            if isinstance(ty, SimTypeNumOffset):
                out._pack = True
                ty.offset = offset_so_far % arch.byte_width
                offset_so_far += ty.size
        return out

    def __repr__(self):
        return 'struct %s' % self.name

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        if not full or (memo is not None and self in memo):
            return super().c_repr(name, full, memo, indent)

        indented = ' ' * indent if indent is not None else ''
        new_indent = indent + 4 if indent is not None else None
        new_indented = ' ' * new_indent if indent is not None else ''
        newline = '\n' if indent is not None else ' '
        new_memo = (self,) + (memo if memo is not None else ())
        members = newline.join(new_indented + v.c_repr(k, full-1, new_memo, new_indent) + ';' for k, v in self.fields.items())
        return 'struct %s {%s%s%s%s}%s' % (self.name, newline, members, newline, indented, '' if name is None else ' ' + name)

    def __hash__(self):
        return hash((SimStruct, self._name, self._align, self._pack, tuple(self.fields.keys())))

    @property
    def size(self):
        if not self.offsets:
            return 0

        last_name, last_off = list(self.offsets.items())[-1]
        last_type = self.fields[last_name]
        if isinstance(last_type, SimTypeNumOffset):
            return last_off * self._arch.byte_width + (last_type.size + last_type.offset)
        else:
            return last_off * self._arch.byte_width + last_type.size

    @property
    def alignment(self):
        if self._align is not None:
            return self._align
        return max(val.alignment for val in self.fields.values() if not isinstance(val, SimTypeBottom))

    def _refine_dir(self):
        return list(self.fields.keys())

    def _refine(self, view, k):
        offset = self.offsets[k]
        ty = self.fields[k]
        return view._deeper(ty=ty, addr=view._addr + offset)

    def store(self, state, addr, value):
        if type(value) is dict:
            pass
        elif type(value) is SimStructValue:
            value = value._values
        else:
            raise TypeError("Can't store struct of type %s" % type(value))

        if len(value) != len(self.fields):
            raise ValueError("Passed bad values for %s; expected %d, got %d" % (self, len(self.offsets), len(value)))

        for field, offset in self.offsets.items():
            ty = self.fields[field]
            ty.store(state, addr + offset, value[field])

    @staticmethod
    def _field_str(field_name, field_type):
        return "\"%s\": %s" % (field_name, field_type._init_str())

    def _init_str(self):
        return "%s({%s}, name=\"%s\", pack=%s, align=%s)" % (
            self.__class__.__name__,
            ", ".join([self._field_str(f, ty) for f, ty in self.fields.items()]),
            self._name,
            self._pack,
            self._align,
        )

    def copy(self):
        return SimStruct(dict(self.fields), name=self.name, pack=self._pack, align=self._align)


class SimStructValue:
    """
    A SimStruct type paired with some real values
    """
    def __init__(self, struct, values=None):
        """
        :param struct:      A SimStruct instance describing the type of this struct
        :param values:      A mapping from struct fields to values
        """
        self._struct = struct
        # since the keys are specified, also support specifying the values as just a list
        if values is not None and hasattr(values, '__iter__') and not hasattr(values, 'items'):
            values = dict(zip(struct.fields.keys(), values))
        self._values = defaultdict(lambda: None, values or ())

    @property
    def struct(self):
        return self._struct

    def __indented_repr__(self, indent=0):
        fields = []
        for name in self._struct.fields:
            value = self._values[name]
            try:
                f = getattr(value, '__indented_repr__')
                s = f(indent=indent+2)
            except AttributeError:
                s = repr(value)
            fields.append(' ' * (indent + 2) + '.{} = {}'.format(name, s))

        return '{{\n{}\n{}}}'.format(',\n'.join(fields), ' ' * indent)

    def __repr__(self):
        return self.__indented_repr__()

    def __getattr__(self, k):
        return self[k]

    def __getitem__(self, k):
        if type(k) is int:
            k = self._struct.fields[k]
        if k not in self._values:
            for f in self._struct.fields:
                if isinstance(f, NamedTypeMixin) and f.name is None:
                    try:
                        return f[k]
                    except:
                        continue
            else:
                return self._values[k]

        return self._values[k]

    def copy(self):
        return SimStructValue(self._struct, values=defaultdict(lambda: None, self._values))


class SimUnion(NamedTypeMixin, SimType):
    fields = ('members', 'name')

    def __init__(self, members, name=None, label=None):
        """
        :param members:     The members of the union, as a mapping name -> type
        :param name:        The name of the union
        """
        super().__init__(label, name=name if name is not None else '<anon>')
        self.members = members

    @property
    def size(self):
        return max(ty.size for ty in self.members.values() if not isinstance(ty, SimTypeBottom))

    @property
    def alignment(self):
        return max(val.alignment for val in self.members.values() if not isinstance(val, SimTypeBottom))

    def _refine_dir(self):
        return list(self.members.keys())

    def _refine(self, view, k):
        ty = self.members[k]
        return view._deeper(ty=ty, addr=view._addr)

    def extract(self, state, addr, concrete=False):
        values = {}
        for name, ty in self.members.items():
            v = SimMemView(ty=ty, addr=addr, state=state)
            if concrete:
                values[name] = v.concrete
            else:
                values[name] = v.resolved

        return SimUnionValue(self, values=values)

    def __repr__(self):
        # use the str instead of repr of each member to avoid exceed recursion
        # depth when representing self-referential unions
        return 'union %s {\n\t%s\n}' % (self.name, '\n\t'.join('%s %s;' % (name, str(ty)) for name, ty in self.members.items()))

    def c_repr(self, name=None, full=0, memo=None, indent=0):
        if not full or (memo is not None and self in memo):
            return super().c_repr(name, full, memo, indent)

        indented = ' ' * indent if indent is not None else ''
        new_indent = indent + 4 if indent is not None else None
        new_indented = ' ' * new_indent if indent is not None else ''
        newline = '\n' if indent is not None else ' '
        new_memo = (self,) + (memo if memo is not None else ())
        members = newline.join(new_indented + v.c_repr(k, full-1, new_memo, new_indent) + ';' for k, v in self.members.items())
        return 'union %s {%s%s%s%s}%s' % (self.name, newline, members, newline, indented, '' if name is None else ' ' + name)

    def _init_str(self):
        return "%s({%s}, name=\"%s\", label=\"%s\")" % (
            self.__class__.__name__,
            ", ".join([self._field_str(f, ty) for f, ty in self.members.items()]),
            self._name,
            self.label,
        )

    @staticmethod
    def _field_str(field_name, field_type):
        return "\"%s\": %s" % (field_name, field_type._init_str())

    def __str__(self):
        return 'union %s' % (self.name, )

    def _with_arch(self, arch):
        out = SimUnion({name: ty.with_arch(arch) for name, ty in self.members.items()}, self.label)
        out._arch = arch
        return out

    def copy(self):
        return SimUnion(dict(self.members), name=self.name, label=self.label)

class SimUnionValue:
    """
    A SimStruct type paired with some real values
    """
    def __init__(self, union, values=None):
        """
        :param union:      A SimUnion instance describing the type of this union
        :param values:      A mapping from union members to values
        """
        self._union = union
        self._values = defaultdict(lambda: None, values or ())

    def __indented_repr__(self, indent=0):
        fields = []
        for name, value in self._values.items():
            try:
                f = getattr(value, '__indented_repr__')
                s = f(indent=indent+2)
            except AttributeError:
                s = repr(value)
            fields.append(' ' * (indent + 2) + '.{} = {}'.format(name, s))

        return '{{\n{}\n{}}}'.format(',\n'.join(fields), ' ' * indent)

    def __repr__(self):
        return self.__indented_repr__()

    def __getattr__(self, k):
        return self[k]

    def __getitem__(self, k):
        if k not in self._values:
            return super().__getitem__(k)
        return self._values[k]

    def copy(self):
        return SimUnionValue(self._union, values=self._values)


class SimCppClass(SimStruct):
    def __init__(self, members: Optional[Dict[str,SimType]]=None,
                 function_members: Optional[Dict[str,SimTypeCppFunction]]=None,
                 vtable_ptrs=None, name: Optional[str]=None, pack: bool=False, align=None):
        super().__init__(members, name=name, pack=pack, align=align)
        # these are actually addresses in the binary
        self.function_members = function_members
        # this should also be added to the fields once we know the offsets of the members of this object
        self.vtable_ptrs = [] if vtable_ptrs is None else vtable_ptrs

    @property
    def members(self):
        return self.fields

    def __repr__(self):
        return 'class %s' % self.name

    def extract(self, state, addr, concrete=False):
        values = {}
        for name, offset in self.offsets.items():
            ty = self.fields[name]
            v = SimMemView(ty=ty, addr=addr+offset, state=state)
            if concrete:
                values[name] = v.concrete
            else:
                values[name] = v.resolved

        return SimCppClassValue(self, values=values)

    def store(self, state, addr, value):
        if type(value) is dict:
            pass
        elif type(value) is SimCppClassValue:
            value = value._values
        else:
            raise TypeError("Can't store struct of type %s" % type(value))

        if len(value) != len(self.fields):
            raise ValueError("Passed bad values for %s; expected %d, got %d" % (self, len(self.offsets), len(value)))

        for field, offset in self.offsets.items():
            ty = self.fields[field]
            ty.store(state, addr + offset, value[field])

    def copy(self):
        return SimCppClass(dict(self.fields), name=self.name, pack=self._pack, align=self._align,
                           function_members=self.function_members, vtable_ptrs=self.vtable_ptrs)


class SimCppClassValue:
    """
    A SimCppClass type paired with some real values
    """
    def __init__(self, class_type, values):
        self._class = class_type
        self._values = defaultdict(lambda: None, values or ())

    def __indented_repr__(self, indent=0):
        fields = []
        for name in self._class.fields:
            value = self._values[name]
            try:
                f = getattr(value, '__indented_repr__')
                s = f(indent=indent+2)
            except AttributeError:
                s = repr(value)
            fields.append(' ' * (indent + 2) + '.{} = {}'.format(name, s))

        return '{{\n{}\n{}}}'.format(',\n'.join(fields), ' ' * indent)

    def __repr__(self):
        return self.__indented_repr__()

    def __getattr__(self, k):
        return self[k]

    def __getitem__(self, k):
        if type(k) is int:
            k = self._class.fields[k]
        if k not in self._values:
            for f in self._class.fields:
                if isinstance(f, NamedTypeMixin) and f.name is None:
                    try:
                        return f[k]
                    except:
                        continue
            else:
                return self._values[k]

        return self._values[k]

    def copy(self):
        return SimCppClassValue(self._class, values=defaultdict(lambda: None, self._values))


class SimTypeNumOffset(SimTypeNum):
    """
    like SimTypeNum, but supports an offset of 1 to 7 to a byte aligned address to allow structs with bitfields
    """
    _fields = SimTypeNum._fields + ("offset",)

    def __init__(self, size, signed=True, label=None, offset=0):
        super().__init__(size, signed, label)
        self.offset = offset

    def __repr__(self):
        return super().__repr__()

    def extract(self, state: "SimState", addr, concrete=False):
        if state.arch.memory_endness != Endness.LE:
            raise NotImplementedError("This has only been implemented and tested with Little Endian arches so far")
        minimum_load_size = self.offset + self.size # because we start from a byte aligned offset _before_ the value
        # Now round up to the next byte
        load_size = (minimum_load_size - minimum_load_size % (-state.arch.byte_width)) // state.arch.byte_width
        out = state.memory.load(addr, size=load_size, endness=state.arch.memory_endness)
        out = out[self.offset + self.size - 1:self.offset]

        if not concrete:
            return out
        n = state.solver.eval(out)
        if self.signed and n >= 1 << (self.size - 1):
            n -= 1 << (self.size)
        return n

    def store(self, state, addr, value):
        raise NotImplementedError()

    def copy(self):
        return SimTypeNumOffset(self.size, signed=self.signed, label=self.label, offset=self.offset)


BASIC_TYPES = {
    'char': SimTypeChar(),
    'signed char': SimTypeChar(),
    'unsigned char': SimTypeChar(signed=False),

    'short': SimTypeShort(True),
    'signed short': SimTypeShort(True),
    'unsigned short': SimTypeShort(False),
    'short int': SimTypeShort(True),
    'signed short int': SimTypeShort(True),
    'unsigned short int': SimTypeShort(False),

    'int': SimTypeInt(True),
    'signed': SimTypeInt(True),
    'unsigned': SimTypeInt(False),
    'signed int': SimTypeInt(True),
    'unsigned int': SimTypeInt(False),

    'long': SimTypeLong(True),
    'signed long': SimTypeLong(True),
    'long signed': SimTypeLong(True),
    'unsigned long': SimTypeLong(False),
    'long int': SimTypeLong(True),
    'signed long int': SimTypeLong(True),
    'unsigned long int': SimTypeLong(False),
    'long unsigned int': SimTypeLong(False),

    'long long': SimTypeLongLong(True),
    'signed long long': SimTypeLongLong(True),
    'unsigned long long': SimTypeLongLong(False),
    'long long int': SimTypeLongLong(True),
    'signed long long int': SimTypeLongLong(True),
    'unsigned long long int': SimTypeLongLong(False),

    '__int128': SimTypeNum(128, True),
    'unsigned __int128': SimTypeNum(128, False),
    '__int256': SimTypeNum(256, True),
    'unsigned __int256': SimTypeNum(256, False),

    'bool': SimTypeBool(),
    '_Bool': SimTypeBool(),

    'float': SimTypeFloat(),
    'double': SimTypeDouble(),
    'long double': SimTypeDouble(),
    'void': SimTypeBottom(label="void"),
}

ALL_TYPES = {
    'int8_t': SimTypeNum(8, True),
    'uint8_t': SimTypeNum(8, False),
    'byte': SimTypeNum(8, False),

    'int16_t': SimTypeNum(16, True),
    'uint16_t': SimTypeNum(16, False),
    'word': SimTypeNum(16, False),

    'int32_t': SimTypeNum(32, True),
    'uint32_t': SimTypeNum(32, False),
    'dword': SimTypeNum(32, False),

    'int64_t': SimTypeNum(64, True),
    'uint64_t': SimTypeNum(64, False),
    'qword': SimTypeNum(64, False),

    'ptrdiff_t': SimTypeLong(True),
    'size_t': SimTypeLength(False),
    'ssize_t': SimTypeLength(True),
    'ssize': SimTypeLength(False),
    'uintptr_t': SimTypeLong(False),

    'string': SimTypeString(),
    'wstring': SimTypeWString(),

    'va_list': SimStruct({}, name='va_list'),

    # C++-specific
    'basic_string': SimTypeString(),
    'CharT': SimTypeChar(),
}


ALL_TYPES.update(BASIC_TYPES)


def _make_scope(predefined_types=None):
    """
    Generate CParser scope_stack argument to parse method
    """
    all_types = ChainMap(predefined_types or {}, ALL_TYPES)
    scope = dict()
    for ty in all_types:
        if ty in BASIC_TYPES:
            continue
        if ' ' in ty:
            continue

        typ = all_types[ty]
        if type(typ) is TypeRef:
            typ = typ.type
        if isinstance(typ, (SimTypeFunction,SimTypeString, SimTypeWString)):
            continue

        scope[ty] = True
    return [scope]


@deprecated(replacement="register_types(parse_type(struct_expr))")
def define_struct(defn):
    """
    Register a struct definition globally

    >>> define_struct('struct abcd {int x; int y;}')
    """
    struct = parse_type(defn)
    ALL_TYPES[struct.name] = struct
    ALL_TYPES['struct ' + struct.name] = struct
    return struct


def register_types(types):
    """
    Pass in some types and they will be registered to the global type store.

    The argument may be either a mapping from name to SimType, or a plain SimType.
    The plain SimType must be either a struct or union type with a name present.

    >>> register_types(parse_types("typedef int x; typedef float y;"))
    >>> register_types(parse_type("struct abcd { int ab; float cd; }"))
    """
    if type(types) is SimStruct:
        if types.name == '<anon>':
            raise ValueError("Cannot register anonymous struct")
        ALL_TYPES['struct ' + types.name] = types
    elif type(types) is SimUnion:
        if types.name == '<anon>':
            raise ValueError("Cannot register anonymous union")
        ALL_TYPES['union ' + types.name] = types
    else:
        ALL_TYPES.update(types)


def do_preprocess(defn, include_path=()):
    """
    Run a string through the C preprocessor that ships with pycparser but is weirdly inaccessible?
    """
    from pycparser.ply import lex, cpp  # pylint:disable=import-outside-toplevel
    lexer = lex.lex(cpp)
    p = cpp.Preprocessor(lexer)
    for included in include_path:
        p.add_path(included)
    p.parse(defn)
    return ''.join(tok.value for tok in p.parser if tok.type not in p.ignore)


def parse_signature(defn, preprocess=True, predefined_types=None, arch=None):
    """
    Parse a single function prototype and return its type
    """
    try:
        parsed = parse_file(
            defn.strip(' \n\t;') + ';',
            preprocess=preprocess,
            predefined_types=predefined_types,
            arch=arch
        )
        return next(iter(parsed[0].values()))
    except StopIteration as e:
        raise ValueError("No declarations found") from e


def parse_defns(defn, preprocess=True, predefined_types=None, arch=None):
    """
    Parse a series of C definitions, returns a mapping from variable name to variable type object
    """
    return parse_file(defn, preprocess=preprocess, predefined_types=predefined_types, arch=arch)[0]


def parse_types(defn, preprocess=True, predefined_types=None, arch=None):
    """
    Parse a series of C definitions, returns a mapping from type name to type object
    """
    return parse_file(defn, preprocess=preprocess, predefined_types=predefined_types, arch=arch)[1]


_include_re = re.compile(r'^\s*#include')
def parse_file(defn, preprocess=True, predefined_types: Optional[Dict[Any,SimType]]=None, arch=None):
    """
    Parse a series of C definitions, returns a tuple of two type mappings, one for variable
    definitions and one for type definitions.
    """
    if pycparser is None:
        raise ImportError("Please install pycparser in order to parse C definitions")

    defn = '\n'.join(x for x in defn.split('\n') if _include_re.match(x) is None)

    if preprocess:
        defn = do_preprocess(defn)

    node = pycparser.c_parser.CParser().parse(defn, scope_stack=_make_scope(predefined_types))
    if not isinstance(node, pycparser.c_ast.FileAST):
        raise ValueError("Something went horribly wrong using pycparser")
    out = {}
    extra_types = {}

    # populate extra_types
    if predefined_types:
        extra_types = dict(predefined_types)

    for piece in node.ext:
        if isinstance(piece, pycparser.c_ast.FuncDef):
            out[piece.decl.name] = _decl_to_type(piece.decl.type, extra_types, arch=arch)
        elif isinstance(piece, pycparser.c_ast.Decl):
            ty = _decl_to_type(piece.type, extra_types, arch=arch)
            if piece.name is not None:
                out[piece.name] = ty

            # Don't forget to update typedef types
            if (isinstance(ty, SimStruct) or isinstance(ty, SimUnion)) and ty.name != '<anon>':
                for _, i in extra_types.items():
                    if type(i) is type(ty) and i.name == ty.name:
                        if isinstance(ty, SimStruct):
                            i.fields = ty.fields
                        else:
                            i.members = ty.members

        elif isinstance(piece, pycparser.c_ast.Typedef):
            extra_types[piece.name] = copy.copy(_decl_to_type(piece.type, extra_types, arch=arch))
            extra_types[piece.name].label = piece.name

    return out, extra_types

if pycparser is not None:
    _type_parser_singleton = pycparser.CParser()
    _type_parser_singleton.cparser = pycparser.ply.yacc.yacc(module=_type_parser_singleton,
                                                             start='parameter_declaration',
                                                             debug=False,
                                                             optimize=False,
                                                             errorlog=errorlog)

def parse_type(defn, preprocess=True, predefined_types=None, arch=None):  # pylint:disable=unused-argument
    """
    Parse a simple type expression into a SimType

    >>> parse_type('int *')
    """
    return parse_type_with_name(defn, preprocess=preprocess, predefined_types=predefined_types, arch=arch)[0]

def parse_type_with_name(defn, preprocess=True, predefined_types:Optional[Dict[Any,SimType]]=None, arch=None):  # pylint:disable=unused-argument
    """
    Parse a simple type expression into a SimType, returning the a tuple of the type object and any associated name
    that might be found in the place a name would go in a type declaration.

    >>> parse_type_with_name('int *foo')
    """
    if pycparser is None:
        raise ImportError("Please install pycparser in order to parse C definitions")

    if preprocess:
        defn = re.sub(r"/\*.*?\*/", r"", defn)

    node = _type_parser_singleton.parse(text=defn, scope_stack=_make_scope(predefined_types))
    if not isinstance(node, pycparser.c_ast.Typename) and \
            not isinstance(node, pycparser.c_ast.Decl):
        raise pycparser.c_parser.ParseError("Got an unexpected type out of pycparser")

    decl = node.type
    extra_types = { } if not predefined_types else dict(predefined_types)
    return _decl_to_type(decl, extra_types=extra_types, arch=arch), node.name

def _accepts_scope_stack():
    """
    pycparser hack to include scope_stack as parameter in CParser parse method
    """
    def parse(self,text, filename='', debug=False, scope_stack=None):
        self.clex.filename = filename
        self.clex.reset_lineno()
        self._scope_stack = [dict()] if scope_stack is None else scope_stack
        self._last_yielded_token = None
        return self.cparser.parse(
            input=text,
            lexer=self.clex,
            debug=debug)
    setattr(pycparser.CParser, 'parse', parse)


def _decl_to_type(decl, extra_types=None, bitsize=None, arch=None) -> SimType:
    if extra_types is None: extra_types = {}

    if isinstance(decl, pycparser.c_ast.FuncDecl):
        argtyps = () if decl.args is None else [... if type(x) is pycparser.c_ast.EllipsisParam else \
                                                SimTypeBottom().with_arch(arch) if type(x) is pycparser.c_ast.ID else \
                                                _decl_to_type(x.type, extra_types, arch=arch) for x in decl.args.params]
        arg_names = [ arg.name for arg in decl.args.params if type(arg) is not pycparser.c_ast.EllipsisParam] if decl.args else None
        # special handling: func(void) is func()
        if len(argtyps) == 1 and isinstance(argtyps[0], SimTypeBottom) and arg_names[0] is None:
            argtyps = ()
            arg_names = None
        if argtyps and argtyps[-1] is ...:
            argtyps.pop()
            variadic = True
        else:
            variadic = False
        r = SimTypeFunction(argtyps, _decl_to_type(decl.type, extra_types, arch=arch), arg_names=arg_names, variadic=variadic)
        r._arch = arch
        return r

    elif isinstance(decl, pycparser.c_ast.TypeDecl):
        if decl.declname == 'TOP':
            r = SimTypeTop()
            r._arch = arch
            return r
        return _decl_to_type(decl.type, extra_types, bitsize=bitsize, arch=arch)

    elif isinstance(decl, pycparser.c_ast.PtrDecl):
        pts_to = _decl_to_type(decl.type, extra_types, arch=arch)
        r = SimTypePointer(pts_to)
        r._arch = arch
        return r

    elif isinstance(decl, pycparser.c_ast.ArrayDecl):
        elem_type = _decl_to_type(decl.type, extra_types, arch=arch)

        if decl.dim is None:
            r = SimTypeArray(elem_type)
            r._arch = arch
            return r
        try:
            size = _parse_const(decl.dim, extra_types=extra_types, arch=arch)
        except ValueError as e:
            l.warning("Got error parsing array dimension, defaulting to zero: %s", e)
            size = 0
        r = SimTypeFixedSizeArray(elem_type, size)
        r._arch = arch
        return r

    elif isinstance(decl, pycparser.c_ast.Struct):
        if decl.decls is not None:
            fields = OrderedDict((field.name, _decl_to_type(field.type, extra_types, bitsize=field.bitsize, arch=arch)) for field in decl.decls)
        else:
            fields = OrderedDict()

        # Don't forget that "type[]" has a different meaning in structures than in functions
        if len(fields) > 0 and isinstance(fields[next(reversed(fields))], SimTypeArray):
            raise NotImplementedError("Sorry, we have no support of flexible array members")

        if decl.name is not None:
            key = 'struct ' + decl.name
            struct = extra_types.get(key, None)
            if struct is None:
                struct = ALL_TYPES.get(key, None)
                if struct is not None:
                    struct = struct.with_arch(arch)

            if struct is None:
                struct = SimStruct(fields, decl.name)
                struct._arch = arch
            elif not struct.fields:
                struct.fields = fields
            elif fields and struct.fields != fields:
                raise ValueError("Redefining body of " + key)

            extra_types[key] = struct
        else:
            struct = SimStruct(fields)
            struct._arch = arch
        return struct

    elif isinstance(decl, pycparser.c_ast.Union):
        if decl.decls is not None:
            fields = {field.name: _decl_to_type(field.type, extra_types, arch=arch) for field in decl.decls}
        else:
            fields = {}

        if decl.name is not None:
            key = 'union ' + decl.name
            if key in extra_types:
                union = extra_types[key]
            elif key in ALL_TYPES:
                union = ALL_TYPES[key]
            else:
                union = None

            if union is None:
                union = SimUnion(fields, decl.name)
                union._arch = arch
            elif not union.members:
                union.members = fields
            elif fields and union.members != fields:
                raise ValueError("Redefining body of " + key)

            extra_types[key] = union
        else:
            union = SimUnion(fields)
            union._arch = arch
        return union

    elif isinstance(decl, pycparser.c_ast.IdentifierType):
        key = ' '.join(decl.names)
        if bitsize is not None:
            return SimTypeNumOffset(int(bitsize.value), signed=False)
        elif key in extra_types:
            return extra_types[key]
        elif key in ALL_TYPES:
            return ALL_TYPES[key].with_arch(arch)
        else:
            raise TypeError("Unknown type '%s'" % key)

    elif isinstance(decl, pycparser.c_ast.Enum):
        # See C99 at 6.7.2.2
        return ALL_TYPES['int'].with_arch(arch)

    raise ValueError("Unknown type!")


def _parse_const(c, arch=None, extra_types=None):
    if type(c) is pycparser.c_ast.Constant:
        return int(c.value, base=0)
    elif type(c) is pycparser.c_ast.BinaryOp:
        if c.op == '+':
            return _parse_const(c.children()[0][1], arch, extra_types) + _parse_const(c.children()[1][1], arch, extra_types)
        if c.op == '-':
            return _parse_const(c.children()[0][1], arch, extra_types) - _parse_const(c.children()[1][1], arch, extra_types)
        if c.op == '*':
            return _parse_const(c.children()[0][1], arch, extra_types) * _parse_const(c.children()[1][1], arch, extra_types)
        if c.op == '/':
            return _parse_const(c.children()[0][1], arch, extra_types) // _parse_const(c.children()[1][1], arch, extra_types)
        if c.op == '<<':
            return _parse_const(c.children()[0][1], arch, extra_types) << _parse_const(c.children()[1][1], arch, extra_types)
        if c.op == '>>':
            return _parse_const(c.children()[0][1], arch, extra_types) >> _parse_const(c.children()[1][1], arch, extra_types)
        raise ValueError('Binary op %s' % c.op)
    elif type(c) is pycparser.c_ast.UnaryOp:
        if c.op == 'sizeof':
            return _decl_to_type(c.expr.type, extra_types=extra_types, arch=arch).size
        else:
            raise ValueError("Unary op %s" % c.op)
    elif type(c) is pycparser.c_ast.Cast:
        return _parse_const(c.expr, arch, extra_types)
    else:
        raise ValueError(c)


def _cpp_decl_to_type(decl: Any, extra_types: Dict[str,SimType], opaque_classes=True):
    if isinstance(decl, CppHeaderParser.CppMethod):
        the_func = decl
        func_name = the_func['name']
        if "__deleting_dtor__" in func_name:
            the_func['destructor'] = True
        elif "__base_dtor__" in func_name:
            the_func['destructor'] = True
        elif "__dtor__" in func_name:
            the_func['destructor'] = True
        # translate parameters
        args = [ ]
        arg_names: List[str] = [ ]
        for param in the_func['parameters']:
            arg_type = param['type']
            args.append(_cpp_decl_to_type(arg_type, extra_types, opaque_classes=opaque_classes))
            arg_name = param['name']
            arg_names.append(arg_name)

        args = tuple(args)
        arg_names: Tuple[str] = tuple(arg_names)
        # returns
        if not the_func['returns'].strip():
            returnty = SimTypeBottom()
        else:
            returnty = _cpp_decl_to_type(the_func['returns'].strip(), extra_types, opaque_classes=opaque_classes)
        # other properties
        ctor = the_func['constructor']
        dtor = the_func['destructor']
        func = SimTypeCppFunction(args, returnty, arg_names=arg_names, ctor=ctor, dtor=dtor)
        return func

    elif isinstance(decl, str):
        # a string that represents type
        if decl.endswith("&"):
            # reference
            subdecl = decl.rstrip("&").strip()
            subt = _cpp_decl_to_type(subdecl, extra_types, opaque_classes=opaque_classes)
            t = SimTypeReference(subt)
            return t

        if decl.endswith(" const"):
            # drop const
            return _cpp_decl_to_type(decl[:-6].strip(), extra_types, opaque_classes=opaque_classes)

        if "::" in decl:
            unqualified_name = decl.split("::")[-1]
        else:
            unqualified_name = decl

        key = unqualified_name
        if key in extra_types:
            t = extra_types[key]
        elif key in ALL_TYPES:
            t = ALL_TYPES[key]
        elif opaque_classes is True:
            # create a class without knowing the internal members
            t = SimCppClass({}, name=decl)
        else:
            raise TypeError("Unknown type '%s'" % ' '.join(key))

        if unqualified_name != decl:
            t = t.copy()
            t.name = decl
        return t

    raise NotImplementedError()


def normalize_cpp_function_name(name: str) -> str:
    _s = name
    s = None
    while s != _s:
        _s = s if s is not None else _s
        s = re.sub(r"<[^<>]+>", "", _s)

    m = re.search(r"{([a-z\s]+)}", s)
    if m is not None:
        s = s[:m.start()] + "__" + m.group(1).replace(" ", "_") + "__" + s[m.end():]
    return s


def parse_cpp_file(cpp_decl, with_param_names: bool=False):
    #
    # A series of hacks to make CppHeaderParser happy with whatever C++ function prototypes we feed in
    #

    if CppHeaderParser is None:
        raise ImportError("Please install CppHeaderParser to parse C++ definitions")

    # CppHeaderParser does not support specialization
    s = normalize_cpp_function_name(cpp_decl)

    # CppHeaderParser does not like missing parameter names
    # FIXME: The following logic is only dealing with *one* C++ function declaration. Support multiple declarations
    # FIXME: when needed in the future.
    if not with_param_names:
        last_pos = 0
        i = 0
        while True:
            idx = s.find(",", last_pos)
            if idx == -1:
                break
            arg_name = "a%d" % i
            i += 1
            s = s[:idx] + " " + arg_name + s[idx:]
            last_pos = idx + len(arg_name) + 1 + 1

        # the last parameter
        idx = s.find(")", last_pos)
        if idx != -1:
            # TODO: consider the case where there are one or multiple spaces between ( and )
            if s[idx - 1] != "(":
                arg_name = "a%d" % i
                s = s[:idx] + " " + arg_name + s[idx:]

    # CppHeaderParser does not like missing function body
    s += "\n\n{}"

    try:
        h = CppHeaderParser.CppHeader(s, argType="string")
    except CppHeaderParser.CppParseError:
        return None, None
    if not h.functions:
        return None, None

    func_decls: Dict[str,SimTypeCppFunction] = { }
    for the_func in h.functions:
        # FIXME: We always assume that there is a "this" pointer but it is not the case for static methods.
        proto: Optional[SimTypeCppFunction] = _cpp_decl_to_type(the_func, {}, opaque_classes=True)
        if proto is not None and the_func['class']:
            func_name = the_func['class'] + "::" + the_func['name']
            proto.args = (SimTypePointer(pts_to=SimTypeBottom(label="void")),) + proto.args  # pylint:disable=attribute-defined-outside-init
            proto.arg_names = ("this",) + proto.arg_names  # pylint:disable=attribute-defined-outside-init
        else:
            func_name = the_func['name']
        func_decls[func_name] = proto

    return func_decls, { }


if pycparser is not None:
    _accepts_scope_stack()

try:
    register_types(parse_types("""
typedef long time_t;

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};

struct timeval {
    time_t tv_sec;
    long tv_usec;
};
"""))
except ImportError:
    pass

from .state_plugins.view import SimMemView
from .state_plugins import SimState

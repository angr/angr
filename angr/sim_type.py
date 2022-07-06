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
        return max(val.alignment if val.alignment is not NotImplemented else 1 for val in self.fields.values())

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

ALL_TYPES = {}
BASIC_TYPES = {
    "char": SimTypeChar(),
    "signed char": SimTypeChar(),
    "unsigned char": SimTypeChar(signed=False),
    "short": SimTypeShort(True),
    "signed short": SimTypeShort(True),
    "unsigned short": SimTypeShort(False),
    "short int": SimTypeShort(True),
    "signed short int": SimTypeShort(True),
    "unsigned short int": SimTypeShort(False),
    "int": SimTypeInt(True),
    "signed": SimTypeInt(True),
    "unsigned": SimTypeInt(False),
    "signed int": SimTypeInt(True),
    "unsigned int": SimTypeInt(False),
    "long": SimTypeLong(True),
    "signed long": SimTypeLong(True),
    "long signed": SimTypeLong(True),
    "unsigned long": SimTypeLong(False),
    "long int": SimTypeLong(True),
    "signed long int": SimTypeLong(True),
    "unsigned long int": SimTypeLong(False),
    "long unsigned int": SimTypeLong(False),
    "long long": SimTypeLongLong(True),
    "signed long long": SimTypeLongLong(True),
    "unsigned long long": SimTypeLongLong(False),
    "long long int": SimTypeLongLong(True),
    "signed long long int": SimTypeLongLong(True),
    "unsigned long long int": SimTypeLongLong(False),
    "__int128": SimTypeNum(128, True),
    "unsigned __int128": SimTypeNum(128, False),
    "__int256": SimTypeNum(256, True),
    "unsigned __int256": SimTypeNum(256, False),
    "bool": SimTypeBool(),
    "_Bool": SimTypeBool(),
    "float": SimTypeFloat(),
    "double": SimTypeDouble(),
    "long double": SimTypeDouble(),
    "void": SimTypeBottom(label="void"),
}
ALL_TYPES.update(BASIC_TYPES)

STDINT_TYPES = {
    "int8_t": SimTypeNum(8, True),
    "uint8_t": SimTypeNum(8, False),
    "byte": SimTypeNum(8, False),
    "int16_t": SimTypeNum(16, True),
    "uint16_t": SimTypeNum(16, False),
    "word": SimTypeNum(16, False),
    "int32_t": SimTypeNum(32, True),
    "uint32_t": SimTypeNum(32, False),
    "dword": SimTypeNum(32, False),
    "int64_t": SimTypeNum(64, True),
    "uint64_t": SimTypeNum(64, False),
    "qword": SimTypeNum(64, False),
    "ptrdiff_t": SimTypeLong(True),
    "size_t": SimTypeLength(False),
    "ssize_t": SimTypeLength(True),
    "ssize": SimTypeLength(False),
    "uintptr_t": SimTypeLong(False),
    "wchar_t": SimTypeShort(True),
}
ALL_TYPES.update(STDINT_TYPES)

# Most glibc internal basic types are defined in the following two files:
# https://github.com/bminor/glibc/blob/master/bits/typesizes.h
# https://github.com/bminor/glibc/blob/master/posix/bits/types.h
# Anything that is defined in a different file should probably have a permalink

GLIBC_INTERNAL_BASIC_TYPES = {
    "__off_t": ALL_TYPES["long int"],
    "__off64_t": ALL_TYPES["long long int"],
    "__pid_t": ALL_TYPES["int"],
    "__ino_t": ALL_TYPES["unsigned long int"],
    "__ino64_t": ALL_TYPES["unsigned long long int"],
    "__mode_t": ALL_TYPES["unsigned int"],
    "__dev_t": ALL_TYPES["uint64_t"],
    "__nlink_t": ALL_TYPES["unsigned int"],
    "__uid_t": ALL_TYPES["unsigned int"],
    "__gid_t": ALL_TYPES["unsigned int"],
    "__time_t": ALL_TYPES["long int"],
    # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/sysdeps/unix/sysv/linux/x86/bits/siginfo-arch.h#L12
    "__clock_t": ALL_TYPES["uint32_t"],
    "__suseconds_t": ALL_TYPES["int64_t"],
}
ALL_TYPES.update(GLIBC_INTERNAL_BASIC_TYPES)

GLIBC_EXTERNAL_BASIC_TYPES = {
    "off_t": ALL_TYPES["__off_t"],
    "off64_t": ALL_TYPES["__off64_t"],
    "pid_t": ALL_TYPES["__pid_t"],
    # https://www.gnu.org/software/libc/manual/html_node/Attribute-Meanings.html
    # This is "no narrower than unsigned int" but may be wider...
    # TODO: This should be defined based on the architecture
    "ino_t": ALL_TYPES["__ino_t"],
    "ino64_t": ALL_TYPES["__ino64_t"],
    # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/bits/sockaddr.h#L28
    "sa_family_t": ALL_TYPES["unsigned short int"],
    # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/inet/netinet/in.h#L123
    "in_port_t": ALL_TYPES["uint16_t"],
    # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/bits/termios.h#L102
    "tcflag_t": ALL_TYPES["unsigned long int"],
    # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/bits/termios.h#L105
    "cc_t": ALL_TYPES["unsigned char"],
    # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/bits/termios.h#L108
    "speed_t": ALL_TYPES["long int"],
    "clock_t": ALL_TYPES["__clock_t"],
    "rlim_t": ALL_TYPES["unsigned long int"],
    "rlim64_t": ALL_TYPES["uint64_t"],
    # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/bits/types/error_t.h#L22
    "error_t": ALL_TYPES["int"],
}
ALL_TYPES.update(GLIBC_EXTERNAL_BASIC_TYPES)


CXX_TYPES = {
    "string": SimTypeString(),
    "wstring": SimTypeWString(),
    "basic_string": SimTypeString(),
    "CharT": SimTypeChar(),
}
ALL_TYPES.update(CXX_TYPES)


# Note about structs with self/next pointers -- they will be defined as memberless
# name-only structs the same way they would be in C as a forward declaration

# This dictionary is defined in two steps to allow structs that are members of other
# structs to be defined first
GLIBC_INTERNAL_TYPES = {
    "sigval": SimUnion(
        {
            "sival_int": ALL_TYPES["int"],
            "sival_ptr": SimTypePointer(ALL_TYPES["void"], label="void *"),
        },
        name="sigval",
    ),
    "__mbstate_t": SimStruct(
        {
            "__count": ALL_TYPES["int"],
            "__value": SimUnion(
                {
                    "__wch": ALL_TYPES["unsigned int"],
                    "__wchb": SimTypeArray(ALL_TYPES["char"], length=4),
                }
            ),
        },
        name="__mbstate_t",
    ),
    "_IO_codecvt": SimStruct(
        {
            "__cd_in": SimStruct({}, name="_IO_iconv_t"),
            "__cd_out": SimStruct({}, name="_IO_iconv_t"),
        },
        name="_IO_codecvt",
    ),
    "argp_option": SimStruct(
        {
            "name": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "key": ALL_TYPES["int"],
            "arg": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "flags": ALL_TYPES["int"],
            "doc": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "group": ALL_TYPES["int"],
        },
        name="argp_option",
    ),
    "argp_child": SimStruct(
        {
            "argp": SimStruct({}, name="argp"),
            "flags": ALL_TYPES["int"],
            "header": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "group": ALL_TYPES["int"],
        },
        name="argp_child",
    ),
    "argp_parser_t": SimTypeFunction(
        (
            ALL_TYPES["int"],
            SimTypePointer(ALL_TYPES["char"], label="char *"),
            SimTypePointer(SimStruct({}, name="argp_state")),
        ),
        ALL_TYPES["error_t"],
        arg_names=("__key", "__arg", "__state"),
    ),
}


GLIBC_INTERNAL_TYPES.update(
    {
        "_obstack_chunk": SimStruct(
            {
                "limit": SimTypePointer(ALL_TYPES["char"], label="char *"),
                "prev": SimTypePointer(
                    SimStruct({}, name="_obstack_chunk", pack=False, align=None)
                ),
                "contents": SimTypeArray(ALL_TYPES["char"], length=4, label="char"),
            },
            name="_obstack_chunk",
        ),
        # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/misc/search.h#L69
        "_ENTRY": SimStruct(
            {
                "key": SimTypePointer(ALL_TYPES["char"], label="char *"),
                "data": SimTypePointer(ALL_TYPES["void"], label="void *"),
            },
            name="_ENTRY",
        ),
        # https://man7.org/linux/man-pages/man7/sigevent.7.html
        "sigevent": SimStruct(
            {
                "sigev_notify": ALL_TYPES["int"],
                "sigev_signo": ALL_TYPES["int"],
                "sigev_value": GLIBC_INTERNAL_TYPES["sigval"],
                "sigev_notify_function": SimTypeFunction(
                    (GLIBC_INTERNAL_TYPES["sigval"],),
                    SimTypePointer(ALL_TYPES["void"], label="void *"),
                ),
                "sigev_notify_attributes": SimTypePointer(
                    ALL_TYPES["void"], label="void *"
                ),
                "sigev_notify_thread_id": ALL_TYPES["pid_t"],
            },
            name="sigevent",
        ),
        "in_addr": SimStruct({"s_addr": ALL_TYPES["uint32_t"]}, name="in_addr"),
        "_IO_marker": SimStruct(
            {
                "_next": SimTypePointer(
                    SimStruct({}, name="_IO_marker"), label="struct _IO_marker *"
                ),
                "_sbuf": SimTypePointer(SimStruct({}, name="FILE"), label="FILE *"),
                "_pos": ALL_TYPES["int"],
            },
            name="_IO_marker",
        ),
        "_IO_iconv_t": SimStruct(
            {
                # TODO: Define __gconv structs
                "step": SimTypePointer(
                    SimStruct({}, name="__gconv_step"), label="struct __gconv_step *"
                ),
                "step_data": SimStruct({}, name="__gconv_step_data"),
            },
            name="_IO_iconv_t",
        ),
        "_IO_codecvt": GLIBC_INTERNAL_TYPES["_IO_codecvt"],
        "_IO_lock_t": SimStruct({}, name="pthread_mutex_t"),
        "__mbstate_t": GLIBC_INTERNAL_TYPES["__mbstate_t"],
        "_IO_wide_data": SimStruct(
            {
                "_IO_read_ptr": SimTypePointer(ALL_TYPES["wchar_t"], label="wchar_t *"),
                "_IO_read_end": SimTypePointer(ALL_TYPES["wchar_t"], label="wchar_t *"),
                "_IO_read_base": SimTypePointer(
                    ALL_TYPES["wchar_t"], label="wchar_t *"
                ),
                "_IO_write_base": SimTypePointer(
                    ALL_TYPES["wchar_t"], label="wchar_t *"
                ),
                "_IO_write_ptr": SimTypePointer(
                    ALL_TYPES["wchar_t"], label="wchar_t *"
                ),
                "_IO_write_end": SimTypePointer(
                    ALL_TYPES["wchar_t"], label="wchar_t *"
                ),
                "_IO_buf_base": SimTypePointer(ALL_TYPES["wchar_t"], label="wchar_t *"),
                "_IO_buf_end": SimTypePointer(ALL_TYPES["wchar_t"], label="wchar_t *"),
                "_IO_save_base": SimTypePointer(
                    ALL_TYPES["wchar_t"], label="wchar_t *"
                ),
                "_IO_backup_base": SimTypePointer(
                    ALL_TYPES["wchar_t"], label="wchar_t *"
                ),
                "_IO_save_end": SimTypePointer(ALL_TYPES["wchar_t"], label="wchar_t *"),
                "_IO_state": GLIBC_INTERNAL_TYPES["__mbstate_t"],
                "_IO_last_state": GLIBC_INTERNAL_TYPES["__mbstate_t"],
                "_codecvt": GLIBC_INTERNAL_TYPES["_IO_codecvt"],
                "_shortbuf": SimTypeArray(
                    ALL_TYPES["wchar_t"], length=1, label="wchar_t[1]"
                ),
                # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/libio/libioP.h#L293
                "_wide_vtable": SimStruct({}, name="_IO_jump_t"),
            },
            name="_IO_wide_data",
        ),
        "argp": SimStruct(
            {
                "options": SimTypePointer(
                    GLIBC_INTERNAL_TYPES["argp_option"], label="struct argp_option *"
                ),
                "parser": GLIBC_INTERNAL_TYPES["argp_parser_t"],
                "args_doc": SimTypePointer(ALL_TYPES["char"], label="char *"),
                "doc": SimTypePointer(ALL_TYPES["char"], label="char *"),
                "children": SimTypePointer(
                    GLIBC_INTERNAL_TYPES["argp_child"], label="struct argp_child *"
                ),
                "help_filter": SimTypeFunction(
                    (
                        ALL_TYPES["int"],
                        SimTypePointer(ALL_TYPES["char"], label="char *"),
                        SimTypePointer(ALL_TYPES["void"], label="void *"),
                    ),
                    SimTypePointer(ALL_TYPES["char"], label="char *"),
                    arg_names=("__key", "__text", "__input"),
                ),
                "argp_domain": SimTypePointer(ALL_TYPES["char"], label="char *"),
            },
            name="argp",
        ),
        "timeval": SimStruct(
            {
                # TODO: This should be architecture dependent
                "tv_sec": ALL_TYPES["__time_t"],
                "tv_usec": ALL_TYPES["__suseconds_t"],
            },
            name="timeval",
        ),
        # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/time/bits/types/struct_timespec.h#L11
        "timespec": SimStruct(
            {
                # TODO: This should be architecture dependent
                "tv_sec": ALL_TYPES["__time_t"],
                "tv_nsec": ALL_TYPES["long int"],
                # TODO: This should be architecture dependent (byte order)
                "_pad0": ALL_TYPES["uint32_t"],
            },
            name="timeval",
        ),
        # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/bits/utmp.h#L50
        "exit_status": SimStruct(
            {
                "e_termination": ALL_TYPES["short int"],
                "e_exit": ALL_TYPES["short int"],
            },
            name="exit_status",
        ),
    }
)
ALL_TYPES.update(GLIBC_INTERNAL_TYPES)

GLIBC_TYPES = {
    # DO NOT use the glibc manual to define these structs! It is not accurate and does
    # not contain all fields or even the fields in the correct order!. Instead, you
    # need to use the glibc source and actually find the struct. In most cases,
    # a link to the struct is provided.
    # ABI-defined, for x86_64 it can be found here in sec 3.34:
    # https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf
    # TODO: This should be architecture dependent
    "va_list": SimTypeArray(
        SimStruct(
            {
                "gp_offset": ALL_TYPES["unsigned int"],
                "fp_offset": ALL_TYPES["unsigned int"],
                "overflow_arg_area": SimTypePointer(ALL_TYPES["void"], label="void *"),
                "reg_save_area": SimTypePointer(ALL_TYPES["void"], label="void *"),
            },
            name="va_list",
        ),
        length=1,
        label="va_list[1]",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/malloc/malloc.h#L82
    "mallinfo": SimStruct(
        {
            "arena": ALL_TYPES["int"],
            "ordblks": ALL_TYPES["int"],
            "smblks": ALL_TYPES["int"],
            "hblks": ALL_TYPES["int"],
            "hblkhd": ALL_TYPES["int"],
            "usmblks": ALL_TYPES["int"],
            "fsmblks": ALL_TYPES["int"],
            "uordblks": ALL_TYPES["int"],
            "fordblks": ALL_TYPES["int"],
            "keepcost": ALL_TYPES["int"],
        },
        name="mallinfo",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/malloc/malloc.h#L99
    "mallinfo2": SimStruct(
        {
            "arena": ALL_TYPES["size_t"],
            "ordblks": ALL_TYPES["size_t"],
            "smblks": ALL_TYPES["size_t"],
            "hblks": ALL_TYPES["size_t"],
            "hblkhd": ALL_TYPES["size_t"],
            "usmblks": ALL_TYPES["size_t"],
            "fsmblks": ALL_TYPES["size_t"],
            "uordblks": ALL_TYPES["size_t"],
            "fordblks": ALL_TYPES["size_t"],
            "keepcost": ALL_TYPES["size_t"],
        },
        name="mallinfo2",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/malloc/obstack.h#L153
    "obstack": SimStruct(
        {
            "chunk_size": SimTypeLong(signed=True, label="long"),
            "chunk": GLIBC_INTERNAL_TYPES["_obstack_chunk"],
            "object_base": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "next_free": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "chunk_limit": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "temp": SimUnion(
                {
                    "tempint": ALL_TYPES["ptrdiff_t"],
                    "tempptr": SimTypePointer(ALL_TYPES["void"], label="void *"),
                }
            ),
            "alignment_mask": ALL_TYPES["int"],
            "chunkfun": SimTypeFunction(
                (SimTypePointer(ALL_TYPES["void"], label="void *"), ALL_TYPES["long"]),
                SimTypePointer(
                    ALL_TYPES["_obstack_chunk"], label="struct _obstack_chunk *"
                ),
            ),
            "freefun": SimTypeFunction(
                (
                    SimTypePointer(ALL_TYPES["void"], label="void *"),
                    SimTypePointer(
                        ALL_TYPES["_obstack_chunk"], label="_obstack_chunk *"
                    ),
                ),
                ALL_TYPES["void"],
            ),
            "extra_arg": SimTypePointer(ALL_TYPES["void"], label="void *"),
            "use_extra_arg": SimTypeNumOffset(1, signed=False, label="unsigned"),
            "maybe_extra_object": SimTypeNumOffset(1, signed=False, label="unsigned"),
            "alloc_failed": SimTypeNumOffset(1, signed=False, label="unsigned"),
        },
        name="obstack",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/locale/locale.h#L51
    "lconv": SimStruct(
        {
            "decimal_point": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "thousands_sep": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "grouping": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "int_curr_symbol": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "currency_symbol": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "mon_decimal_point": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "mon_thousands_sep": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "mon_grouping": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "positive_sign": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "negative_sign": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "int_frac_digits": ALL_TYPES["char"],
            "frac_digits": ALL_TYPES["char"],
            "p_cs_precedes": ALL_TYPES["char"],
            "p_sep_by_space": ALL_TYPES["char"],
            "n_cs_precedes": ALL_TYPES["char"],
            "n_sep_by_space": ALL_TYPES["char"],
            "p_sign_posn": ALL_TYPES["char"],
            "n_sign_posn": ALL_TYPES["char"],
            "int_p_cs_precedes": ALL_TYPES["char"],
            "int_p_sep_by_space": ALL_TYPES["char"],
            "int_n_cs_precedes": ALL_TYPES["char"],
            "int_n_sep_by_space": ALL_TYPES["char"],
            "int_p_sign_posn": ALL_TYPES["char"],
            "int_n_sign_posn": ALL_TYPES["char"],
        },
        name="lconv",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/misc/search.h#L97
    "hsearch_data": SimStruct(
        {
            "table": SimTypePointer(ALL_TYPES["_ENTRY"], label="struct _ENTRY *"),
            "size": ALL_TYPES["unsigned int"],
            "filled": ALL_TYPES["unsigned int"],
        },
        name="hsearch_data",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/libio/bits/types/struct_FILE.h#L49
    "FILE_t": SimStruct(
        {
            "_flags": ALL_TYPES["int"],
            "_IO_read_ptr": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_read_end": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_read_base": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_write_base": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_write_ptr": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_write_end": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_buf_base": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_buf_end": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_save_base": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_backup_base": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_IO_save_end": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "_markers": SimTypePointer(ALL_TYPES["_IO_marker"]),
            "_chain": SimTypePointer(
                SimStruct({}, name="_IO_FILE"), label="struct _IO_FILE *"
            ),
            "_fileno": ALL_TYPES["int"],
            "_flags2": ALL_TYPES["int"],
            "_old_offset": ALL_TYPES["__off_t"],
            "_cur_column": ALL_TYPES["unsigned short"],
            "_vtable_offset": ALL_TYPES["signed char"],
            "_shortbuf": SimTypeArray(ALL_TYPES["char"], length=1, label="char[1]"),
            "_lock": SimTypePointer(ALL_TYPES["_IO_lock_t"]),
            "_offset": ALL_TYPES["__off64_t"],
            "_codecvt": SimTypePointer(
                ALL_TYPES["_IO_codecvt"], label="struct _IO_codecvt *"
            ),
            "_wide_data": SimTypePointer(
                ALL_TYPES["_IO_wide_data"], label="struct _IO_wide_data *"
            ),
            "_freeres_list": SimTypePointer(
                SimStruct({}, name="_IO_FILE"), label="struct _IO_FILE *"
            ),
            "__pad5": ALL_TYPES["size_t"],
            "_mode": ALL_TYPES["int"],
            "_unused2": SimTypeArray(
                ALL_TYPES["char"],
                length=20,
                label="char[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)]",
            ),
        },
        name="FILE_t",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/stdio-common/printf.h#L34
    "printf_info": SimStruct(
        {
            "prec": ALL_TYPES["int"],
            "width": ALL_TYPES["int"],
            "spec": ALL_TYPES["wchar_t"],
            "is_long_double": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "is_short": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "is_long": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "alt": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "space": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "left": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "showsign": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "group": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "extra": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "is_char": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "wide": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "i18n": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "is_binary128": SimTypeNumOffset(1, signed=False, label="unsigned int"),
            "__pad": SimTypeNumOffset(3, signed=False, label="unsigned int"),
            "user": ALL_TYPES["unsigned short int"],
            "pad": ALL_TYPES["wchar_t"],
        },
        name="printf_info",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/rt/aio.h#L34
    "aiocb": SimStruct(
        {
            "aio_filedes": ALL_TYPES["int"],
            "aio_lio_opcode": ALL_TYPES["int"],
            "aio_reqprio": ALL_TYPES["int"],
            "aio_buf": SimTypePointer(ALL_TYPES["void"], label="void *"),
            "aio_nbytes": ALL_TYPES["size_t"],
            "aio_sigevent": ALL_TYPES["sigevent"],
            "__next_prio": SimTypePointer(
                SimStruct({}, name="aiocb"), label="struct aiocb *"
            ),
            "__abs_prio": ALL_TYPES["int"],
            "__policy": ALL_TYPES["int"],
            "__error_code": ALL_TYPES["int"],
            "__return_value": ALL_TYPES["ssize_t"],
            # TODO: This should be architecture dependent
            "aio_offset": ALL_TYPES["off_t"],
            "__glibc_reserved": SimTypeArray(
                ALL_TYPES["char"], length=32, label="char[32]"
            ),
        },
        name="aiocb",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/rt/aio.h#L62
    "aiocb64": SimStruct(
        {
            "aio_filedes": ALL_TYPES["int"],
            "aio_lio_opcode": ALL_TYPES["int"],
            "aio_reqprio": ALL_TYPES["int"],
            "aio_buf": SimTypePointer(ALL_TYPES["void"], label="void *"),
            "aio_nbytes": ALL_TYPES["size_t"],
            "aio_sigevent": ALL_TYPES["sigevent"],
            "__next_prio": SimTypePointer(
                SimStruct({}, name="aiocb"), label="struct aiocb *"
            ),
            "__abs_prio": ALL_TYPES["int"],
            "__policy": ALL_TYPES["int"],
            "__error_code": ALL_TYPES["int"],
            "__return_value": ALL_TYPES["ssize_t"],
            "aio_offset": ALL_TYPES["off64_t"],
            "__glibc_reserved": SimTypeArray(
                ALL_TYPES["char"], length=32, label="char[32]"
            ),
        },
        name="aiocb64",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/rt/aio.h#L86
    "aioinit": SimStruct(
        {
            "aio_threads": ALL_TYPES["int"],
            "aio_num": ALL_TYPES["int"],
            "aio_locks": ALL_TYPES["int"],
            "aio_debug": ALL_TYPES["int"],
            "aio_numusers": ALL_TYPES["int"],
            "aio_idle_time": ALL_TYPES["int"],
            "aio_reserved": ALL_TYPES["int"],
        },
        name="aioinit",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/dirent.h#L23
    "dirent": SimStruct(
        {
            "d_ino": ALL_TYPES["ino_t"],
            "d_reclen": ALL_TYPES["unsigned short int"],
            "d_type": ALL_TYPES["unsigned char"],
            "d_namelen": ALL_TYPES["unsigned char"],
            "d_name": SimTypeArray(ALL_TYPES["char"], length=1, label="char[1]"),
        },
        name="dirent",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/dirent.h#L39
    "dirent64": SimStruct(
        {
            "d_ino": ALL_TYPES["ino64_t"],
            "d_reclen": ALL_TYPES["unsigned short int"],
            "d_type": ALL_TYPES["unsigned char"],
            "d_namelen": ALL_TYPES["unsigned char"],
            "d_name": SimTypeArray(ALL_TYPES["char"], length=1, label="char[1]"),
        },
        name="dirent64",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/stat.h#L31
    "stat": SimStruct(
        {
            "st_mode": ALL_TYPES["__mode_t"],
            # TODO: This should be architecture dependent
            "st_ino": ALL_TYPES["__ino_t"],
            "st_dev": ALL_TYPES["__dev_t"],
            "st_nlink": ALL_TYPES["__nlink_t"],
            "st_uid": ALL_TYPES["__uid_t"],
            "st_gid": ALL_TYPES["__gid_t"],
            # TODO: This should be architecture dependent
            "st_size": ALL_TYPES["__off_t"],
            "st_atime": ALL_TYPES["__time_t"],
            "st_mtime": ALL_TYPES["__time_t"],
            "st_ctime": ALL_TYPES["__time_t"],
        },
        name="stat",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/stat.h#L86
    "stat64": SimStruct(
        {
            "st_mode": ALL_TYPES["__mode_t"],
            # TODO: This should be architecture dependent
            "st_ino": ALL_TYPES["__ino64_t"],
            "st_dev": ALL_TYPES["__dev_t"],
            "st_nlink": ALL_TYPES["__nlink_t"],
            "st_uid": ALL_TYPES["__uid_t"],
            "st_gid": ALL_TYPES["__gid_t"],
            # TODO: This should be architecture dependent
            "st_size": ALL_TYPES["__off64_t"],
            "st_atime": ALL_TYPES["__time_t"],
            "st_mtime": ALL_TYPES["__time_t"],
            "st_ctime": ALL_TYPES["__time_t"],
        },
        name="stat64",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/io/utime.h#L36
    "utimbuf": SimStruct(
        {
            # TODO: This should be architecture dependent
            "actime": ALL_TYPES["__time_t"],
            "modtime": ALL_TYPES["__time_t"],
        },
        name="utimbuf",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/socket.h#L152
    "sockaddr": SimStruct(
        {
            "sin_family": ALL_TYPES["sa_family_t"],
            "sa_data": SimTypeArray(ALL_TYPES["char"], length=14, label="char[14]"),
        },
        name="sockaddr",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/inet/netinet/in.h#L245
    "sockaddr_in": SimStruct(
        {
            "sin_family": ALL_TYPES["sa_family_t"],
            "sin_port": ALL_TYPES["in_port_t"],
            "sin_addr": ALL_TYPES["in_addr"],
            "sin_zero": SimTypeArray(
                ALL_TYPES["unsigned char"],
                length=8,
                label=(
                    "unsigned char[sizeof (struct sockaddr) - __SOCKADDR_COMMON_SIZE - "
                    "sizeof (in_port_t) - sizeof (struct in_addr)]"
                )
            ),
        },
        name="sockaddr_in",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/sysdeps/gnu/net/if.h#L33
    "if_nameindex": SimStruct(
        {
            "if_index": ALL_TYPES["unsigned int"],
            "if_name": SimTypePointer(ALL_TYPES["char"], label="char *"),
        },
        name="if_nameindex",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/resolv/netdb.h#L98
    "hostent": SimStruct(
        {
            "h_name": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "h_aliases": SimTypePointer(
                SimTypePointer(ALL_TYPES["char"], label="char *"), label="char **"
            ),
            "h_addrtype": ALL_TYPES["int"],
            "h_length": ALL_TYPES["int"],
            "h_addr_list": SimTypePointer(
                SimTypePointer(ALL_TYPES["char"], label="char *"), label="char **"
            ),
        },
        name="hostent",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/resolv/netdb.h#L255
    "servent": SimStruct(
        {
            "s_name": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "s_aliases": SimTypePointer(
                SimTypePointer(ALL_TYPES["char"], label="char *"), label="char **"
            ),
            "s_port": ALL_TYPES["int"],
            "s_proto": SimTypePointer(ALL_TYPES["char"], label="char *"),
        },
        name="servent",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/resolv/netdb.h#L324
    "protoent": SimStruct(
        {
            "p_name": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "p_aliases": SimTypePointer(
                SimTypePointer(ALL_TYPES["char"], label="char *"), label="char **"
            ),
            "p_proto": ALL_TYPES["int"],
        },
        name="protoent",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/netdb.h#L26
    "netent": SimStruct(
        {
            "n_name": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "n_aliases": SimTypePointer(
                SimTypePointer(ALL_TYPES["char"], label="char *"), label="char **"
            ),
            "n_addrtype": ALL_TYPES["int"],
            "n_net": ALL_TYPES["uint32_t"],
        },
        name="netent",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/termios.h#L111
    "termios": SimStruct(
        {
            "c_iflag": ALL_TYPES["tcflag_t"],
            "c_oflag": ALL_TYPES["tcflag_t"],
            "c_cflag": ALL_TYPES["tcflag_t"],
            "c_lflag": ALL_TYPES["tcflag_t"],
            "c_cc": SimTypeArray(ALL_TYPES["cc_t"], length=20, label="cc_t[20]"),
            "__ispeed": ALL_TYPES["speed_t"],
            "__ospeed": ALL_TYPES["speed_t"],
        },
        name="termios",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/ioctl-types.h#L56
    "sgttyb": SimStruct(
        {
            "sg_ispeed": ALL_TYPES["char"],
            "sg_ospeed": ALL_TYPES["char"],
            "sg_erase": ALL_TYPES["char"],
            "sg_kill": ALL_TYPES["char"],
            "sg_flags": ALL_TYPES["short int"],
        },
        name="sgttyb",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/ioctl-types.h#L70
    "winsize": SimStruct(
        {
            "ws_row": ALL_TYPES["unsigned short int"],
            "ws_col": ALL_TYPES["unsigned short int"],
            "ws_xpixel": ALL_TYPES["unsigned short int"],
            "ws_ypixel": ALL_TYPES["unsigned short int"],
        },
        name="winsize",
    ),
    # This type is legitimately opaque
    "random_data": SimStruct({}),
    # This type is also legitimately opaque
    "drand48_data": SimStruct({}),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/posix/sys/times.h#L32
    "tms": SimStruct(
        {
            "tms_utime": ALL_TYPES["clock_t"],
            "tms_stime": ALL_TYPES["clock_t"],
            "tms_cutime": ALL_TYPES["clock_t"],
            "tms_cstime": ALL_TYPES["clock_t"],
        },
        name="tms",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/time/sys/time.h#L52
    "timezone": SimStruct(
        {
            "tz_minuteswest": ALL_TYPES["int"],
            "tz_dsttime": ALL_TYPES["int"],
        },
        name="timezone",
    ),
    "timeval": ALL_TYPES["timeval"],
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/sysdeps/unix/sysv/linux/bits/timex.h#L26
    "timex": SimStruct(
        # TODO: This should be architecture dependent
        {
            "modes": ALL_TYPES["unsigned int"],
            "_pad0": ALL_TYPES["uint32_t"],
            "offset": ALL_TYPES["long long"],
            "freq": ALL_TYPES["long long"],
            "maxerror": ALL_TYPES["long long"],
            "esterror": ALL_TYPES["long long"],
            "status": ALL_TYPES["int"],
            "_pad1": ALL_TYPES["uint32_t"],
            "constant": ALL_TYPES["long long"],
            "precision": ALL_TYPES["long long"],
            "tolerance": ALL_TYPES["long long"],
            "time": ALL_TYPES["timeval"],
            "tick": ALL_TYPES["long long"],
            "ppsfreq": ALL_TYPES["long long"],
            "jitter": ALL_TYPES["long long"],
            "shift": ALL_TYPES["int"],
            "_pad2": ALL_TYPES["uint32_t"],
            "stabil": ALL_TYPES["long long"],
            "jitcnt": ALL_TYPES["long long"],
            "calcnt": ALL_TYPES["long long"],
            "errcnt": ALL_TYPES["long long"],
            "stbcnt": ALL_TYPES["long long"],
            "tai": ALL_TYPES["int"],
            "_pad3": SimTypeArray(
                ALL_TYPES["uint32_t"], length=11, label="int :32[11]"
            ),
        },
        name="timex",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/time/bits/types/struct_tm.h#L7
    "tm": SimStruct(
        {
            "tm_sec": ALL_TYPES["int"],
            "tm_min": ALL_TYPES["int"],
            "tm_hour": ALL_TYPES["int"],
            "tm_mday": ALL_TYPES["int"],
            "tm_mon": ALL_TYPES["int"],
            "tm_year": ALL_TYPES["int"],
            "tm_wday": ALL_TYPES["int"],
            "tm_yday": ALL_TYPES["int"],
            "tm_isdst": ALL_TYPES["int"],
            "tm_gmtoff": ALL_TYPES["long int"],
            "tm_zone": SimTypePointer(ALL_TYPES["char"], label="char *"),
        },
        name="tm",
    ),
    # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/sysdeps/unix/sysv/linux/sys/timex.h#L30
    "ntptimeval": SimStruct(
        {
            "time": ALL_TYPES["timeval"],
            "maxerror": ALL_TYPES["long int"],
            "esterror": ALL_TYPES["long int"],
            "tai": ALL_TYPES["long int"],
            "__glibc_reserved1": ALL_TYPES["long int"],
            "__glibc_reserved2": ALL_TYPES["long int"],
            "__glibc_reserved3": ALL_TYPES["long int"],
            "__glibc_reserved4": ALL_TYPES["long int"],

        },
        name="ntptimeval"
    ),
    # https://github.com/bminor/glibc/blob/a01a13601c95f5d111d25557656d09fe661cfc89/misc/bits/types/struct_iovec.h#L26
    "iovec": SimStruct(
        {
            "iov_base": SimTypePointer(ALL_TYPES["void"], label="void *"),
            "iov_len": ALL_TYPES["size_t"],
        }
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/time/sys/time.h#L130
    "itimerval": SimStruct(
        {
            "it_interval": ALL_TYPES["timeval"],
            "it_value": ALL_TYPES["timeval"],
        },
        name="itimerval",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/resource/bits/types/struct_rusage.h#L33
    "rusage": SimStruct(
        {
            "ru_utime": ALL_TYPES["timeval"],
            "ru_stime": ALL_TYPES["timeval"],
            "ru_maxrss": ALL_TYPES["long int"],
            "ru_ixrss": ALL_TYPES["long int"],
            "ru_idrss": ALL_TYPES["long int"],
            "ru_isrss": ALL_TYPES["long int"],
            "ru_minflt": ALL_TYPES["long int"],
            "ru_majflt": ALL_TYPES["long int"],
            "ru_nswap": ALL_TYPES["long int"],
            "ru_inblock": ALL_TYPES["long int"],
            "ru_oublock": ALL_TYPES["long int"],
            "ru_msgsnd": ALL_TYPES["long int"],
            "ru_msgrcv": ALL_TYPES["long int"],
            "ru_nsignals": ALL_TYPES["long int"],
            "ru_nvcsw": ALL_TYPES["long int"],
            "ru_nivcsw": ALL_TYPES["long int"],
        },
        name="rusage",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/resource/vtimes.c#L28
    "vtimes": SimStruct(
        {
            "vm_utime": ALL_TYPES["int"],
            "vm_stime": ALL_TYPES["int"],
            "vm_idsrss": ALL_TYPES["unsigned int"],
            "vm_ixrss": ALL_TYPES["unsigned int"],
            "vm_maxrss": ALL_TYPES["int"],
            "vm_maxflt": ALL_TYPES["int"],
            "vm_minflt": ALL_TYPES["int"],
            "vm_nswap": ALL_TYPES["int"],
            "vm_inblk": ALL_TYPES["int"],
            "vm_outblk": ALL_TYPES["int"],
        },
        name="vtimes",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/sysdeps/unix/sysv/linux/bits/resource.h#L139
    "rlimit": SimStruct(
        {
            "rlim_cur": ALL_TYPES["rlim_t"],
            "rlim_max": ALL_TYPES["rlim_t"],
        },
        name="rlimit",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/sysdeps/unix/sysv/linux/bits/resource.h#L148
    "rlimit64": SimStruct(
        {
            "rlim_cur": ALL_TYPES["rlim64_t"],
            "rlim_max": ALL_TYPES["rlim64_t"],
        },
        name="rlimit64",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/types/struct_sched_param.h#L23
    "sched_param": SimStruct(
        {"sched_priority": ALL_TYPES["int"]},
        name="sched_param",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/signal/bits/types/struct_sigstack.h#L23
    "sigstack": SimStruct(
        {
            "ss_sp": SimTypePointer(ALL_TYPES["void"], label="void *"),
            "ss_onstack": ALL_TYPES["int"],
        },
        name="sigstack",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/posix/bits/getopt_ext.h#L50
    "option": SimStruct(
        {
            "name": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "has_arg": ALL_TYPES["int"],
            "flag": SimTypePointer(ALL_TYPES["int"], label="int *"),
            "val": ALL_TYPES["int"],
        },
        name="option",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/argp/argp.h#L273
    "argp_state": SimStruct(
        {
            "root_argp": ALL_TYPES["argp"],
            "argc": ALL_TYPES["int"],
            "argv": SimTypePointer(
                SimTypePointer(ALL_TYPES["char"], label="char *"), label="char **"
            ),
            "next": ALL_TYPES["int"],
            "flags": ALL_TYPES["unsigned"],
            "arg_num": ALL_TYPES["unsigned"],
            "quoted": ALL_TYPES["int"],
            "input": SimTypePointer(ALL_TYPES["void"], label="void *"),
            "child_inputs": SimTypePointer(
                SimTypePointer(ALL_TYPES["void"], label="void *"), label="void **"
            ),
            "hook": SimTypePointer(ALL_TYPES["void"], label="void *"),
            "name": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "err_stream": SimStruct({}, name="FILE"),
            "pstate": SimTypePointer(ALL_TYPES["void"], label="void *"),
        },
        name="argp_state",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/sysvipc/sys/sem.h#L40
    "sembuf": SimStruct(
        {
            "sem_num": ALL_TYPES["unsigned short int"],
            "sem_op": ALL_TYPES["short int"],
            "sem_flg": ALL_TYPES["short int"],
        },
        name="sembuf",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/bits/utmp.h#L58
    "utmp": SimStruct(
        {
            "ut_type": ALL_TYPES["short int"],
            "ut_pid": ALL_TYPES["pid_t"],
            "ut_line": SimTypeArray(ALL_TYPES["char"], length=32, label="char[32]"),
            "ut_id": SimTypeArray(ALL_TYPES["char"], length=4, label="char[32]"),
            "ut_user": SimTypeArray(ALL_TYPES["char"], length=32, label="char[32]"),
            "ut_host": SimTypeArray(ALL_TYPES["char"], length=256, label="char[32]"),
            "ut_exit": ALL_TYPES["exit_status"],
            "ut_session": ALL_TYPES["long int"],
            "ut_tv": ALL_TYPES["timeval"],
            "ut_addr_v6": SimTypeArray(
                ALL_TYPES["int32_t"], length=4, label="int32_t[4]"
            ),
            "__glibc_reserved": SimTypeArray(
                ALL_TYPES["char"], length=20, label="char[20]"
            ),
        },
        name="utmp",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/sysdeps/gnu/bits/utmpx.h#L55
    "utmpx": SimStruct(
        {
            "ut_type": ALL_TYPES["short int"],
            "ut_pid": ALL_TYPES["pid_t"],
            "ut_line": SimTypeArray(ALL_TYPES["char"], length=32, label="char[32]"),
            "ut_id": SimTypeArray(ALL_TYPES["char"], length=4, label="char[32]"),
            "ut_user": SimTypeArray(ALL_TYPES["char"], length=32, label="char[32]"),
            "ut_host": SimTypeArray(ALL_TYPES["char"], length=256, label="char[32]"),
            "ut_exit": ALL_TYPES["exit_status"],
            "ut_session": ALL_TYPES["long int"],
            "ut_tv": ALL_TYPES["timeval"],
            "ut_addr_v6": SimTypeArray(
                ALL_TYPES["int32_t"], length=4, label="int32_t[4]"
            ),
            "__glibc_reserved": SimTypeArray(
                ALL_TYPES["char"], length=20, label="char[20]"
            ),
        },
        name="utmx",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/pwd/pwd.h#L49
    "passwd": SimStruct(
        {
            "pw_name": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "pw_passwd": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "pw_uid": ALL_TYPES["__uid_t"],
            "pw_gid": ALL_TYPES["__gid_t"],
            "pw_gecos": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "pw_dir": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "pw_shell": SimTypePointer(ALL_TYPES["char"], label="char *"),
        },
        name="passwd",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/grp/grp.h#L42
    "group": SimStruct(
        {
            "gr_name": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "gr_passwd": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "gr_gid": ALL_TYPES["__gid_t"],
            "gr_mem": SimTypePointer(
                SimTypePointer(ALL_TYPES["char"], label="char *"), label="char **"
            ),
        },
        name="group",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/posix/sys/utsname.h#L48
    "utsname": SimStruct(
        {
            "sysname": SimTypeArray(ALL_TYPES["char"], length=1024, label="char[1024]"),
            "nodename": SimTypeArray(
                ALL_TYPES["char"], length=1024, label="char[1024]"
            ),
            "release": SimTypeArray(ALL_TYPES["char"], length=1024, label="char[1024]"),
            "version": SimTypeArray(ALL_TYPES["char"], length=1024, label="char[1024]"),
            "machine": SimTypeArray(ALL_TYPES["char"], length=1024, label="char[1024]"),
            "domain": SimTypeArray(ALL_TYPES["char"], length=1024, label="char[1024]"),
        },
        name="utsname",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/misc/fstab.h#L57
    "fstab": SimStruct(
        {
            "fs_spec": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "fs_file": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "fs_vfstype": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "fs_mntops": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "fs_type": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "fs_freq": ALL_TYPES["int"],
            "fs_passno": ALL_TYPES["int"],
        },
        name="fstab",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/misc/mntent.h#L51
    "mntent": SimStruct(
        {
            "mnt_fsname": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "mnt_dir": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "mnt_type": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "mnt_opts": SimTypePointer(ALL_TYPES["char"], label="char *"),
            "mnt_freq": ALL_TYPES["int"],
            "mnt_passno": ALL_TYPES["int"],
        },
        name="mntent",
    ),
    # https://github.com/bminor/glibc/blob/2d5ec6692f5746ccb11db60976a6481ef8e9d74f/crypt/crypt.h#L43
    "crypt_data": SimStruct(
        {
            "keysched": SimTypeArray(
                ALL_TYPES["char"], length=16 * 8, label="char[16 * 8]"
            ),
            "sb0": SimTypeArray(ALL_TYPES["char"], length=32768, label="char[32768]"),
            "sb1": SimTypeArray(ALL_TYPES["char"], length=32768, label="char[32768]"),
            "sb2": SimTypeArray(ALL_TYPES["char"], length=32768, label="char[32768]"),
            "sb3": SimTypeArray(ALL_TYPES["char"], length=32768, label="char[32768]"),
            "crypt_3_buf": SimTypeArray(ALL_TYPES["char"], length=14, label="char[14]"),
            "current_salt": SimTypeArray(ALL_TYPES["char"], length=2, label="char[2]"),
            "current_saltbits": ALL_TYPES["long int"],
            "direction": ALL_TYPES["int"],
            "initialized": ALL_TYPES["int"],
        },
        name="crypt_data",
    ),
}
ALL_TYPES.update(GLIBC_TYPES)


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
        for field, ty in fields.items():
            if isinstance(ty, SimTypeArray):
                fields[field] = SimTypeFixedSizeArray(ty.elem_type, 0)

        if decl.name is not None:
            key = 'struct ' + decl.name
            struct = extra_types.get(key, None)
            from_global = False
            if struct is None:
                struct = ALL_TYPES.get(key, None)
                from_global = True
                if struct is not None:
                    struct = struct.with_arch(arch)

            if struct is None:
                struct = SimStruct(fields, decl.name)
                struct._arch = arch
            elif not struct.fields:
                struct.fields = fields
            elif fields and struct.fields != fields:
                if from_global:
                    struct = SimStruct(fields, decl.name)
                    struct._arch = arch
                else:
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

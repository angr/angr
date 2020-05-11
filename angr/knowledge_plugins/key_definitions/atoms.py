
from typing import Union

from ...engines.light import SpOffset


class Atom:
    """
    This class represents a data storage location manipulated by IR instructions.

    It could either be a Tmp (temporary variable), a Register, a MemoryLocation, or a Parameter.
    """
    def __repr__(self):
        raise NotImplementedError()

    @property
    def size(self) -> int:
        raise NotImplementedError()


class GuardUse(Atom):
    def __init__(self, target):
        self.target = target

    def __repr__(self):
        return '<Guard %#x>' % self.target

    @property
    def size(self) -> int:
        raise NotImplementedError()


class Tmp(Atom):
    """
    Represents a variable used by the IR to store intermediate values.
    """
    __slots__ = ('tmp_idx', '_size', )

    def __init__(self, tmp_idx: int, size: int):
        super(Tmp, self).__init__()
        self.tmp_idx = tmp_idx
        self._size = size

    def __repr__(self):
        return "<Tmp %d>" % self.tmp_idx

    def __eq__(self, other):
        return type(other) is Tmp and self.tmp_idx == other.tmp_idx

    def __hash__(self):
        return hash(('tmp', self.tmp_idx))

    @property
    def size(self) -> int:
        return self._size


class Register(Atom):
    """
    Represents a given CPU register.

    As an IR abstracts the CPU design to target different architectures, registers are represented as a separated memory
    space.
    Thus a register is defined by its offset from the base of this memory and its size.

    :ivar int reg_offset:    The offset from the base to define its place in the memory bloc.
    :ivar int size:          The size, in number of bytes.
    """
    __slots__ = ('reg_offset', '_size', )

    def __init__(self, reg_offset: int, size: int):
        super(Register, self).__init__()

        self.reg_offset = reg_offset
        self._size = size

    def __repr__(self):
        return "<Reg %d<%d>>" % (self.reg_offset, self.size)

    def __eq__(self, other):
        return type(other) is Register and \
               self.reg_offset == other.reg_offset and \
               self.size == other.size

    def __hash__(self):
        return hash(('reg', self.reg_offset, self.size))

    @property
    def bits(self) -> int:
        return self._size * 8

    @property
    def size(self) -> int:
        return self._size


class MemoryLocation(Atom):
    """
    Represents a memory slice.

    It is characterized by its address and its size.
    """

    __slots__ = ('addr', '_size')

    def __init__(self, addr: Union[SpOffset,int], size: int):
        """
        :param int addr: The address of the beginning memory location slice.
        :param int size: The size of the represented memory location, in bytes.
        """
        super(MemoryLocation, self).__init__()

        self.addr: Union[SpOffset,int] = addr
        self._size: int = size

    def __repr__(self):
        address_format = hex(self.addr) if type(self.addr) is int else self.addr
        stack_format = ' (stack)' if self.is_on_stack else ''
        return "<Mem %s<%d>%s>" % (address_format, self.size, stack_format)

    @property
    def is_on_stack(self) -> bool:
        """
        True if this memory location is located on the stack.
        """
        return isinstance(self.addr, SpOffset)

    @property
    def bits(self) -> int:
        return self.size * 8

    @property
    def size(self) -> int:
        return self._size

    @property
    def symbolic(self) -> bool:
        if isinstance(self.addr, int):
            return False
        elif isinstance(self.addr, SpOffset):
            return not type(self.addr.offset) is int
        return True

    def __eq__(self, other):
        return type(other) is MemoryLocation and \
               self.addr == other.addr and \
               self.size == other.size

    def __hash__(self):
        return hash(('mem', self.addr, self.size))


class Parameter(Atom):
    """
    Represents a function parameter.

    Can either be a <angr.engines.light.data.SpOffset> if the parameter was passed on the stack, or a <Register>, depending on the calling
    convention.
    """
    __slots__ = ('value', '_size', 'type_', 'meta')

    def __init__(self, value, size=None, type_=None, meta=None):
        super(Parameter, self).__init__()

        self.value = value
        self._size = size
        self.type_ = type_
        self.meta = meta

    @property
    def size(self) -> int:
        return self._size

    def __repr__(self):
        type_ = ', type=%s' % self.type_ if self.type_ is not None else ''
        meta = ', meta=%s' % self.meta if self.meta is not None else ''
        return '<Param %s%s%s>' % (self.value, type_, meta)

    def __eq__(self, other):
        return type(other) is Parameter and \
               self.value == other.value and \
               self.type_ == other.type_ and \
               self.meta == other.meta

    def __hash__(self):
        return hash(('par', self.value, self.type_, self.meta))

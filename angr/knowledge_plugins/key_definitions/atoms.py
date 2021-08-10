from typing import Dict, Tuple, Union, Optional

import claripy

from ...calling_conventions import SimFunctionArgument, SimRegArg
from ...engines.light import SpOffset
from .heap_address import HeapAddress


class Atom:
    """
    This class represents a data storage location manipulated by IR instructions.

    It could either be a Tmp (temporary variable), a Register, a MemoryLocation.
    """
    def __repr__(self):
        raise NotImplementedError()

    @property
    def size(self) -> int:
        raise NotImplementedError()

    @staticmethod
    def from_argument(argument: SimFunctionArgument, registers: Dict[str,Tuple[int,int]]):
        """
        Instanciate an `Atom` from a given argument.

        :param argument: The argument to create a new atom from.
        :param registers: A mapping representing the registers of a given architecture.
        """
        if isinstance(argument, SimRegArg):
            return Register(registers[argument.reg_name][0], argument.size)
        else:
            raise TypeError("Argument type %s is not yet supported." % type(argument))


class GuardUse(Atom):
    """
    Implements a guard use.
    """
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
        super().__init__()
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
        super().__init__()

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

    __slots__ = ('addr', '_size', 'endness', )

    def __init__(self, addr: Union[SpOffset,HeapAddress,int], size: int, endness: Optional[str]=None):
        """
        :param int addr: The address of the beginning memory location slice.
        :param int size: The size of the represented memory location, in bytes.
        """
        super().__init__()

        self.addr: Union[SpOffset,int,claripy.ast.BV] = addr
        self._size: int = size
        self.endness = endness

    def __repr__(self):
        address_format = hex(self.addr) if type(self.addr) is int else self.addr
        stack_format = ' (stack)' if self.is_on_stack else ''
        size = "%d" % self.size if isinstance(self.size, int) else self.size

        return "<Mem %s<%s>%s>" % (address_format, size, stack_format)

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
        # pylint:disable=isinstance-second-argument-not-valid-type
        return type(other) is MemoryLocation and \
               (
                    self.addr is other.addr if isinstance(self.addr, (claripy.ast.BV)) else self.addr == other.addr
               ) and \
               self.size == other.size and \
               self.endness == other.endness

    def __hash__(self):
        return hash(('mem', self.addr, self.size, self.endness))

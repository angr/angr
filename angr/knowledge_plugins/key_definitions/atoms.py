from typing import Dict, Tuple, Union, Optional

import claripy
import ailment

from ...calling_conventions import SimFunctionArgument, SimRegArg, SimStackArg
from ...engines.light import SpOffset
from .heap_address import HeapAddress
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues


class Atom:
    """
    This class represents a data storage location manipulated by IR instructions.

    It could either be a Tmp (temporary variable), a Register, a MemoryLocation.
    """

    __slots__ = ('_hash', )

    def __init__(self):
        self._hash = None

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
        elif isinstance(argument, SimStackArg):
            return MemoryLocation(registers["sp"][0] + argument.stack_offset, argument.size)
        else:
            raise TypeError("Argument type %s is not yet supported." % type(argument))

    def _core_hash(self):
        raise NotImplementedError()

    def __hash__(self):
        if self._hash is None:
            self._hash = self._core_hash()
        return self._hash


class GuardUse(Atom):
    """
    Implements a guard use.
    """
    __slots__ = ("target",)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def __repr__(self):
        return '<Guard %#x>' % self.target

    @property
    def size(self) -> int:
        raise NotImplementedError()

    __hash__ = Atom.__hash__

    def _core_hash(self):
        return hash((GuardUse, self.target))


class FunctionCall(Atom):
    __slots__ = ('target', 'callsite')

    def __init__(self, target, callsite):
        super().__init__()
        self.target = target
        self.callsite = callsite

    @property
    def single_target(self):
        if type(self.target) is MultiValues and len(self.target.values) == 1 and 0 in self.target.values and \
                len(self.target.values[0]) == 1 and next(iter(self.target.values[0])).op == 'BVV':
            return next(iter(self.target.values[0])).args[0]
        return None

    def __repr__(self):
        target = self.single_target
        target_txt = hex(target) if target is not None else '(indirect)'
        return '<Call %s>' % target_txt

    def __eq__(self, other):
        return type(other) is FunctionCall and self.callsite == other.callsite

    __hash__ = Atom.__hash__

    def _core_hash(self):
        return hash(self.callsite)

    @property
    def size(self):
        raise NotImplementedError


class ConstantSrc(Atom):
    __slots__ = ('const',)

    def __init__(self, const):
        super().__init__()
        self.const = const

    def __repr__(self):
        return repr(self.const)

    def __eq__(self, other):
        return type(other) is ConstantSrc and self.const == other.const

    __hash__ = Atom.__hash__

    def _core_hash(self):
        return hash(self.const)

    @property
    def size(self):
        return self.const.size


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

    __hash__ = Atom.__hash__

    def _core_hash(self):
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

    __hash__ = Atom.__hash__

    def _core_hash(self):
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

    __hash__ = Atom.__hash__

    def _core_hash(self):
        return hash(('mem', self.addr, self.size, self.endness))

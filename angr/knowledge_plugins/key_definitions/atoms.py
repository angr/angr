from typing import Union, Optional
from enum import Enum, auto

import claripy
from archinfo import Arch

from ...calling_conventions import SimFunctionArgument, SimRegArg, SimStackArg
from ...engines.light import SpOffset
from .heap_address import HeapAddress


class AtomKind(Enum):
    REGISTER = auto()
    MEMORY = auto()
    TMP = auto()
    GUARD = auto()
    CONSTANT = auto()


class Atom:
    """
    This class represents a data storage location manipulated by IR instructions.

    It could either be a Tmp (temporary variable), a Register, a MemoryLocation.
    """

    __slots__ = ("_hash", "size")

    def __init__(self, size):
        """
        :param size:  The size of the atom in bytes
        """
        self.size = size
        self._hash = None

    def __repr__(self):
        raise NotImplementedError()

    @property
    def bits(self) -> int:
        return self.size * 8

    @property
    def _size(self):
        return self.size

    @_size.setter
    def _size(self, v):
        self.size = v

    @staticmethod
    def from_argument(argument: SimFunctionArgument, arch: Arch, full_reg=False):
        """
        Instanciate an `Atom` from a given argument.

        :param argument: The argument to create a new atom from.
        :param registers: A mapping representing the registers of a given architecture.
        :param full_reg: Whether to return an atom indicating the entire register if the argument only specifies a
                        slice of the register.
        """
        if isinstance(argument, SimRegArg):
            if full_reg:
                return Register(arch.registers[argument.reg_name][0], arch.registers[argument.reg_name][1], arch)
            else:
                return Register(arch.registers[argument.reg_name][0] + argument.reg_offset, argument.size, arch)
        elif isinstance(argument, SimStackArg):
            # XXX why are we adding a stack offset to a register offset. wtf
            return MemoryLocation(arch.registers["sp"][0] + argument.stack_offset, argument.size)
        else:
            raise TypeError("Argument type %s is not yet supported." % type(argument))

    def _identity(self):
        raise NotImplementedError()

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(self._identity())
        return self._hash

    def __eq__(self, other):
        return type(self) is type(other) and self._identity() == other._identity()


class GuardUse(Atom):
    """
    Implements a guard use.
    """

    __slots__ = ("target",)

    def __init__(self, target):
        super().__init__(0)
        self.target = target

    def __repr__(self):
        return "<Guard %#x>" % self.target

    def _identity(self):
        return (self.target,)


class ConstantSrc(Atom):
    """
    Represents a constant.
    """

    __slots__ = ("value",)

    def __init__(self, value: int, size: int):
        super().__init__(size)
        self.value: int = value

    def __repr__(self):
        return f"<Const {self.value}>"

    def _identity(self):
        return (self.value, self.size)


class Tmp(Atom):
    """
    Represents a variable used by the IR to store intermediate values.
    """

    __slots__ = ("tmp_idx",)

    def __init__(self, tmp_idx: int, size: int):
        super().__init__(size)
        self.tmp_idx = tmp_idx

    def __repr__(self):
        return "<Tmp %d>" % self.tmp_idx

    def _identity(self):
        return hash(("tmp", self.tmp_idx))


class Register(Atom):
    """
    Represents a given CPU register.

    As an IR abstracts the CPU design to target different architectures, registers are represented as a separated memory
    space.
    Thus a register is defined by its offset from the base of this memory and its size.

    :ivar int reg_offset:    The offset from the base to define its place in the memory bloc.
    :ivar int size:          The size, in number of bytes.
    """

    __slots__ = (
        "reg_offset",
        "arch",
    )

    def __init__(self, reg_offset: int, size: int, arch: Optional[Arch] = None):
        super().__init__(size)

        self.reg_offset = reg_offset
        self.arch = arch

    def __repr__(self):
        return "<Reg %s<%d>>" % (self.name, self.size)

    def _identity(self):
        return (self.reg_offset, self.size)

    @property
    def name(self) -> str:
        return (
            str(self.reg_offset) if self.arch is None else self.arch.translate_register_name(self.reg_offset, self.size)
        )

    def __getstate__(self):
        return None

    def __setstate__(self, state):
        self.arch = None
        for k, v in state[1].items():
            setattr(self, k, v)


class MemoryLocation(Atom):
    """
    Represents a memory slice.

    It is characterized by its address and its size.
    """

    __slots__ = (
        "addr",
        "endness",
    )

    def __init__(self, addr: Union[SpOffset, HeapAddress, int], size: int, endness: Optional[str] = None):
        """
        :param int addr: The address of the beginning memory location slice.
        :param int size: The size of the represented memory location, in bytes.
        """
        super().__init__(size)

        self.addr: Union[SpOffset, int, claripy.ast.BV] = addr
        self.endness = endness

    def __repr__(self):
        address_format = hex(self.addr) if type(self.addr) is int else self.addr
        stack_format = " (stack)" if self.is_on_stack else ""
        size = "%d" % self.size if isinstance(self.size, int) else self.size

        return f"<Mem {address_format}<{size}>{stack_format}>"

    @property
    def is_on_stack(self) -> bool:
        """
        True if this memory location is located on the stack.
        """
        return isinstance(self.addr, SpOffset)

    @property
    def symbolic(self) -> bool:
        if isinstance(self.addr, int):
            return False
        elif isinstance(self.addr, SpOffset):
            return type(self.addr.offset) is not int
        return True

    def __eq__(self, other):
        # pylint:disable=isinstance-second-argument-not-valid-type
        return (
            type(other) is MemoryLocation
            and (
                self.addr is other.addr
                if (isinstance(self.addr, claripy.ast.BV) or isinstance(other.addr, claripy.ast.BV))
                else self.addr == other.addr
            )
            and self.size == other.size
            and self.endness == other.endness
        )

    __hash__ = Atom.__hash__

    def _identity(self):
        return (self.addr, self.size, self.endness)

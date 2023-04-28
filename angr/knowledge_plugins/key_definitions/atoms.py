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

    __slots__ = ("_hash",)

    def __init__(self):
        self._hash = None

    def __repr__(self):
        raise NotImplementedError()

    @property
    def size(self) -> int:
        """
        The size of the storage location, in bytes.
        """
        raise NotImplementedError()

    @property
    def bits(self) -> int:
        return self.size * 8

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

    def _core_hash(self):
        raise NotImplementedError()

    def __hash__(self):
        if self._hash is None:
            self._hash = self._core_hash()
        return self._hash

    def __getstate__(self):
        raise NotImplementedError()


class GuardUse(Atom):
    """
    Implements a guard use.
    """

    __slots__ = ("target",)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def __repr__(self):
        return "<Guard %#x>" % self.target

    @property
    def size(self) -> int:
        raise NotImplementedError()

    __hash__ = Atom.__hash__

    def _core_hash(self):
        return hash(self.__getstate__())

    def __getstate__(self):
        return (GuardUse, self.target)


class ConstantSrc(Atom):
    """
    Represents a constant.
    """

    __slots__ = ("value", "_size")

    def __init__(self, value: int, size: int):
        super().__init__()
        self.value: int = value
        self._size: int = size

    def __repr__(self):
        return f"<Const {self.value}>"

    def __eq__(self, other):
        return type(other) is ConstantSrc and self.value == other.value and self.size == other.size

    __hash__ = Atom.__hash__

    def _core_hash(self):
        return hash(self.__getstate__())

    def __getstate__(self):
        return (self.value, self.size)

    @property
    def size(self):
        return self._size


class Tmp(Atom):
    """
    Represents a variable used by the IR to store intermediate values.
    """

    __slots__ = (
        "tmp_idx",
        "_size",
    )

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
        return hash(("tmp", self.tmp_idx))

    def __getstate__(self):
        return (self.tmp_idx,)

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

    __slots__ = (
        "reg_offset",
        "_size",
        "arch",
    )

    def __init__(self, reg_offset: int, size: int, arch: Optional[Arch] = None):
        super().__init__()

        self.reg_offset = reg_offset
        self._size = size
        self.arch = arch

    def __repr__(self):
        return "<Reg %s<%d>>" % (self.name, self.size)

    def __eq__(self, other):
        return type(other) is Register and self.reg_offset == other.reg_offset and self.size == other.size

    __hash__ = Atom.__hash__

    def _core_hash(self):
        return hash(("reg", self.reg_offset, self.size))

    def __getstate__(self):
        return (self.reg_offset, self.size)

    @property
    def size(self) -> int:
        return self._size

    @property
    def name(self) -> str:
        return (
            str(self.reg_offset)
            if self.arch is None
            else self.arch.translate_register_name(self.reg_offset, self._size)
        )


class MemoryLocation(Atom):
    """
    Represents a memory slice.

    It is characterized by its address and its size.
    """

    __slots__ = (
        "addr",
        "_size",
        "endness",
    )

    def __init__(self, addr: Union[SpOffset, HeapAddress, int], size: int, endness: Optional[str] = None):
        """
        :param int addr: The address of the beginning memory location slice.
        :param int size: The size of the represented memory location, in bytes.
        """
        super().__init__()

        self.addr: Union[SpOffset, int, claripy.ast.BV] = addr
        self._size: int = size
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

    def _core_hash(self):
        return hash(("mem", self.addr, self.size, self.endness))

    def __getstate__(self):
        return (self.addr, self.size, self.endness)

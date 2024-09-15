from __future__ import annotations
from enum import Enum, auto

import claripy
import ailment
from archinfo import Arch, RegisterOffset

from ...calling_conventions import SimFunctionArgument, SimRegArg, SimStackArg
from ...engines.light import SpOffset
from .heap_address import HeapAddress


class AtomKind(Enum):
    """
    An enum indicating the class of an atom
    """

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
        raise NotImplementedError

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
    def from_ail_expr(expr: ailment.Expr.Expression, arch: Arch, full_reg: bool = False) -> Register:
        if isinstance(expr, ailment.Expr.Register):
            if full_reg:
                reg_name = arch.translate_register_name(expr.reg_offset)
                return Register(arch.registers[reg_name][0], arch.registers[reg_name][1], arch)
            return Register(expr.reg_offset, expr.size, arch)
        raise TypeError(f"Expression type {type(expr)} is not yet supported")

    @staticmethod
    def from_argument(
        argument: SimFunctionArgument, arch: Arch, full_reg=False, sp: int | None = None
    ) -> Register | MemoryLocation:
        """
        Instantiate an `Atom` from a given argument.

        :param argument: The argument to create a new atom from.
        :param arch: The argument representing archinfo architecture for argument.
        :param full_reg: Whether to return an atom indicating the entire register if the argument only specifies a
                        slice of the register.
        :param sp:      The current stack offset. Optional. Only used when argument is a SimStackArg.
        """
        if isinstance(argument, SimRegArg):
            if full_reg:
                return Register(arch.registers[argument.reg_name][0], arch.registers[argument.reg_name][1], arch)
            return Register(arch.registers[argument.reg_name][0] + argument.reg_offset, argument.size, arch)
        if isinstance(argument, SimStackArg):
            if sp is None:
                raise ValueError("You must provide a stack pointer to translate a SimStackArg")
            return MemoryLocation(
                SpOffset(arch.bits, argument.stack_offset + sp), argument.size, endness=arch.memory_endness
            )
        raise TypeError(f"Argument type {type(argument)} is not yet supported.")

    @staticmethod
    def reg(thing: str | RegisterOffset, size: int | None = None, arch: Arch | None = None) -> Register:
        """
        Create a Register atom.

        :param thing:   The register offset (e.g., project.arch.registers["rax"][0]) or the register name (e.g., "rax").
        :param size:    Size of the register atom. Must be provided when creating the atom using a register offset.
        :param arch:    The architecture. Must be provided when creating the atom using a register name.
        :return:        The Register Atom object.
        """

        if isinstance(thing, str):
            if arch is None:
                raise ValueError(
                    "Cannot create a Register Atom by register name without having an architecture "
                    "specified through arch!"
                )
            if thing not in arch.registers:
                raise ValueError(f"Unknown register name {thing} for architecture {arch.name}")
            reg_offset, size_ = arch.registers[thing]
            if size is None:
                size = size_
        elif isinstance(thing, RegisterOffset):
            reg_offset = thing
            if size is None:
                raise ValueError("You must provide a size when specifying the register offset")
        else:
            raise TypeError(
                "Unsupported type of register. It must be a string (for register name) or an int (for "
                "register offset)"
            )
        return Register(reg_offset, size, arch=arch)

    register = reg

    @staticmethod
    def mem(addr: SpOffset | HeapAddress | int, size: int, endness: str | None = None) -> MemoryLocation:
        """
        Create a MemoryLocation atom,

        :param addr:        The memory location. Can be an SpOffset for stack variables, an int for global memory
                            variables, or a HeapAddress for items on the heap.
        :param size:        Size of the atom.
        :param endness:     Optional, either "Iend_LE" or "Iend_BE".
        :return:            The MemoryLocation Atom object.
        """
        return MemoryLocation(addr, size, endness=endness)

    memory = mem

    def _identity(self):
        raise NotImplementedError

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
        return f"<Guard {self.target:#x}>"

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

    def __init__(self, reg_offset: RegisterOffset, size: int, arch: Arch | None = None):
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


class VirtualVariable(Atom):
    """
    Represents a virtual variable.
    """

    __slots__ = (
        "varid",
        "category",
        "oident",
    )

    def __init__(
        self, varid: int, size: int, category: ailment.Expr.VirtualVariableCategory, oident: str | int | None = None
    ):
        super().__init__(size)

        self.varid = varid
        self.category = category
        self.oident = oident

    def __repr__(self):
        return "<VVar %d<%d>>" % (self.varid, self.size)

    def _identity(self):
        return self.varid, self.size

    @property
    def was_reg(self) -> bool:
        return self.category == ailment.Expr.VirtualVariableCategory.REGISTER

    @property
    def was_stack(self) -> bool:
        return self.category == ailment.Expr.VirtualVariableCategory.STACK

    @property
    def was_parameter(self) -> bool:
        return self.category == ailment.Expr.VirtualVariableCategory.PARAMETER

    @property
    def reg_offset(self) -> int | None:
        if self.was_reg:
            return self.oident
        return None

    @property
    def stack_offset(self) -> int | None:
        if self.was_stack:
            return self.oident
        return None


class MemoryLocation(Atom):
    """
    Represents a memory slice.

    It is characterized by its address and its size.
    """

    __slots__ = (
        "addr",
        "endness",
    )

    def __init__(self, addr: SpOffset | HeapAddress | int, size: int, endness: str | None = None):
        """
        :param int addr: The address of the beginning memory location slice.
        :param int size: The size of the represented memory location, in bytes.
        """
        super().__init__(size)

        self.addr: SpOffset | int | claripy.ast.BV = addr
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
        if isinstance(self.addr, SpOffset):
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
        return self.addr, self.size, self.endness


atom_kind_mapping = {
    AtomKind.REGISTER: Register,
    AtomKind.MEMORY: MemoryLocation,
    AtomKind.TMP: Tmp,
    AtomKind.GUARD: GuardUse,
    AtomKind.CONSTANT: ConstantSrc,
}

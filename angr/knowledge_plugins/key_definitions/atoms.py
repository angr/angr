from __future__ import annotations

import json
from enum import Enum, auto

import claripy
from archinfo import Arch, Endness, RegisterOffset

import angr.ailment as ailment
from angr.calling_conventions import SimFunctionArgument, SimRegArg, SimStackArg
from angr.engines.light import SpOffset
from angr.protos import key_defs_pb2
from angr.serializable import Serializable

from .heap_address import HeapAddress
from .undefined import UNDEFINED, Undefined


# The local protobuf enum VirtualVariableCategory mirrors ailment.Expr.VirtualVariableCategory. We rely on the
# integer values agreeing so that round-tripping through protobuf cannot drift; verify this once at import time.
assert all(
    int(key_defs_pb2.VirtualVariableCategory.Value(f"VVC_{name}"))
    == int(getattr(ailment.Expr.VirtualVariableCategory, name))
    for name in ("REGISTER", "STACK", "MEMORY", "PARAMETER", "TMP", "COMBO_REGISTER", "UNKNOWN")
), "VirtualVariableCategory mirror in key_defs.proto is out of sync with ailment.Expr.VirtualVariableCategory"


def _tuplify(v):
    if isinstance(v, list):
        return tuple(_tuplify(x) for x in v)
    return v


class AtomKind(Enum):
    """
    An enum indicating the class of an atom
    """

    REGISTER = auto()
    MEMORY = auto()
    TMP = auto()
    GUARD = auto()
    CONSTANT = auto()


class Atom(Serializable):
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

    def __getstate__(self):
        # Exclude the cached hash from the pickle: it folds in per-process-salted
        # string hashes (e.g. register names), so a persisted value is stale when
        # unpickled in another process. It is recomputed lazily instead.
        slotstate = {
            slot: getattr(self, slot)
            for klass in type(self).__mro__
            for slot in getattr(klass, "__slots__", ())
            if slot != "_hash" and hasattr(self, slot)
        }
        return getattr(self, "__dict__", None), slotstate

    def __setstate__(self, state):
        dictstate, slotstate = state if isinstance(state, tuple) else (None, state)
        if dictstate:
            self.__dict__.update(dictstate)
        for slot, value in (slotstate or {}).items():
            if slot != "_hash":
                setattr(self, slot, value)
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
                "Unsupported type of register. It must be a string (for register name) or an int (for register offset)"
            )
        return Register(reg_offset, size, arch=arch)

    register = reg

    @staticmethod
    def mem(addr: SpOffset | HeapAddress | int, size: int, endness: Endness | None = None) -> MemoryLocation:
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

    # The atom is serialized as a wrapping ``Atom`` cmessage carrying the per-kind inner cmessage in a oneof field;
    # ``parse_from_cmessage`` dispatches on ``WhichOneof("kind")`` to the right subclass.

    _SERIALIZE_KIND: str = ""  # name of the oneof field for this subclass; set by each concrete subclass

    @classmethod
    def _get_cmsg(cls):
        return key_defs_pb2.Atom()

    def serialize_to_cmessage(self):
        cmsg = key_defs_pb2.Atom()
        inner = self._serialize_inner()
        getattr(cmsg, self._SERIALIZE_KIND).CopyFrom(inner)
        return cmsg

    def _serialize_inner(self):
        raise NotImplementedError

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        kind = cmsg.WhichOneof("kind")
        if kind is None:
            raise ValueError("Atom cmessage has no kind set")
        subclass = _ATOM_KIND_TO_CLASS[kind]
        return subclass._parse_from_inner(getattr(cmsg, kind), **kwargs)

    @classmethod
    def _parse_from_inner(cls, inner_cmsg, **kwargs):
        raise NotImplementedError


class GuardUse(Atom):
    """
    Implements a guard use.
    """

    __slots__ = ("target",)
    _SERIALIZE_KIND = "guard_use"

    def __init__(self, target):
        super().__init__(0)
        self.target = target

    def __repr__(self):
        return f"<Guard {self.target:#x}>"

    def _identity(self):
        return (self.target,)

    def _serialize_inner(self):
        return key_defs_pb2.GuardUseAtom(target=self.target)

    @classmethod
    def _parse_from_inner(cls, inner_cmsg, **kwargs):
        return cls(inner_cmsg.target)


class ConstantSrc(Atom):
    """
    Represents a constant.
    """

    __slots__ = ("value",)
    _SERIALIZE_KIND = "constant_src"

    def __init__(self, value: int, size: int):
        super().__init__(size)
        self.value: int = value

    def __repr__(self):
        return f"<Const {self.value}>"

    def _identity(self):
        return (self.value, self.size)

    def _serialize_inner(self):
        return key_defs_pb2.ConstantSrcAtom(value=self.value, size=self.size)

    @classmethod
    def _parse_from_inner(cls, inner_cmsg, **kwargs):
        return cls(inner_cmsg.value, inner_cmsg.size)


class Tmp(Atom):
    """
    Represents a variable used by the IR to store intermediate values.
    """

    __slots__ = ("tmp_idx",)
    _SERIALIZE_KIND = "tmp"

    def __init__(self, tmp_idx: int, size: int):
        super().__init__(size)
        self.tmp_idx = tmp_idx

    def __repr__(self):
        return f"<Tmp {self.tmp_idx}>"

    def _identity(self):
        return hash(("tmp", self.tmp_idx))

    def _serialize_inner(self):
        return key_defs_pb2.TmpAtom(tmp_idx=self.tmp_idx, size=self.size)

    @classmethod
    def _parse_from_inner(cls, inner_cmsg, **kwargs):
        return cls(inner_cmsg.tmp_idx, inner_cmsg.size)


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
        "arch",
        "reg_offset",
    )
    _SERIALIZE_KIND = "register"

    def __init__(self, reg_offset: RegisterOffset | int, size: int, arch: Arch | None = None):
        super().__init__(size)

        self.reg_offset = RegisterOffset(reg_offset)
        self.arch = arch

    def __repr__(self):
        return f"<Reg {self.name}<{self.size}>>"

    def _identity(self):
        return (self.reg_offset, self.size)

    @property
    def name(self) -> str:
        return (
            str(self.reg_offset) if self.arch is None else self.arch.translate_register_name(self.reg_offset, self.size)
        )

    def _serialize_inner(self):
        # arch is intentionally dropped; it is reattached from the parent Project at parse time when needed.
        return key_defs_pb2.RegisterAtom(reg_offset=int(self.reg_offset), size=self.size)

    @classmethod
    def _parse_from_inner(cls, inner_cmsg, *, arch: Arch | None = None, **kwargs):
        return cls(inner_cmsg.reg_offset, inner_cmsg.size, arch=arch)


class VirtualVariable(Atom):
    """
    Represents a virtual variable.
    """

    __slots__ = (
        "category",
        "oident",
        "varid",
    )
    _SERIALIZE_KIND = "virtual_variable"

    def __init__(
        self,
        varid: int,
        size: int,
        category: ailment.Expr.VirtualVariableCategory,
        oident: str | int | tuple | None = None,
    ):
        super().__init__(size)

        self.varid = varid
        self.category = category
        self.oident = oident

    def __repr__(self):
        return f"<VVar {self.varid}<{self.size}>>"

    def _identity(self):
        return self.varid, self.size

    def _serialize_inner(self):
        msg = key_defs_pb2.VirtualVariableAtom(
            varid=self.varid,
            size=self.size,
            category=int(self.category),
        )
        if self.oident is not None:
            # oident may be int, str, tuple, or nested tuples (e.g. for PARAMETER atoms). JSON round-trips primitives
            # cleanly; tuples become lists and we re-tuplify on parse.
            msg.oident_json = json.dumps(self.oident, default=int)
        return msg

    @classmethod
    def _parse_from_inner(cls, inner_cmsg, **kwargs):
        oident = _tuplify(json.loads(inner_cmsg.oident_json)) if inner_cmsg.HasField("oident_json") else None
        return cls(
            inner_cmsg.varid,
            inner_cmsg.size,
            ailment.Expr.VirtualVariableCategory._from_int_py(inner_cmsg.category),
            oident=oident,
        )

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
    def was_tmp(self) -> bool:
        return self.category == ailment.Expr.VirtualVariableCategory.TMP

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

    @property
    def tmp_idx(self) -> int | None:
        return self.oident if self.was_tmp else None


class MemoryLocation(Atom):
    """
    Represents a memory slice.

    It is characterized by its address and its size.
    """

    __slots__ = (
        "addr",
        "endness",
    )
    _SERIALIZE_KIND = "memory_location"

    def __init__(self, addr: SpOffset | HeapAddress | int, size: int, endness: Endness | None = None):
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
        size = f"{self.size}" if isinstance(self.size, int) else self.size

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

    def _serialize_inner(self):
        addr_msg = key_defs_pb2.MemoryLocationAddr()
        if isinstance(self.addr, SpOffset):
            if not isinstance(self.addr.offset, int):
                raise ValueError(f"Cannot serialize SpOffset with symbolic offset: {self.addr!r}")
            addr_msg.sp_offset.bits = self.addr._bits
            addr_msg.sp_offset.offset = self.addr.offset
            addr_msg.sp_offset.is_base = self.addr.is_base
        elif isinstance(self.addr, HeapAddress):
            if isinstance(self.addr.value, Undefined):
                addr_msg.heap_address.is_undefined = True
            elif isinstance(self.addr.value, int):
                addr_msg.heap_address.value = self.addr.value
            else:
                raise ValueError(f"Cannot serialize HeapAddress with non-int/Undefined value: {self.addr!r}")
        elif isinstance(self.addr, int):
            addr_msg.int_addr = self.addr
        else:
            # claripy.ast.BV (symbolic) intentionally not supported; symbolic memory locations are not part of any
            # persisted state targeted by this serialization effort.
            raise TypeError(f"Cannot serialize MemoryLocation with addr of type {type(self.addr).__name__}")
        msg = key_defs_pb2.MemoryLocationAtom(addr=addr_msg, size=self.size)
        if self.endness is not None:
            msg.endness = str(self.endness)
        return msg

    @classmethod
    def _parse_from_inner(cls, inner_cmsg, **kwargs):
        kind = inner_cmsg.addr.WhichOneof("kind")
        if kind == "int_addr":
            addr = inner_cmsg.addr.int_addr
        elif kind == "sp_offset":
            addr = SpOffset(
                inner_cmsg.addr.sp_offset.bits,
                inner_cmsg.addr.sp_offset.offset,
                is_base=inner_cmsg.addr.sp_offset.is_base,
            )
        elif kind == "heap_address":
            addr = HeapAddress(
                UNDEFINED if inner_cmsg.addr.heap_address.is_undefined else inner_cmsg.addr.heap_address.value
            )
        else:
            raise ValueError("MemoryLocationAddr has no kind set")
        endness = Endness(inner_cmsg.endness) if inner_cmsg.HasField("endness") else None
        return cls(addr, inner_cmsg.size, endness=endness)


# Polymorphic dispatch table: maps the Atom oneof field name to the concrete subclass.
_ATOM_KIND_TO_CLASS: dict[str, type[Atom]] = {
    "tmp": Tmp,
    "register": Register,
    "virtual_variable": VirtualVariable,
    "memory_location": MemoryLocation,
    "guard_use": GuardUse,
    "constant_src": ConstantSrc,
}


atom_kind_mapping = {
    AtomKind.REGISTER: Register,
    AtomKind.MEMORY: MemoryLocation,
    AtomKind.TMP: Tmp,
    AtomKind.GUARD: GuardUse,
    AtomKind.CONSTANT: ConstantSrc,
}

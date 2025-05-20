from __future__ import annotations
from typing import TYPE_CHECKING
import logging

import claripy

from .protos import variables_pb2 as pb2
from .serializable import Serializable

if TYPE_CHECKING:
    import archinfo


_l = logging.getLogger(__name__)


class SimVariable(Serializable):
    """
    The base class for all other classes of variables.
    """

    __slots__ = [
        "candidate_names",
        "category",
        "ident",
        "name",
        "region",
        "renamed",
        "size",
    ]

    def __init__(
        self, size: int, ident: str | None = None, name: str | None = None, region: int | None = None, category=None
    ):
        """
        :param ident: A unique identifier provided by user or the program. Usually a string.
        :param str name: Name of this variable.
        """
        self.ident = ident
        self.name = name
        self.region: int | None = region
        self.category: str | None = category
        self.renamed = False
        self.candidate_names = None
        self.size = size

    def copy(self):
        raise NotImplementedError

    def loc_repr(self, arch: archinfo.Arch):
        """
        The representation that shows up in a GUI
        """
        raise NotImplementedError

    def _set_base(self, obj):
        obj.base.ident = self.ident
        if self.category is not None:
            obj.base.category = self.category
        if self.region is not None:
            obj.base.region = self.region
        if self.name is not None:
            obj.base.name = self.name
        obj.base.renamed = self.renamed

    def _from_base(self, obj):
        self.ident = obj.base.ident
        if obj.base.HasField("category"):
            self.category = obj.base.category
        else:
            self.category = None
        if obj.base.HasField("region"):
            self.region = obj.base.region
        self.name = obj.base.name
        self.renamed = obj.base.renamed

    @property
    def is_function_argument(self):
        return self.ident and self.ident.startswith("arg_")

    @property
    def bits(self) -> int:
        return self.size * 8

    @property
    def key(self) -> tuple[str | int | None, ...]:
        raise NotImplementedError

    #
    # Operations
    #

    def __add__(self, other):
        if isinstance(other, int) and other == 0:
            return self
        return None

    def __sub__(self, other):
        if isinstance(other, int) and other == 0:
            return self
        return None


class SimConstantVariable(SimVariable):
    """
    Describes a constant variable.
    """

    __slots__ = ["_hash", "value"]

    def __init__(self, size: int, ident=None, value=None, region=None):
        super().__init__(ident=ident, region=region, size=size)
        self.value = value
        self._hash = None

    def __repr__(self):
        return f"<{self.region}|const {self.value}>"

    def loc_repr(self, arch):
        return f"const {self.value}"

    def __eq__(self, other):
        if not isinstance(other, SimConstantVariable):
            return False

        if self.value is None or other.value is None:
            # they may or may not represent the same constant. return not equal to be safe
            return False

        return self.ident == other.ident and self.value == other.value and self.region == other.region

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(("const", self.value, self.ident, self.region, self.ident))
        return self._hash

    def copy(self) -> SimConstantVariable:
        r = SimConstantVariable(ident=self.ident, value=self.value, region=self.region, size=self.size)
        r._hash = self._hash
        return r

    @property
    def key(self) -> tuple[str | int | None, ...]:
        return ("const", self.value, self.size, self.ident)


class SimTemporaryVariable(SimVariable):
    """
    Describes a temporary variable.
    """

    __slots__ = ["_hash", "tmp_id"]

    def __init__(self, tmp_id: int, size: int):
        SimVariable.__init__(self, size=size)

        self.tmp_id = tmp_id
        self._hash = None

    def __repr__(self):
        return f"<tmp {self.tmp_id}>"

    def loc_repr(self, arch):
        return f"tmp #{self.tmp_id}"

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(f"tmp_{self.tmp_id}")
        return self._hash

    def __eq__(self, other):
        if isinstance(other, SimTemporaryVariable):
            return hash(self) == hash(other)

        return False

    def copy(self) -> SimTemporaryVariable:
        r = SimTemporaryVariable(self.tmp_id, size=self.size)
        r._hash = self._hash
        return r

    @property
    def key(self) -> tuple[str | int | None, ...]:
        return ("tmp", self.tmp_id, self.size, self.ident)

    @classmethod
    def _get_cmsg(cls):
        return pb2.TemporaryVariable()  # type:ignore, pylint:disable=no-member

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        self._set_base(obj)
        obj.tmp_id = self.tmp_id
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        obj = cls(cmsg.tmp_id, cmsg.base.size)
        obj._from_base(cmsg)
        return obj


class SimRegisterVariable(SimVariable):
    """
    Describes a register variable.
    """

    __slots__ = ["_hash", "reg"]

    def __init__(self, reg_offset: int, size: int, ident=None, name=None, region=None, category=None):
        SimVariable.__init__(self, ident=ident, name=name, region=region, category=category, size=size)

        self.reg = reg_offset
        self._hash: int | None = None

    def __repr__(self):
        ident_str = f"[{self.ident}]" if self.ident else ""
        region_str = hex(self.region) if isinstance(self.region, int) else self.region

        return f"<{region_str}{ident_str}|Reg {self.reg}, {self.size}B>"

    def loc_repr(self, arch):
        return arch.translate_register_name(self.reg, self.size)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash(("reg", self.region, self.reg, self.size, self.ident))
        return self._hash

    def __eq__(self, other):
        if isinstance(other, SimRegisterVariable):
            return (
                self.ident == other.ident
                and self.reg == other.reg
                and self.size == other.size
                and self.region == other.region
            )

        return False

    @property
    def key(self) -> tuple[str | int | None, ...]:
        return ("reg", self.reg, self.size, self.ident)

    def copy(self) -> SimRegisterVariable:
        s = SimRegisterVariable(
            self.reg, self.size, ident=self.ident, name=self.name, region=self.region, category=self.category
        )
        s._hash = self._hash
        return s

    @classmethod
    def _get_cmsg(cls):
        return pb2.RegisterVariable()  # type:ignore, pylint:disable=no-member

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        self._set_base(obj)
        obj.reg = self.reg
        obj.size = self.size
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        obj = cls(
            cmsg.reg,
            cmsg.size,
        )
        obj._from_base(cmsg)
        return obj


class SimMemoryVariable(SimVariable):
    """
    Describes a memory variable; the base class for other types of memory variables.
    """

    __slots__ = ["_hash", "addr"]

    def __init__(self, addr, size: int, ident=None, name=None, region=None, category=None):
        SimVariable.__init__(self, ident=ident, name=name, region=region, category=category, size=size)

        self.addr = addr

        if isinstance(size, claripy.ast.BV) and not size.symbolic:
            # Convert it to a concrete number
            size = size.concrete_value

        self.size = size
        self._hash = None

    def __repr__(self):
        if type(self.addr) is int:
            s = f"<{self.name}: {self.region}-Mem {self.addr:#x} {self.size}>"
        else:
            s = f"<{self.name}: {self.region}-Mem {self.addr} {self.size}>"

        return s

    def loc_repr(self, arch):
        return f"[{self.addr:#x}]"

    def __hash__(self):
        if self._hash is not None:
            return self._hash

        self._hash = hash((hash(self.addr), hash(self.size), self.ident))
        return self._hash

    def __eq__(self, other):
        if isinstance(other, SimMemoryVariable):
            return self.ident == other.ident and self.addr == other.addr and self.size == other.size

        return False

    def copy(self) -> SimMemoryVariable:
        r = SimMemoryVariable(
            self.addr, self.size, ident=self.ident, name=self.name, region=self.region, category=self.category
        )
        r._hash = self._hash
        return r

    @property
    def key(self) -> tuple[str | int | None, ...]:
        return ("mem", self.addr, self.size, self.ident)

    @classmethod
    def _get_cmsg(cls):
        return pb2.MemoryVariable()  # type:ignore, pylint:disable=no-member

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        self._set_base(obj)
        obj.addr = self.addr
        obj.size = self.size
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        obj = cls(
            cmsg.addr,
            cmsg.size,
        )
        obj._from_base(cmsg)
        return obj


class SimStackVariable(SimMemoryVariable):
    """
    Describes a stack variable.
    """

    __slots__ = (
        "base",
        "base_addr",
        "offset",
    )

    def __init__(
        self, offset: int, size: int, base="sp", base_addr=None, ident=None, name=None, region=None, category=None
    ):
        if isinstance(offset, int) and offset > 0x1000000:
            # I don't think any positive stack offset will be greater than that...
            # convert it to a negative number
            mask = (1 << offset.bit_length()) - 1
            offset = -((0 - offset) & mask)

        addr = offset + base_addr if base_addr is not None else offset  # TODO: this is not optimal

        super().__init__(addr, size, ident=ident, name=name, region=region, category=category)

        self.base = base
        self.offset = offset
        self.base_addr = base_addr

    def __repr__(self):
        prefix = f"{self.name}(stack)" if self.name is not None else "Stack"
        ident = f"[{self.ident}]" if self.ident else ""
        region_str = hex(self.region) if isinstance(self.region, int) else self.region

        if type(self.offset) is int:
            if self.offset < 0:
                offset = f"{self.offset:#x}"
            elif self.offset > 0:
                offset = f"+{self.offset:#x}"
            else:
                offset = ""

            s = f"<{region_str}{ident}|{prefix} {self.base}{offset}, {self.size} B>"
        else:
            s = f"<{region_str}{ident}|{prefix} {self.base}{self.addr}, {self.size} B>"

        return s

    def loc_repr(self, arch):
        return f"[{self.base}{self.offset:+#x}]"

    def __eq__(self, other):
        if type(other) is not SimStackVariable:
            return False

        return (
            self.ident == other.ident
            and self.base == other.base
            and self.offset == other.offset
            and self.size == other.size
        )

    def __hash__(self):
        return hash((self.ident, self.base, self.offset, self.size))

    def copy(self) -> SimStackVariable:
        s = SimStackVariable(
            self.offset,
            self.size,
            base=self.base,
            base_addr=self.base_addr,
            ident=self.ident,
            name=self.name,
            region=self.region,
            category=self.category,
        )
        s._hash = self._hash
        return s

    @property
    def key(self) -> tuple[str | int | None, ...]:
        return (
            "stack",
            self.base,
            self.base_addr if isinstance(self.base_addr, int) else None,
            self.offset if isinstance(self.offset, int) else None,
            self.size,
            self.ident,
        )

    @classmethod
    def _get_cmsg(cls):
        return pb2.StackVariable()  # type:ignore, pylint:disable=no-member

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        self._set_base(obj)
        obj.sp_base = self.base == "sp"
        if not -0x8000_0000 <= self.offset < 0x8000_0000:
            _l.warning(
                "The offset of stack variable %r (%d) is out of allowable range; force it to within the int32 range.",
                self,
                self.offset,
            )
            obj.offset = -0x7FFF_DEAD if self.offset < 0 else 0x7FFF_DEAD
        else:
            obj.offset = self.offset
        obj.size = self.size
        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        obj = cls(
            cmsg.offset,
            cmsg.size,
            base="sp" if cmsg.sp_base else "bp",
        )
        obj._from_base(cmsg)
        return obj

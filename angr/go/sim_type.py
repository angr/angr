# pylint:disable=missing-class-docstring,arguments-differ
"""
Go-flavored SimTypes.

Every class carries an optional ``go_name`` (the declared name of a named type such as ``time.Duration``), which is
what gets rendered; the underlying representation decides size, layout and how values are passed.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, cast

import claripy

from angr.sim_type import (
    IDENT_TO_CLS,
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeBottom,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeInt,
    SimTypePointer,
)


class GoSimType(SimType):
    _ident = "go"
    go_name: str | None = None

    def go_repr(self) -> str:
        """The canonical Go spelling of this type (its name when it is a named type)."""
        if self.go_name is not None:
            return self.go_name
        return self._go_repr()

    def _go_repr(self) -> str:
        raise NotImplementedError

    def repr(self, name=None, full=0, memo=None, indent: int | None = 0):
        if name:
            return f"{name} {self.go_repr()}"
        return self.go_repr()

    def c_repr(  # type: ignore[override]
        self, name=None, full=0, memo=None, indent: int | None = 0, name_parens: bool = True, **kwargs
    ):
        del name_parens, kwargs
        return self.repr(name, full, memo, indent)

    def __repr__(self):
        return self.go_repr()

    def __str__(self):
        return self.go_repr()


#
# Scalars
#


class GoSimTypeInt(GoSimType, SimTypeInt):
    """An integer of explicit width. ``go_name`` distinguishes ``int``/``uintptr``/``rune`` from ``int64``/``uint64``/
    ``int32``."""

    _ident = "go_int"
    _fields = (*(x for x in SimTypeInt._fields if x != "size"), "_size", "go_name")
    _args = ("size", "signed", "go_name", "label")

    def __init__(self, size: int = 64, signed: bool = True, go_name: str | None = None, label=None):
        SimTypeInt.__init__(self, signed, label)
        self._size = size
        self.go_name = go_name

    @property
    def size(self) -> int:
        assert self._size is not None
        return self._size

    @property
    def alignment(self):
        assert self._arch is not None
        return min(max(1, self._size // self._arch.byte_width), self._arch.bytes)

    def _go_repr(self) -> str:
        return ("int" if self.signed else "uint") + str(self._size)

    def copy(self):
        return GoSimTypeInt(self._size, self.signed, self.go_name, self.label).with_arch(self._arch)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeInt(self._size, self.signed, self.go_name, self.label)
        out._arch = arch
        return out


class GoSimTypeBool(GoSimTypeInt):
    _ident = "go_bool"
    _args = ("go_name", "label")

    def __init__(self, go_name: str | None = None, label=None):
        super().__init__(8, False, go_name, label)

    def _go_repr(self) -> str:
        return "bool"

    def copy(self):
        return GoSimTypeBool(self.go_name, self.label).with_arch(self._arch)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeBool(self.go_name, self.label)
        out._arch = arch
        return out


class GoSimTypeFloat(GoSimType, SimTypeFloat):
    _ident = "go_float"
    _fields = ("size", "go_name")
    _args = ("size", "go_name", "label")

    def __init__(self, size: int = 64, go_name: str | None = None, label=None):
        SimTypeFloat.__init__(self, size, label)
        self._size = size
        self.go_name = go_name

    @property
    def size(self) -> int:
        assert self._size is not None
        return self._size

    @property
    def sort(self):
        return claripy.FSORT_DOUBLE if self._size == 64 else claripy.FSORT_FLOAT

    def _go_repr(self) -> str:
        return f"float{self.size}"

    def copy(self):
        return GoSimTypeFloat(self.size, self.go_name, self.label).with_arch(self._arch)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeFloat(self.size, self.go_name, self.label)
        out._arch = arch
        return out


#
# Pointers and arrays
#


class GoSimTypePointer(GoSimType, SimTypePointer):
    _ident = "go_ptr"
    _args = ("pts_to", "go_name", "label", "offset")

    def __init__(self, pts_to: SimType, go_name: str | None = None, label=None, offset: int = 0):
        SimTypePointer.__init__(self, pts_to, label, offset)
        self.go_name = go_name

    def _go_repr(self) -> str:
        pts_to = self.pts_to
        if pts_to is None or isinstance(pts_to, SimTypeBottom):
            return "unsafe.Pointer"
        return "*" + go_type_repr(pts_to)

    def to_json(self, fields=None, memo=None):
        if memo is None:
            memo = {}
        d = SimType.to_json(self, fields=fields, memo=memo)
        if d.get("offset") == 0:
            d.pop("offset")
        return d

    @property
    def size(self):
        if self._arch is None:
            raise ValueError("Can't tell my size without an arch!")
        return self._arch.bits

    def copy(self):
        return self.__class__(self.pts_to, go_name=self.go_name, label=self.label, offset=self.offset).with_arch(
            self._arch
        )

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = self.__class__(
            self.pts_to.with_arch(arch, memo=memo) if self.pts_to is not None else None,
            go_name=self.go_name,
            label=self.label,
            offset=self.offset,
        )
        out._arch = arch
        return out


class GoSimTypeUnsafePointer(GoSimTypePointer):
    _ident = "go_unsafe_ptr"
    _args = ("go_name", "label")

    def __init__(self, go_name: str | None = None, label=None, **kwargs):
        del kwargs
        super().__init__(SimTypeBottom(label="void"), go_name=go_name, label=label)

    def _go_repr(self) -> str:
        return "unsafe.Pointer"

    def copy(self):
        return GoSimTypeUnsafePointer(self.go_name, self.label).with_arch(self._arch)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeUnsafePointer(self.go_name, self.label)
        out.pts_to = out.pts_to.with_arch(arch)
        out._arch = arch
        return out


class GoSimTypeArray(GoSimType, SimTypeArray):
    """A fixed-size Go array ``[N]T``."""

    _ident = "go_array"
    _fields = ("elem_type", "length", "go_name")
    _args = ("elem_type", "length", "go_name", "label")

    def __init__(self, elem_type: SimType, length: int, go_name: str | None = None, label=None):
        SimTypeArray.__init__(self, elem_type, length, label)
        self.go_name = go_name

    def _go_repr(self) -> str:
        return f"[{self.length}]{go_type_repr(self.elem_type)}"

    def copy(self):
        return GoSimTypeArray(self.elem_type, self.length, self.go_name, self.label).with_arch(self._arch)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeArray(self.elem_type.with_arch(arch, memo=memo), self.length, self.go_name, self.label)
        out._arch = arch
        return out


#
# Structs and the struct-shaped builtins (string, slice, interface)
#


class GoSimStruct(GoSimType, SimStruct):
    """
    A Go struct. ``go_name`` is the qualified type name (``main.point``); anonymous structs have none. Field offsets
    and the total size may be pinned (``offsets``/``go_size``) when they come from a trusted source such as DWARF, so
    the layout never depends on angr's C-style alignment rules.
    """

    _ident = "go_struct"
    _fields = ("go_name", "fields")
    _args = ("fields", "go_name", "offsets", "go_size", "label")

    def __init__(
        self,
        fields: dict[str, SimType] | OrderedDict[str, SimType] | None = None,
        go_name: str | None = None,
        offsets: dict[str, int] | None = None,
        go_size: int | None = None,
        label=None,
    ):
        SimStruct.__init__(self, fields or OrderedDict(), name=go_name, anonymous=go_name is None)
        self.label = label
        self.go_name = go_name
        self._go_offsets: dict[str, int] | None = dict(offsets) if offsets else None
        self.go_size: int | None = go_size

    # keep .name (used throughout angr) and .go_name in sync
    @property
    def name(self) -> str:
        return self.go_name if self.go_name is not None else "<anon>"

    @name.setter
    def name(self, v):
        self.go_name = None if v in (None, "<anon>") else v
        self._name = v

    @property
    def offsets(self) -> dict[str, int]:
        if self._go_offsets is not None:
            return dict(self._go_offsets)
        return SimStruct.offsets.fget(self)  # type: ignore[misc]

    @offsets.setter
    def offsets(self, v):
        self._go_offsets = dict(v) if v else None

    @property
    def size(self):
        if self.go_size is not None:
            return self.go_size * (self._arch.byte_width if self._arch is not None else 8)
        if not self.fields:
            return 0
        size = SimStruct.size.fget(self)  # type: ignore[misc]
        if not size:
            return size
        assert self._arch is not None
        align = self.alignment * self._arch.byte_width
        if align and size % align:
            size += align - size % align
        return size

    @property
    def alignment(self):
        if self.go_size is not None and self._arch is not None:
            # a pinned layout was computed by the Go compiler; the largest field decides
            aligns = [f.alignment for f in self.fields.values() if f.size]
            return min(max(aligns) if aligns else 1, self._arch.bytes)
        return SimStruct.alignment.fget(self)  # type: ignore[misc]

    def _go_repr(self) -> str:
        if not self.fields:
            return "struct{}"
        return "struct { " + "; ".join(f"{k} {go_type_repr(v)}" for k, v in self.fields.items()) + " }"

    def go_definition_lines(self) -> list[str]:
        """Field lines of a ``type X struct { ... }`` definition."""
        return [f"{k} {go_type_repr(v)}" for k, v in self.fields.items()]

    def __repr__(self):
        return self.go_repr()

    def __hash__(self):
        return hash((self.__class__, self.go_name, tuple(self.fields.keys())))

    def _new_like(self) -> GoSimStruct:
        return self.__class__(OrderedDict(), go_name=self.go_name, offsets=self._go_offsets, go_size=self.go_size)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        key = self.go_name if self.go_name is not None else f"<anon:{id(self)}>"
        if key in memo:
            return cast(GoSimStruct, memo[key])
        out = self._new_like()
        out._arch = arch
        out.label = self.label
        memo[key] = out
        out.fields = OrderedDict((k, v.with_arch(arch, memo=memo)) for k, v in self.fields.items())
        return out

    def copy(self):
        out = self._new_like()
        out.fields = OrderedDict(self.fields)
        out.label = self.label
        return out.with_arch(self._arch)

    def to_json(self, fields=None, memo=None):
        if memo is None:
            memo = {}
        d = SimType.to_json(self, fields=fields, memo=memo)
        if d.get("offsets") is None:
            d.pop("offsets", None)
        if d.get("go_size") is None:
            d.pop("go_size", None)
        return d


class GoSimTypeString(GoSimStruct):
    _ident = "go_string"
    _args = ("go_name", "label")

    def __init__(self, go_name: str | None = None, label=None, **kwargs):
        del kwargs
        super().__init__(
            OrderedDict(
                [("ptr", GoSimTypePointer(GoSimTypeInt(8, False, "uint8"))), ("len", GoSimTypeInt(64, True, "int"))]
            ),
            label=label,
        )
        self.go_name = go_name
        self._name = "string"
        self.anonymous = False

    @property
    def name(self) -> str:
        return "string" if self.go_name is None else self.go_name

    @name.setter
    def name(self, v):
        self._name = v

    def _go_repr(self) -> str:
        return "string"

    def _new_like(self) -> GoSimStruct:
        return GoSimTypeString(go_name=self.go_name)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeString(go_name=self.go_name, label=self.label)
        out._arch = arch
        out.fields = OrderedDict((k, v.with_arch(arch, memo=memo)) for k, v in out.fields.items())
        return out


class GoSimTypeSlice(GoSimStruct):
    _ident = "go_slice"
    _fields = ("go_name", "elem_type")
    _args = ("elem_type", "go_name", "label")

    def __init__(self, elem_type: SimType, go_name: str | None = None, label=None, **kwargs):
        del kwargs
        self.elem_type = elem_type
        super().__init__(
            OrderedDict(
                [
                    ("ptr", GoSimTypePointer(elem_type)),
                    ("len", GoSimTypeInt(64, True, "int")),
                    ("cap", GoSimTypeInt(64, True, "int")),
                ]
            ),
            label=label,
        )
        self.go_name = go_name
        self._name = self._go_repr()
        self.anonymous = False

    @property
    def name(self) -> str:
        return self.go_repr()

    @name.setter
    def name(self, v):
        self._name = v

    def _go_repr(self) -> str:
        return "[]" + go_type_repr(self.elem_type)

    def __hash__(self):
        return hash((GoSimTypeSlice, self.go_name, hash(self.elem_type)))

    def _new_like(self) -> GoSimStruct:
        return GoSimTypeSlice(self.elem_type, go_name=self.go_name)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeSlice(self.elem_type.with_arch(arch, memo=memo), go_name=self.go_name, label=self.label)
        out._arch = arch
        out.fields = OrderedDict((k, v.with_arch(arch, memo=memo)) for k, v in out.fields.items())
        return out


class GoSimTypeInterface(GoSimStruct):
    """
    An interface value: an itab (or type) pointer and a data pointer. ``methods`` is a list of ``(name, func_type)``;
    the empty method set is ``any``.
    """

    _ident = "go_iface"
    _fields = ("go_name", "methods")
    _args = ("methods", "go_name", "label")

    def __init__(self, methods: list | None = None, go_name: str | None = None, label=None, **kwargs):
        del kwargs
        self.methods: list[tuple[str, SimType]] = [tuple(m) for m in methods] if methods else []
        super().__init__(
            OrderedDict([("tab", GoSimTypeUnsafePointer()), ("data", GoSimTypeUnsafePointer())]),
            label=label,
        )
        self.go_name = go_name
        self._name = self._go_repr()
        self.anonymous = False

    @property
    def name(self) -> str:
        return self.go_repr()

    @name.setter
    def name(self, v):
        self._name = v

    @property
    def is_empty(self) -> bool:
        return not self.methods

    def _go_repr(self) -> str:
        if not self.methods:
            return "any"
        return "interface { " + "; ".join(f"{n}{go_type_repr(t).removeprefix('func')}" for n, t in self.methods) + " }"

    def __hash__(self):
        return hash((GoSimTypeInterface, self.go_name, tuple(n for n, _ in self.methods)))

    def _new_like(self) -> GoSimStruct:
        return GoSimTypeInterface(list(self.methods), go_name=self.go_name)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        key = f"<iface:{self.go_name}>" if self.go_name is not None else f"<iface:{id(self)}>"
        if key in memo:
            return cast(GoSimTypeInterface, memo[key])
        out = GoSimTypeInterface([], go_name=self.go_name, label=self.label)
        out._arch = arch
        memo[key] = out
        out.methods = [(n, t.with_arch(arch, memo=memo)) for n, t in self.methods]
        out.fields = OrderedDict((k, v.with_arch(arch, memo=memo)) for k, v in out.fields.items())
        return out


class GoSimTypeTuple(GoSimStruct):
    """The result list of a function with more than one result, laid out like a struct."""

    _ident = "go_tuple"
    _fields = ("elems",)
    _args = ("elems", "names", "label")

    def __init__(self, elems: list[SimType], names: list[str] | None = None, label=None, **kwargs):
        del kwargs
        self.elems = list(elems)
        self.names = list(names) if names else [f"~r{i}" for i in range(len(self.elems))]
        super().__init__(OrderedDict(zip(self.names, self.elems)), label=label)
        self._name = self._go_repr()
        self.anonymous = False

    @property
    def name(self) -> str:
        return self.go_repr()

    @name.setter
    def name(self, v):
        self._name = v

    def _go_repr(self) -> str:
        return "(" + ", ".join(go_type_repr(e) for e in self.elems) + ")"

    def __hash__(self):
        return hash((GoSimTypeTuple, len(self.elems)))

    def _new_like(self) -> GoSimStruct:
        return GoSimTypeTuple(list(self.elems), list(self.names))

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeTuple([e.with_arch(arch, memo=memo) for e in self.elems], list(self.names), label=self.label)
        out._arch = arch
        return out


#
# Reference-shaped builtins (map, chan, func values)
#


class GoSimTypeMap(GoSimTypePointer):
    _ident = "go_map"
    _fields = ("key_type", "elem_type", "go_name")
    _args = ("key_type", "elem_type", "go_name", "label")

    def __init__(self, key_type: SimType, elem_type: SimType, go_name: str | None = None, label=None, **kwargs):
        del kwargs
        self.key_type = key_type
        self.elem_type = elem_type
        super().__init__(GoSimStruct(OrderedDict(), go_name="runtime.hmap"), go_name=go_name, label=label)

    def _go_repr(self) -> str:
        return f"map[{go_type_repr(self.key_type)}]{go_type_repr(self.elem_type)}"

    def copy(self):
        return GoSimTypeMap(self.key_type, self.elem_type, self.go_name, self.label).with_arch(self._arch)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeMap(
            self.key_type.with_arch(arch, memo=memo),
            self.elem_type.with_arch(arch, memo=memo),
            self.go_name,
            self.label,
        )
        out.pts_to = out.pts_to.with_arch(arch)
        out._arch = arch
        return out


class GoSimTypeChan(GoSimTypePointer):
    _ident = "go_chan"
    _fields = ("elem_type", "direction", "go_name")
    _args = ("elem_type", "direction", "go_name", "label")

    def __init__(self, elem_type: SimType, direction: str = "both", go_name: str | None = None, label=None, **kwargs):
        del kwargs
        self.elem_type = elem_type
        self.direction = direction  # "both", "send", "recv"
        super().__init__(GoSimStruct(OrderedDict(), go_name="runtime.hchan"), go_name=go_name, label=label)

    def _go_repr(self) -> str:
        elem = go_type_repr(self.elem_type)
        if self.direction == "send":
            return f"chan<- {elem}"
        if self.direction == "recv":
            return f"<-chan {elem}"
        return f"chan {elem}"

    def copy(self):
        return GoSimTypeChan(self.elem_type, self.direction, self.go_name, self.label).with_arch(self._arch)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeChan(self.elem_type.with_arch(arch, memo=memo), self.direction, self.go_name, self.label)
        out.pts_to = out.pts_to.with_arch(arch)
        out._arch = arch
        return out


class GoSimTypeFunction(GoSimType, SimTypeFunction):
    """
    A function signature: parameters (named) and results. More than one result is a ``GoSimTypeTuple`` return type
    so calling-convention code sees one struct-shaped value.
    """

    _ident = "go_func_sig"
    _args = ("args", "returnty", "go_name", "label", "arg_names", "variadic")

    def __init__(
        self,
        args,
        returnty: SimType | None,
        go_name: str | None = None,
        label=None,
        arg_names=None,
        variadic: bool = False,
    ):
        SimTypeFunction.__init__(self, args, returnty, label=label, arg_names=arg_names, variadic=variadic)
        self.go_name = go_name

    @property
    def results(self) -> list[SimType]:
        if self.returnty is None or isinstance(self.returnty, SimTypeBottom):
            return []
        if isinstance(self.returnty, GoSimTypeTuple):
            return list(self.returnty.elems)
        return [self.returnty]

    @property
    def result_names(self) -> list[str]:
        if isinstance(self.returnty, GoSimTypeTuple):
            return list(self.returnty.names)
        return ["~r0"] if self.results else []

    def go_results_repr(self) -> str:
        results = self.results
        if not results:
            return ""
        if len(results) == 1:
            return go_type_repr(results[0])
        return "(" + ", ".join(go_type_repr(r) for r in results) + ")"

    def _go_param_reprs(self) -> list[str]:
        reprs = [go_type_repr(a) for a in self.args]
        if self.variadic and reprs and isinstance(self.args[-1], GoSimTypeSlice):
            reprs[-1] = "..." + go_type_repr(self.args[-1].elem_type)
        return reprs

    def _go_repr(self) -> str:
        args = ", ".join(self._go_param_reprs())
        results = self.go_results_repr()
        return f"func({args})" + (f" {results}" if results else "")

    def repr(self, name=None, full=0, memo=None, indent: int | None = 0):
        if name:
            # declaration form with parameter names
            params = []
            for i, a in enumerate(self._go_param_reprs()):
                pname = self.arg_names[i] if i < len(self.arg_names) else ""
                params.append(f"{pname} {a}".strip())
            results = self.go_results_repr()
            return f"func {name}({', '.join(params)})" + (f" {results}" if results else "")
        return self.go_repr()

    def __hash__(self):
        return hash(type(self)) ^ hash(tuple(self.args)) ^ hash(self.returnty)

    def copy(self):
        return GoSimTypeFunction(
            self.args, self.returnty, self.go_name, self.label, self.arg_names, self.variadic
        ).with_arch(self._arch)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeFunction(
            [a.with_arch(arch, memo=memo) for a in self.args],
            self.returnty.with_arch(arch, memo=memo) if self.returnty is not None else None,
            self.go_name,
            self.label,
            self.arg_names,
            self.variadic,
        )
        out._arch = arch
        return out

    def to_json(self, fields=None, memo=None):
        if memo is None:
            memo = {}
        d = SimType.to_json(self, fields=fields, memo=memo)
        if d.get("variadic") is False:
            d.pop("variadic")
        return d


class GoSimTypeFunc(GoSimTypePointer):
    """A func *value*: a pointer to a closure whose first word is the code pointer."""

    _ident = "go_func"
    _fields = ("signature", "go_name")
    _args = ("signature", "go_name", "label")

    def __init__(self, signature: GoSimTypeFunction, go_name: str | None = None, label=None, **kwargs):
        del kwargs
        self.signature = signature
        super().__init__(GoSimStruct(OrderedDict(), go_name="runtime.funcval"), go_name=go_name, label=label)

    def _go_repr(self) -> str:
        return self.signature.go_repr()

    def copy(self):
        return GoSimTypeFunc(self.signature, self.go_name, self.label).with_arch(self._arch)

    def _with_arch(self, arch, *, memo: dict[str, SimType]):
        out = GoSimTypeFunc(
            cast(GoSimTypeFunction, self.signature.with_arch(arch, memo=memo)), self.go_name, self.label
        )
        out.pts_to = out.pts_to.with_arch(arch)
        out._arch = arch
        return out


#
# Helpers
#


def go_type_repr(ty: SimType | None) -> str:
    """Spell any SimType the Go way; non-Go SimTypes get a best-effort mapping."""
    if ty is None:
        return "any"
    if isinstance(ty, GoSimType):
        return ty.go_repr()
    # lazy import: the C-flavored fallback lives with the code generator
    from angr.analyses.decompiler.structured_codegen.go import go_type_str  # pylint:disable=import-outside-toplevel

    return go_type_str(ty)


def go_int(arch, size: int | None = None, signed: bool = True, go_name: str | None = None) -> GoSimTypeInt:
    size = arch.bits if size is None else size
    return GoSimTypeInt(size, signed, go_name).with_arch(arch)


PREDECLARED: dict[str, Any] = {
    "bool": lambda arch: GoSimTypeBool().with_arch(arch),
    "int": lambda arch: go_int(arch, None, True, "int"),
    "uint": lambda arch: go_int(arch, None, False, "uint"),
    "uintptr": lambda arch: go_int(arch, None, False, "uintptr"),
    "int8": lambda arch: go_int(arch, 8, True),
    "int16": lambda arch: go_int(arch, 16, True),
    "int32": lambda arch: go_int(arch, 32, True),
    "int64": lambda arch: go_int(arch, 64, True, "int64"),
    "uint8": lambda arch: go_int(arch, 8, False),
    "uint16": lambda arch: go_int(arch, 16, False),
    "uint32": lambda arch: go_int(arch, 32, False),
    "uint64": lambda arch: go_int(arch, 64, False, "uint64"),
    "byte": lambda arch: go_int(arch, 8, False, "byte"),
    "rune": lambda arch: go_int(arch, 32, True, "rune"),
    "float32": lambda arch: GoSimTypeFloat(32).with_arch(arch),
    "float64": lambda arch: GoSimTypeFloat(64).with_arch(arch),
    "complex64": lambda arch: GoSimStruct(
        OrderedDict([("real", GoSimTypeFloat(32)), ("imag", GoSimTypeFloat(32))]), go_name="complex64"
    ).with_arch(arch),
    "complex128": lambda arch: GoSimStruct(
        OrderedDict([("real", GoSimTypeFloat(64)), ("imag", GoSimTypeFloat(64))]), go_name="complex128"
    ).with_arch(arch),
    "string": lambda arch: GoSimTypeString().with_arch(arch),
    "unsafe.Pointer": lambda arch: GoSimTypeUnsafePointer().with_arch(arch),
    "any": lambda arch: GoSimTypeInterface().with_arch(arch),
    "interface{}": lambda arch: GoSimTypeInterface().with_arch(arch),
    "interface {}": lambda arch: GoSimTypeInterface().with_arch(arch),
    "error": lambda arch: GoSimTypeInterface(
        [("Error", GoSimTypeFunction([], GoSimTypeString()))], go_name="error"
    ).with_arch(arch),
}


_GO_SIMTYPE_CLASSES = [
    GoSimTypeInt,
    GoSimTypeBool,
    GoSimTypeFloat,
    GoSimTypePointer,
    GoSimTypeUnsafePointer,
    GoSimTypeArray,
    GoSimStruct,
    GoSimTypeString,
    GoSimTypeSlice,
    GoSimTypeInterface,
    GoSimTypeTuple,
    GoSimTypeMap,
    GoSimTypeChan,
    GoSimTypeFunction,
    GoSimTypeFunc,
]
for _cls in _GO_SIMTYPE_CLASSES:
    IDENT_TO_CLS[_cls._ident] = _cls

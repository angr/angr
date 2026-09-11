"""
Read Go function signatures and named types from the DWARF that ``cmd/compile``/``cmd/link`` emit.

Only compile units produced by ``Go cmd/compile`` are read. Type strings are taken from the Go-spelled
``DW_AT_name`` of the type DIEs and normalized to the canonical syntax of :mod:`angr.go.signature`.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import TYPE_CHECKING, Any

from elftools.common.exceptions import DWARFError, ELFError
from elftools.elf.elffile import ELFFile

from angr.go.signature import GoFuncSignature, GoNamedType, GoParam, GoSignatureSet, GoStructField, GoVariable

if TYPE_CHECKING:
    from elftools.dwarf.die import DIE
    from elftools.dwarf.dwarfinfo import DWARFInfo

    from angr.project import Project

log = logging.getLogger(__name__)

# Go-specific DWARF attributes (cmd/internal/dwarf). pyelftools keys unknown attributes by their numeric code.
DW_AT_GO_KIND = 0x2900
DW_AT_GO_KEY = 0x2901
DW_AT_GO_ELEM = 0x2902
DW_AT_GO_EMBEDDED_FIELD = 0x2903
DW_AT_GO_RUNTIME_TYPE = 0x2904
DW_AT_GO_PACKAGE_NAME = 0x2905
DW_AT_GO_DICT_INDEX = 0x2906
DW_AT_GO_CLOSURE_OFFSET = 0x2907

_GO_ATTR_KEYS: dict[int, tuple[Any, ...]] = {
    code: (code, f"DW_AT_go_{name}", f"DW_AT_unknown_{code:x}")
    for code, name in (
        (DW_AT_GO_KIND, "kind"),
        (DW_AT_GO_KEY, "key"),
        (DW_AT_GO_ELEM, "elem"),
        (DW_AT_GO_EMBEDDED_FIELD, "embedded_field"),
        (DW_AT_GO_RUNTIME_TYPE, "runtime_type"),
        (DW_AT_GO_PACKAGE_NAME, "package_name"),
        (DW_AT_GO_DICT_INDEX, "dict_index"),
        (DW_AT_GO_CLOSURE_OFFSET, "closure_offset"),
    )
}

# DW_AT_go_kind values (reflect.Kind)
KIND_BOOL = 1
KIND_INT = 2
KIND_INT8 = 3
KIND_INT16 = 4
KIND_INT32 = 5
KIND_INT64 = 6
KIND_UINT = 7
KIND_UINT8 = 8
KIND_UINT16 = 9
KIND_UINT32 = 10
KIND_UINT64 = 11
KIND_UINTPTR = 12
KIND_FLOAT32 = 13
KIND_FLOAT64 = 14
KIND_COMPLEX64 = 15
KIND_COMPLEX128 = 16
KIND_ARRAY = 17
KIND_CHAN = 18
KIND_FUNC = 19
KIND_INTERFACE = 20
KIND_MAP = 21
KIND_PTR = 22
KIND_SLICE = 23
KIND_STRING = 24
KIND_STRUCT = 25
KIND_UNSAFE_POINTER = 26

_BASIC_KIND_NAMES = {
    KIND_BOOL: "bool",
    KIND_INT: "int",
    KIND_INT8: "int8",
    KIND_INT16: "int16",
    KIND_INT32: "int32",
    KIND_INT64: "int64",
    KIND_UINT: "uint",
    KIND_UINT8: "uint8",
    KIND_UINT16: "uint16",
    KIND_UINT32: "uint32",
    KIND_UINT64: "uint64",
    KIND_UINTPTR: "uintptr",
    KIND_FLOAT32: "float32",
    KIND_FLOAT64: "float64",
    KIND_COMPLEX64: "complex64",
    KIND_COMPLEX128: "complex128",
    KIND_STRING: "string",
    KIND_UNSAFE_POINTER: "unsafe.Pointer",
}

_PREDECLARED = frozenset(_BASIC_KIND_NAMES.values()) | {"error", "any", "interface {}"}
_LITERAL_PREFIXES = (
    "*",
    "[",
    "map[",
    "chan ",
    "chan<-",
    "<-chan ",
    "func(",
    "struct {",
    "struct{",
    "interface {",
    "interface{",
)

_CU_RELATIVE_REF_FORMS = frozenset(
    {"DW_FORM_ref1", "DW_FORM_ref2", "DW_FORM_ref4", "DW_FORM_ref8", "DW_FORM_ref", "DW_FORM_ref_udata"}
)

_GOARCH_BY_ARCH = {
    "AMD64": "amd64",
    "X86": "386",
    "AARCH64": "arm64",
    "ARMEL": "arm",
    "ARMHF": "arm",
    "ARMCortexM": "arm",
    "PPC32": "ppc",
    "PPC64": "ppc64",
    "MIPS32": "mips",
    "MIPS64": "mips64",
    "S390X": "s390x",
    "RISCV64": "riscv64",
    "LoongArch64": "loong64",
}


def _to_str(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return str(v)


def _name(attrs: dict) -> str | None:
    a = attrs.get("DW_AT_name")
    return _to_str(a.value) if a is not None else None


def _go_attr(attrs: dict, code: int) -> Any:
    for key in _GO_ATTR_KEYS[code]:
        a = attrs.get(key)
        if a is not None:
            return a
    return None


def _ref_target(die: DIE, attr) -> int | None:
    """Absolute .debug_info offset referenced by a reference-class attribute."""
    if attr is None:
        return None
    if attr.form in _CU_RELATIVE_REF_FORMS:
        return die.cu.cu_offset + attr.raw_value
    if attr.form == "DW_FORM_ref_addr":
        return attr.raw_value
    return None


def _member_offset(attr) -> int:
    if attr is None:
        return 0
    v = attr.value
    if isinstance(v, int):
        return v
    # DW_OP_plus_uconst <uleb128>
    if isinstance(v, list) and v and v[0] == 0x23:
        result = shift = 0
        for b in v[1:]:
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        return result
    return 0


def _is_literal_type_name(name: str) -> bool:
    return name in _PREDECLARED or name.startswith(_LITERAL_PREFIXES)


def _split_receiver_prefix(type_str: str) -> str | None:
    """``*net/http.Server`` -> ``net/http.(*Server).``; ``main.T[go.shape.int]`` -> ``main.T[go.shape.int].``"""
    pointer = type_str.startswith("*")
    base = type_str[1:] if pointer else type_str
    if not base or base.startswith(_LITERAL_PREFIXES):
        return None
    head = base.split("[", 1)[0]
    dot = base.find(".", head.rfind("/") + 1)
    if dot <= 0:
        return None
    pkg, tname = base[:dot], base[dot + 1 :]
    return f"{pkg}.(*{tname})." if pointer else f"{pkg}.{tname}."


class _RawParam:
    __slots__ = ("is_result", "name", "type_offset")

    def __init__(self, name: str, is_result: bool, type_offset: int | None):
        self.name = name
        self.is_result = is_result
        self.type_offset = type_offset


class _GoDwarfReader:
    """
    Two passes: collect subprograms with raw type-DIE offsets, then resolve type strings and materialize every
    named type reachable from them.
    """

    def __init__(self, dwarf: DWARFInfo, ptr_size: int, memory=None, mem_delta: int = 0, little_endian: bool = True):
        self._dwarf = dwarf
        self._ptr = ptr_size
        self._memory = memory
        self._mem_delta = mem_delta
        self._endian = "<" if little_endian else ">"
        self._type_strs: dict[int, str] = {}
        self._pending: list[tuple[DIE, str, int | None]] = []
        self.go_version: str | None = None
        self.functions: dict[str, GoFuncSignature] = {}
        self.types: dict[str, GoNamedType] = {}
        self.runtime_types: dict[int, str] = {}
        self.variables: dict[str, GoVariable] = {}

    # ------------------------------------------------------------------ pass 1: functions

    def read(self) -> None:
        raw_funcs: list[tuple[str, list[_RawParam]]] = []
        for cu in self._dwarf.iter_CUs():
            top = cu.get_top_DIE()
            producer = _to_str(top.attributes["DW_AT_producer"].value) if "DW_AT_producer" in top.attributes else ""
            if not producer or not producer.startswith("Go cmd/compile"):
                continue
            if self.go_version is None:
                m = re.search(r"\bgo\d[\w.]*", producer)
                if m is not None:
                    self.go_version = m.group(0)
            self._collect_functions(cu, raw_funcs)
            self._collect_variables(cu)

        for name, params in raw_funcs:
            self._add_function(name, params)
        self._drain_types()

    def _collect_variables(self, cu) -> None:
        """Package-level variables: top-level DW_TAG_variable DIEs with a static address."""
        depth = 0
        for die in cu.iter_DIEs():
            tag = die.tag
            if tag is None:
                depth -= 1
                continue
            if depth == 1 and tag == "DW_TAG_variable":
                attrs = die.attributes
                name = _name(attrs)
                loc = attrs.get("DW_AT_location")
                if name and loc is not None and "DW_AT_type" in attrs and name not in self.variables:
                    addr = self._static_address(loc.value)
                    type_off = _ref_target(die, attrs["DW_AT_type"])
                    if addr is not None and type_off is not None:
                        self.variables[name] = GoVariable(name, addr + self._mem_delta, self.type_str(type_off))
            if die.has_children:
                depth += 1

    def _static_address(self, loc) -> int | None:
        """The address of a ``DW_OP_addr`` location expression, or None."""
        if isinstance(loc, (bytes, list, tuple)) and len(loc) == 1 + self._ptr and loc[0] == 0x03:
            return int.from_bytes(bytes(loc[1:]), "little" if self._endian == "<" else "big")
        return None

    def _collect_functions(self, cu, out: list[tuple[str, list[_RawParam]]]) -> None:
        depth = 0
        sub: DIE | None = None
        param_dies: list[DIE] = []
        for die in cu.iter_DIEs():
            tag = die.tag
            if tag is None:
                depth -= 1
                continue
            self._note_runtime_type(die)
            if depth == 1:
                if sub is not None:
                    self._finish_function(sub, param_dies, out)
                    sub = None
                if tag == "DW_TAG_subprogram" and "DW_AT_low_pc" in die.attributes:
                    sub = die
                    param_dies = []
            elif depth == 2 and sub is not None and tag == "DW_TAG_formal_parameter":
                param_dies.append(die)
            if die.has_children:
                depth += 1
        if sub is not None:
            self._finish_function(sub, param_dies, out)

    def _note_runtime_type(self, die: DIE) -> None:
        # type DIEs carry the location of their runtime descriptor (raw: resolved once all are known); the name is
        # already Go-spelled
        rt = _go_attr(die.attributes, DW_AT_GO_RUNTIME_TYPE)
        if rt is None or not rt.value:
            return
        name = _name(die.attributes)
        if name is not None:
            self.runtime_types.setdefault(rt.value, name)

    def _finish_function(self, die: DIE, param_dies: list[DIE], out: list[tuple[str, list[_RawParam]]]) -> None:
        attrs = die.attributes
        name = _name(attrs)
        if name is None:
            # out-of-line instance of an inlinable function: the name lives on the abstract DIE
            origin = self._origin(die)
            name = _name(origin.attributes) if origin is not None else None
            if name is None:
                return
        params: list[_RawParam] = []
        for pdie in param_dies:
            src = pdie
            pattrs = pdie.attributes
            if "DW_AT_type" not in pattrs:
                origin = self._origin(pdie)
                if origin is not None:
                    src = origin
                    pattrs = {**origin.attributes, **pattrs}
            vp = pattrs.get("DW_AT_variable_parameter")
            params.append(
                _RawParam(
                    _name(pattrs) or f"p{len(params)}",
                    bool(vp.value) if vp is not None else False,
                    _ref_target(src, pattrs.get("DW_AT_type")),
                )
            )
        out.append((name, params))

    def _origin(self, die: DIE) -> DIE | None:
        off = _ref_target(die, die.attributes.get("DW_AT_abstract_origin"))
        return self._die(off) if off is not None else None

    def _add_function(self, name: str, raw_params: list[_RawParam]) -> None:
        if name in self.functions:
            log.debug("Duplicate DWARF subprogram %s; keeping the first one", name)
            return
        params: list[GoParam] = []
        results: list[GoParam] = []
        for rp in raw_params:
            tstr = self.type_str(rp.type_offset) if rp.type_offset is not None else "unsafe.Pointer"
            (results if rp.is_result else params).append(GoParam(rp.name, tstr))
        recv = None
        if params:
            prefix = _split_receiver_prefix(params[0].type_str)
            if prefix is not None and name.startswith(prefix) and re.fullmatch(r"\w+", name[len(prefix) :]):
                recv = params.pop(0)
        self.functions[name] = GoFuncSignature(name, params=params, results=results, recv=recv)

    # ------------------------------------------------------------------ pass 2: types

    def _die(self, offset: int) -> DIE:
        return self._dwarf.get_DIE_from_refaddr(offset)

    def type_str(self, offset: int) -> str:
        s = self._type_strs.get(offset)
        if s is None:
            s = self._compute_type_str(self._die(offset))
            self._type_strs[offset] = s
        return s

    def _attr_type_str(self, die: DIE, attr, default: str = "unsafe.Pointer") -> str:
        off = _ref_target(die, attr)
        return self.type_str(off) if off is not None else default

    def _compute_type_str(self, die: DIE) -> str:
        attrs = die.attributes
        tag = die.tag
        name = _name(attrs)
        kind_attr = _go_attr(attrs, DW_AT_GO_KIND)
        kind = kind_attr.value if kind_attr is not None else None

        if kind is None:
            kind = self._kind_from_tag(die, name)
            if tag == "DW_TAG_typedef" and kind is None:
                # the declaration wrapper Go emits for every named type; it shares its name with the definition
                return self._attr_type_str(die, attrs.get("DW_AT_type"), default=name or "unsafe.Pointer")

        if name is not None:
            name = name.replace("interface {}", "any")
            if not _is_literal_type_name(name):
                return self._register_named(die, name, kind)

        if kind in _BASIC_KIND_NAMES:
            return _BASIC_KIND_NAMES[kind]
        if kind == KIND_INTERFACE:
            if name == "error":
                self._register_error()
                return "error"
            return name or "any"
        if kind == KIND_PTR:
            if name == "unsafe.Pointer":
                return name
            target = self._attr_type_str(die, attrs.get("DW_AT_type"))
            return name or ("*" + target)
        if kind == KIND_SLICE:
            elem = self._elem_type_str(die)
            return name or ("[]" + elem)
        if kind == KIND_ARRAY:
            elem = self._attr_type_str(die, attrs.get("DW_AT_type"))
            return name or f"[{self._array_count(die)}]{elem}"
        if kind == KIND_MAP:
            key = self._attr_type_str(die, _go_attr(attrs, DW_AT_GO_KEY))
            elem = self._attr_type_str(die, _go_attr(attrs, DW_AT_GO_ELEM))
            return name or f"map[{key}]{elem}"
        if kind == KIND_CHAN:
            elem = self._elem_type_str(die)
            return name or ("chan " + elem)
        if kind == KIND_FUNC:
            rebuilt = self._func_type_str(die)
            return name or rebuilt
        if kind == KIND_STRUCT:
            fields = self._struct_fields(die)
            return name or (
                "struct { " + "; ".join(f"{f.name} {f.type_str}" for f in fields) + " }" if fields else "struct {}"
            )
        log.debug("Unhandled Go DWARF type DIE %s (%s) at %#x", name, tag, die.offset)
        return name or "unsafe.Pointer"

    def _kind_from_tag(self, die: DIE, name: str | None) -> int | None:
        tag = die.tag
        if tag == "DW_TAG_base_type":
            return self._kind_from_encoding(die)
        if tag == "DW_TAG_pointer_type":
            return KIND_UNSAFE_POINTER if name == "unsafe.Pointer" else KIND_PTR
        if tag == "DW_TAG_structure_type":
            if name == "string":
                return KIND_STRING
            return KIND_SLICE if name is not None and name.startswith("[]") else KIND_STRUCT
        if tag == "DW_TAG_subroutine_type":
            return KIND_FUNC
        if tag == "DW_TAG_array_type":
            return KIND_ARRAY
        if tag == "DW_TAG_typedef" and name is not None:
            if name.startswith("map["):
                return KIND_MAP
            if name.startswith(("chan", "<-chan")):
                return KIND_CHAN
            if name.startswith("interface") or name in ("error", "any"):
                return KIND_INTERFACE
        return None

    @staticmethod
    def _kind_from_encoding(die: DIE) -> int | None:
        attrs = die.attributes
        enc = attrs["DW_AT_encoding"].value if "DW_AT_encoding" in attrs else None
        size = attrs["DW_AT_byte_size"].value if "DW_AT_byte_size" in attrs else None
        if enc == 2:  # boolean
            return KIND_BOOL
        if enc == 4:  # float
            return {4: KIND_FLOAT32, 8: KIND_FLOAT64}.get(size)
        if enc == 3:  # complex float
            return {8: KIND_COMPLEX64, 16: KIND_COMPLEX128}.get(size)
        if enc in (5, 6):  # signed
            return {1: KIND_INT8, 2: KIND_INT16, 4: KIND_INT32, 8: KIND_INT64}.get(size)
        if enc in (7, 8):  # unsigned
            return {1: KIND_UINT8, 2: KIND_UINT16, 4: KIND_UINT32, 8: KIND_UINT64}.get(size)
        return None

    def _register_named(self, die: DIE, name: str, kind: int | None) -> str:
        # cache before materializing so self-referential types terminate
        self._type_strs[die.offset] = name
        if name not in self.types:
            self.types[name] = GoNamedType(name, "named")  # placeholder until drained
            self._pending.append((die, name, kind))
        return name

    def _register_error(self) -> None:
        if "error" not in self.types:
            self.types["error"] = GoNamedType(
                "error", "interface", size=2 * self._ptr, align=self._ptr, methods=[("Error", "func() string")]
            )

    def _drain_types(self) -> None:
        while self._pending:
            die, name, kind = self._pending.pop()
            self.types[name] = self._materialize(die, name, kind)

    def _materialize(self, die: DIE, name: str, kind: int | None) -> GoNamedType:
        attrs = die.attributes
        size = attrs["DW_AT_byte_size"].value if "DW_AT_byte_size" in attrs else None
        if kind == KIND_STRUCT:
            fields = self._struct_fields(die)
            return GoNamedType(name, "struct", size=size, align=self._align(die, size), fields=fields)
        if kind == KIND_INTERFACE:
            size = 2 * self._ptr if size is None else size
            return GoNamedType(name, "interface", size=size, align=self._align(die, size))

        if kind in _BASIC_KIND_NAMES:
            underlying = _BASIC_KIND_NAMES[kind]
            if size is None:
                size = {KIND_STRING: 2 * self._ptr, KIND_UNSAFE_POINTER: self._ptr}.get(kind)
        elif kind == KIND_PTR:
            underlying = "*" + self._attr_type_str(die, attrs.get("DW_AT_type"))
            size = self._ptr
        elif kind == KIND_SLICE:
            underlying = "[]" + self._elem_type_str(die)
            size = 3 * self._ptr
        elif kind == KIND_ARRAY:
            underlying = f"[{self._array_count(die)}]{self._attr_type_str(die, attrs.get('DW_AT_type'))}"
        elif kind == KIND_MAP:
            key = self._attr_type_str(die, _go_attr(attrs, DW_AT_GO_KEY))
            underlying = f"map[{key}]{self._attr_type_str(die, _go_attr(attrs, DW_AT_GO_ELEM))}"
            size = self._ptr
        elif kind == KIND_CHAN:
            underlying = "chan " + self._elem_type_str(die)
            size = self._ptr
        elif kind == KIND_FUNC:
            underlying = self._func_type_str(die)
            size = self._ptr
        else:
            log.debug("Named Go type %s of unknown kind %s at %#x", name, kind, die.offset)
            underlying = "unsafe.Pointer"
        # generic shape types spell their underlying type in the name
        shape = name.removeprefix("go.shape.")
        if shape != name and _is_literal_type_name(shape):
            underlying = shape
        return GoNamedType(name, "named", size=size, align=self._align(die, size), underlying=underlying)

    def _align(self, die: DIE, size: int | None) -> int | None:
        a = die.attributes.get("DW_AT_alignment")
        if a is not None:
            return a.value
        if size is None:
            return None
        return max(1, min(size, self._ptr))

    def _struct_fields(self, die: DIE) -> list[GoStructField]:
        fields = []
        for child in die.iter_children():
            if child.tag != "DW_TAG_member":
                continue
            cattrs = child.attributes
            fields.append(
                GoStructField(
                    _name(cattrs) or f"_{len(fields)}",
                    self._attr_type_str(child, cattrs.get("DW_AT_type")),
                    _member_offset(cattrs.get("DW_AT_data_member_location")),
                )
            )
        return fields

    def _elem_type_str(self, die: DIE) -> str:
        attrs = die.attributes
        elem = _go_attr(attrs, DW_AT_GO_ELEM)
        if elem is not None:
            return self._attr_type_str(die, elem)
        # older DWARF without DW_AT_go_elem: slices carry an `array *T` member
        for child in die.iter_children():
            if child.tag == "DW_TAG_member" and _name(child.attributes) == "array":
                s = self._attr_type_str(child, child.attributes.get("DW_AT_type"))
                return s.removeprefix("*")
        return "unsafe.Pointer"

    @staticmethod
    def _array_count(die: DIE) -> int:
        for child in die.iter_children():
            if child.tag == "DW_TAG_subrange_type":
                cattrs = child.attributes
                if "DW_AT_count" in cattrs:
                    return cattrs["DW_AT_count"].value
                if "DW_AT_upper_bound" in cattrs:
                    return cattrs["DW_AT_upper_bound"].value + 1
        return 0

    def _func_type_str(self, die: DIE) -> str:
        ins: list[str] = []
        outs: list[str] = []
        flagged = False
        for child in die.iter_children():
            if child.tag != "DW_TAG_formal_parameter":
                continue
            t = self._attr_type_str(child, child.attributes.get("DW_AT_type"))
            vp = child.attributes.get("DW_AT_variable_parameter")
            if vp is not None:
                flagged = True
                (outs if vp.value else ins).append(t)
            else:
                ins.append(t)
        variadic = False
        if not flagged and ins:
            # go < 1.23 neither flags results nor types them directly (they point to the result type); the
            # in/out split comes from the runtime type descriptor
            counts = self._runtime_func_counts(die)
            if counts is not None and counts[0] + counts[1] == len(ins):
                ins, outs = ins[: counts[0]], [t.removeprefix("*") for t in ins[counts[0] :]]
                variadic = counts[2]
        if variadic and ins and ins[-1].startswith("[]"):
            ins[-1] = "..." + ins[-1][2:]
        s = "func(" + ", ".join(ins) + ")"
        if len(outs) == 1:
            s += " " + outs[0]
        elif outs:
            s += " (" + ", ".join(outs) + ")"
        return s

    def _runtime_func_counts(self, die: DIE) -> tuple[int, int, bool] | None:
        """(InCount, OutCount, variadic) from the internal/abi.FuncType descriptor at DW_AT_go_runtime_type."""
        rt = _go_attr(die.attributes, DW_AT_GO_RUNTIME_TYPE)
        if self._memory is None or rt is None or not rt.value:
            return None
        # abi.Type: Size_, PtrBytes, Hash(u32), 4 flag bytes, Equal, GCData, Str(i32), PtrToThis(i32)
        addr = rt.value + self._mem_delta + 4 * self._ptr + 16
        try:
            data = self._memory.load(addr, 4)
        except KeyError:
            return None
        if len(data) != 4:
            return None
        n_in, n_out = struct.unpack(self._endian + "HH", data)
        return n_in, n_out & 0x7FFF, bool(n_out & 0x8000)


def read_go_dwarf_signatures(project: Project) -> GoSignatureSet:
    """
    Read Go function signatures and named types from the DWARF of the main object. Returns an empty set when the
    binary has no DWARF or its DWARF was not produced by the Go toolchain.
    """
    obj = project.loader.main_object
    arch = project.arch
    sigs = GoSignatureSet(goarch=_goarch(arch))
    if not getattr(obj, "has_dwarf_info", False):
        return sigs

    # cle drops its ELFFile after loading, so re-open the binary; DWARF parsing is lazy
    elf = getattr(obj, "_reader", None)
    stream = None
    if elf is None:
        if obj.binary is None:
            return sigs
        stream = open(obj.binary, "rb")  # noqa: SIM115
        try:
            elf = ELFFile(stream)
        except ELFError:
            stream.close()
            return sigs
    try:
        try:
            dwarf = elf.get_dwarf_info()
        except (ELFError, DWARFError):
            log.warning("pyelftools failed to load the DWARF of %s", obj.binary_basename, exc_info=True)
            return sigs
        reader = _GoDwarfReader(
            dwarf,
            arch.bytes,
            memory=project.loader.memory,
            mem_delta=obj.mapped_base - obj.linked_base,
            little_endian=arch.memory_endness == "Iend_LE",
        )
        reader.read()
    finally:
        if stream is not None:
            stream.close()

    sigs.go_version = reader.go_version
    sigs.functions = reader.functions
    sigs.types = reader.types
    sigs.variables = reader.variables
    sigs.runtime_types = _resolve_runtime_types(project, reader.runtime_types)
    return sigs


def _resolve_runtime_types(project: Project, raw: dict[int, str]) -> dict[int, str]:
    """
    DW_AT_go_runtime_type is either an absolute descriptor address or, for most types, an offset into the
    ``runtime.types`` section; the section symbols tell the two apart.
    """
    obj = project.loader.main_object
    delta = obj.mapped_base - obj.linked_base
    types = project.loader.find_symbol("runtime.types")
    etypes = project.loader.find_symbol("runtime.etypes")
    base = types.rebased_addr if types is not None else None
    span = etypes.rebased_addr - base if base is not None and etypes is not None else 0
    resolved: dict[int, str] = {}
    for value, name in raw.items():
        if base is not None and value < span:
            addr = base + value
        elif project.loader.find_section_containing(value + delta) is not None:
            addr = value + delta
        else:
            continue
        resolved.setdefault(addr, name)
    return resolved


def _goarch(arch) -> str | None:
    goarch = _GOARCH_BY_ARCH.get(arch.name)
    if goarch in ("mips", "mips64", "ppc64") and arch.memory_endness == "Iend_LE":
        goarch += "le"
    return goarch

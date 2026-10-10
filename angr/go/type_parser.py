"""
Parse canonical Go type strings (see angr.go.signature) into Go SimTypes.
"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict
from collections.abc import Callable

from angr.go.signature import GoNamedType
from angr.go.sim_type import (
    PREDECLARED,
    GoSimStruct,
    GoSimTypeArray,
    GoSimTypeChan,
    GoSimTypeFunc,
    GoSimTypeFunction,
    GoSimTypeInterface,
    GoSimTypeMap,
    GoSimTypePointer,
    GoSimTypeSlice,
    GoSimTypeTuple,
)
from angr.sim_type import SimType

l = logging.getLogger(__name__)

_OPEN = {"[": "]", "(": ")", "{": "}"}
_CLOSE = {"]", ")", "}"}
_QUOTES = {'"', "`"}

# generic instantiations' shape types: go.shape.<underlying type>, or a hash when the spelling is too long
SHAPE_PREFIX = "go.shape."
_SHAPE_HASH = re.compile(r"[0-9a-f]{64}(?![\w.])")
# an interface method: optionally package-qualified (unexported) name, then its parameter list
_METHOD = re.compile(r"(?:[\w./-]+\.)?([A-Za-z_]\w*)\(")
_FIELD_NAMES = re.compile(r"([\w./-]+(?:\s*,\s*[\w./-]+)+)\s+(.+)$", re.DOTALL)
_TYPE_KEYWORDS = ("struct", "interface", "func", "map", "chan")


class GoTypeParseError(ValueError):
    """A malformed Go type string."""


class GoTypeParser:
    """
    Recursive-descent parser for Go type strings. ``resolver`` maps a qualified type name to its GoNamedType record
    (from a signature database or DWARF); unknown names become opaque structs.
    """

    def __init__(self, arch, resolver: Callable[[str], GoNamedType | None] | None = None):
        self.arch = arch
        self.resolver = resolver
        self._named: dict[str, SimType] = {}

    #
    # Public API
    #

    def parse(self, s: str) -> SimType:
        ty, pos = self._parse_type(s.strip(), 0)
        rest = s.strip()[pos:].strip()
        if rest:
            raise GoTypeParseError(f"trailing text {rest!r} in {s!r}")
        return ty.with_arch(self.arch)

    def parse_signature(self, params: list[str], results: list[str], arg_names: list[str] | None = None):
        """Build a function type from parameter and result type strings."""
        args = [self.parse(p) for p in params]
        return_types = [self.parse(r) for r in results]
        if not return_types:
            returnty = None
        elif len(return_types) == 1:
            returnty = return_types[0]
        else:
            returnty = GoSimTypeTuple(return_types)
        return GoSimTypeFunction(args, returnty, arg_names=arg_names).with_arch(self.arch)

    #
    # Named types
    #

    # the runtime's itab struct, by the name each Go version gives it (go1.22+ moved it into internal/abi)
    ITAB_NAMES = ("internal/abi.ITab", "runtime.itab")
    TYPE_NAMES = ("internal/abi.Type", "runtime._type")

    def resolve_named(self, name: str) -> SimType:
        if name in self._named:
            return self._named[name]
        if name in PREDECLARED:
            ty = PREDECLARED[name](self.arch)
            self._named[name] = ty
            if isinstance(ty, GoSimTypeInterface):
                self._type_itab_word(ty)
            return ty

        record = self.resolver(name) if self.resolver is not None else None
        if record is None:
            ty = GoSimStruct(OrderedDict(), go_name=name).with_arch(self.arch)
            self._named[name] = ty
            return ty

        if record.kind == "struct":
            # register before parsing fields so self-referential types terminate
            st = GoSimStruct(OrderedDict(), go_name=name, go_size=record.size).with_arch(self.arch)
            self._named[name] = st
            fields = OrderedDict()
            offsets = {}
            for f in record.fields:
                fname = f.name or _embedded_field_name(f.type_str)
                if fname in fields:
                    fname = f"{fname}_{f.offset:x}" if f.offset is not None else f"{fname}_{len(fields)}"
                fields[fname] = self._safe_parse(f.type_str)
                offsets[fname] = f.offset
            st.fields = OrderedDict((k, v.with_arch(self.arch)) for k, v in fields.items())
            if all(off is not None for off in offsets.values()):
                st.offsets = offsets
            return st

        if record.kind == "interface":
            iface = GoSimTypeInterface([], go_name=name).with_arch(self.arch)
            self._named[name] = iface
            iface.methods = [(mname, self._safe_parse(mtype)) for mname, mtype in record.methods]
            self._type_itab_word(iface)
            return iface

        # kind == "named": the underlying type with a new name
        underlying = self._safe_parse(record.underlying or "int")
        ty = underlying.copy()
        ty.go_name = name
        if isinstance(ty, GoSimStruct):
            ty.name = name
        ty = ty.with_arch(self.arch)
        self._named[name] = ty
        return ty

    def _safe_parse(self, s: str) -> SimType:
        try:
            return self.parse(s)
        except GoTypeParseError as e:
            l.warning("Cannot parse Go type %r: %s", s, e)
            return GoSimStruct(OrderedDict(), go_name=s).with_arch(self.arch)

    #
    # Recursive descent
    #

    def _parse_type(self, s: str, pos: int) -> tuple[SimType, int]:
        pos = _skip_ws(s, pos)
        if pos >= len(s):
            raise GoTypeParseError("unexpected end of type")

        if s.startswith(SHAPE_PREFIX, pos):
            return self._parse_shape(s, pos)

        if s.startswith("*", pos):
            inner, pos = self._parse_type(s, pos + 1)
            return GoSimTypePointer(inner), pos

        if s.startswith("[", pos):
            close = s.index("]", pos)
            dim = s[pos + 1 : close].strip()
            elem, pos = self._parse_type(s, close + 1)
            if dim in ("", "..."):
                return GoSimTypeSlice(elem), pos
            try:
                return GoSimTypeArray(elem, int(dim, 0)), pos
            except ValueError as e:
                raise GoTypeParseError(f"bad array length {dim!r}") from e

        if s.startswith("map[", pos):
            key_start = pos + 4
            key_end = _match_bracket(s, pos + 3)
            key = self.parse(s[key_start:key_end])
            elem, pos = self._parse_type(s, key_end + 1)
            return GoSimTypeMap(key, elem), pos

        if s.startswith("chan<- ", pos):
            elem, pos = self._parse_type(s, pos + 7)
            return GoSimTypeChan(elem, "send"), pos
        if s.startswith("<-chan ", pos):
            elem, pos = self._parse_type(s, pos + 7)
            return GoSimTypeChan(elem, "recv"), pos
        if s.startswith("chan ", pos):
            elem, pos = self._parse_type(s, pos + 5)
            return GoSimTypeChan(elem, "both"), pos

        if s.startswith("func(", pos):
            sig, pos = self._parse_func(s, pos + 4)
            return GoSimTypeFunc(sig), pos

        if s.startswith("struct", pos) and _next_nonws(s, pos + 6) == "{":
            return self._parse_struct(s, s.index("{", pos))

        if s.startswith("interface", pos) and _next_nonws(s, pos + 9) == "{":
            return self._parse_interface(s, s.index("{", pos))

        # a (possibly qualified, possibly instantiated) type name
        end = _scan_name(s, pos)
        name = s[pos:end]
        if not name:
            raise GoTypeParseError(f"cannot parse {s[pos:]!r}")
        return self.resolve_named(name), end

    def _parse_func(self, s: str, pos: int) -> tuple[GoSimTypeFunction, int]:
        """``pos`` points at the opening parenthesis of the parameter list."""
        close = _match_bracket(s, pos)
        params = _split_top_level(s[pos + 1 : close], ",")
        args = []
        variadic = False
        for p in params:
            p = _strip_param_name(p)
            if p.startswith("..."):
                variadic = True
                args.append(GoSimTypeSlice(self.parse(p[3:])))
            else:
                args.append(self.parse(p))
        pos = _skip_ws(s, close + 1)
        results: list[SimType] = []
        if pos < len(s) and s[pos] == "(":
            rclose = _match_bracket(s, pos)
            results = [self.parse(_strip_param_name(r)) for r in _split_top_level(s[pos + 1 : rclose], ",")]
            pos = rclose + 1
        elif pos < len(s) and s[pos] not in {",", ";", ")", "]", "}"}:
            ty, pos = self._parse_type(s, pos)
            results = [ty]
        returnty: SimType | None
        if not results:
            returnty = None
        elif len(results) == 1:
            returnty = results[0]
        else:
            returnty = GoSimTypeTuple(results)
        return GoSimTypeFunction(args, returnty, variadic=variadic), pos

    def _parse_shape(self, s: str, pos: int) -> tuple[SimType, int]:
        """
        ``go.shape.T``: a shape stands for its underlying type ``T``, which may be any type literal. Struct shapes take
        their layout from a source that describes them (DWARF, type descriptors); hash-named shapes stay named.
        """
        start = pos + len(SHAPE_PREFIX)
        m = _SHAPE_HASH.match(s, start)
        if m is not None:
            return self.resolve_named(s[pos : m.end()]), m.end()
        underlying, end = self._parse_type(s, start)
        name = s[pos:end]
        if name in self._named:
            return self._named[name], end
        record = self.resolver(name) if self.resolver is not None else None
        if record is not None and record.kind == "struct" and record.fields:
            described = self.resolve_named(name)
            assert isinstance(described, GoSimStruct)
            ty: SimType = GoSimStruct(
                OrderedDict(described.fields), offsets=described._go_offsets, go_size=described.go_size
            ).with_arch(self.arch)
        else:
            ty = underlying
        self._named[name] = ty
        return ty, end

    def _parse_struct(self, s: str, pos: int) -> tuple[GoSimStruct, int]:
        close = _match_bracket(s, pos)
        fields = OrderedDict()
        for item in _split_top_level(s[pos + 1 : close], ";"):
            item = _strip_tag(item)
            if not item:
                continue
            for fname, ty in self._struct_fields(item):
                if fname in fields:
                    fname = f"{fname}_{len(fields)}"
                fields[fname] = ty
        return GoSimStruct(fields), close + 1

    def _struct_fields(self, item: str) -> list[tuple[str, SimType]]:
        """
        One struct field declaration: ``name T``, ``a, b T``, an embedded ``T`` / ``*T``, or ``name = T`` (an embedded
        generic type). Shape spellings qualify unexported field names with their package path; the name is kept.
        """
        m = _FIELD_NAMES.match(item)
        if m is not None:
            ty = self.parse(m.group(2))
            return [(_unqualify(n.strip()), ty) for n in m.group(1).split(",")]
        head_end = _scan_name(item, 0)
        head, rest = item[:head_end], item[head_end:].strip()
        if rest.startswith("="):
            return [(_unqualify(head), self.parse(rest[1:]))]
        if not rest or "[" in head or head[:1] in "*[<(" or head.startswith(_TYPE_KEYWORDS):
            return [(_embedded_field_name(item), self.parse(item))]
        return [(_unqualify(head), self.parse(rest))]

    def _parse_interface(self, s: str, pos: int) -> tuple[GoSimTypeInterface, int]:
        close = _match_bracket(s, pos)
        methods = []
        for item in _split_top_level(s[pos + 1 : close], ";"):
            item = item.strip()
            if not item:
                continue
            m = _METHOD.match(item)
            if m is None:
                # embedded interface: splice its methods in
                embedded = self.parse(item)
                if isinstance(embedded, GoSimTypeInterface):
                    methods.extend(embedded.methods)
                continue
            sig, _ = self._parse_func(item, m.end() - 1)
            methods.append((m.group(1), sig))
        iface = GoSimTypeInterface(methods).with_arch(self.arch)
        self._type_itab_word(iface)
        return iface, close + 1

    def itab_type(self) -> SimType | None:
        """The runtime's itab struct as the binary describes it, or None."""
        return self._runtime_struct(self.ITAB_NAMES)

    def type_descriptor_type(self) -> SimType | None:
        """The runtime's type descriptor struct as the binary describes it, or None."""
        return self._runtime_struct(self.TYPE_NAMES)

    def _runtime_struct(self, names: tuple[str, ...]) -> SimType | None:
        """The first of the runtime structs the binary describes (by any of its spellings)."""
        if self.resolver is None:
            return None
        for name in names:
            if name in self._named or self.resolver(name) is not None:
                ty = self.resolve_named(name)
                if isinstance(ty, GoSimStruct) and ty.fields:
                    return ty
        return None

    def _type_itab_word(self, iface: GoSimTypeInterface) -> None:
        """
        The first word of an interface value points at the runtime's itab (``internal/abi.ITab``, ``runtime.itab``
        before go1.22), or at the type descriptor for an empty interface: reads through it name the itab's fields
        (``Type``, ``Hash``, ``Fun``) instead of raw offsets.
        """
        target = self._runtime_struct(self.TYPE_NAMES if iface.is_empty else self.ITAB_NAMES)
        if target is None:
            return
        iface.fields["tab"] = GoSimTypePointer(target).with_arch(self.arch)


#
# String scanning helpers
#


def _skip_ws(s: str, pos: int) -> int:
    while pos < len(s) and s[pos] == " ":
        pos += 1
    return pos


def _next_nonws(s: str, pos: int) -> str:
    pos = _skip_ws(s, pos)
    return s[pos] if pos < len(s) else ""


def _skip_string(s: str, pos: int) -> int:
    """Index just past the string literal (a struct tag) starting at ``pos``."""
    quote = s[pos]
    i = pos + 1
    while i < len(s):
        c = s[i]
        if c == "\\" and quote == '"':
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    raise GoTypeParseError(f"unterminated string in {s!r}")


def _match_bracket(s: str, pos: int) -> int:
    """Index of the bracket closing the one at ``pos``."""
    stack = [_OPEN[s[pos]]]
    i = pos + 1
    while i < len(s):
        c = s[i]
        if c in _QUOTES:
            i = _skip_string(s, i)
            continue
        if c in _OPEN:
            stack.append(_OPEN[c])
        elif c in _CLOSE:
            if c != stack.pop():
                raise GoTypeParseError(f"mismatched bracket in {s!r}")
            if not stack:
                return i
        i += 1
    raise GoTypeParseError(f"unbalanced bracket in {s!r}")


def _split_top_level(s: str, sep: str) -> list[str]:
    parts = []
    depth = 0
    start = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c in _QUOTES:
            i = _skip_string(s, i)
            continue
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth -= 1
        elif c == sep and depth == 0:
            parts.append(s[start:i].strip())
            start = i + 1
        i += 1
    tail = s[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _scan_name(s: str, pos: int) -> int:
    """End of a qualified type name, including a balanced generic instantiation suffix."""
    i = pos
    while i < len(s):
        c = s[i]
        if c == "[":
            i = _match_bracket(s, i) + 1
            continue
        if c in " ,;)]}":
            break
        i += 1
    return i


def _strip_param_name(p: str) -> str:
    """Signatures may spell ``name type``; type strings never do. Keep the type."""
    p = p.strip()
    if " " not in p or p.startswith(("func(", "struct", "interface", "map[", "chan ", "chan<- ", "<-chan ")):
        return p
    head, _, rest = p.partition(" ")
    if head.startswith(("*", "[", "...")) or "." in head or "[" in head:
        return p
    return rest.strip()


def _strip_tag(s: str) -> str:
    """Drop a trailing struct tag (an interpreted or raw string literal)."""
    s = s.strip()
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c in _QUOTES:
            end = _skip_string(s, i)
            if depth == 0 and end == len(s) and i > 0:
                return s[:i].strip()
            i = end
            continue
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth -= 1
        i += 1
    return s


def _unqualify(name: str) -> str:
    """``archive/zip.name`` -> ``name``: shape spellings qualify unexported names with their package path."""
    return name.rsplit(".", 1)[-1]


def _embedded_field_name(type_str: str) -> str:
    base = type_str.lstrip("*")
    if "[" in base:
        base = base[: base.index("[")]
    return base.rsplit(".", 1)[-1]

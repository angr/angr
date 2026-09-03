"""
Parse canonical Go type strings (see angr.go.signature) into Go SimTypes.
"""

from __future__ import annotations

import logging
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


class GoTypeParseError(ValueError):
    pass


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

    def resolve_named(self, name: str) -> SimType:
        if name in self._named:
            return self._named[name]
        if name in PREDECLARED:
            ty = PREDECLARED[name](self.arch)
            self._named[name] = ty
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
                    fname = f"{fname}_{f.offset:x}"
                fields[fname] = self._safe_parse(f.type_str)
                offsets[fname] = f.offset
            st.fields = OrderedDict((k, v.with_arch(self.arch)) for k, v in fields.items())
            st.offsets = offsets
            return st

        if record.kind == "interface":
            iface = GoSimTypeInterface([], go_name=name).with_arch(self.arch)
            self._named[name] = iface
            iface.methods = [(mname, self._safe_parse(mtype)) for mname, mtype in record.methods]
            return iface

        # kind == "named": the underlying type with a new name
        underlying = self._safe_parse(record.underlying or "int")
        ty = underlying.copy() if hasattr(underlying, "copy") else underlying
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

        if s.startswith("*", pos):
            inner, pos = self._parse_type(s, pos + 1)
            return GoSimTypePointer(inner), pos

        if s.startswith("[", pos):
            close = s.index("]", pos)
            dim = s[pos + 1 : close].strip()
            elem, pos = self._parse_type(s, close + 1)
            if dim == "" or dim == "...":
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

    def _parse_struct(self, s: str, pos: int) -> tuple[GoSimStruct, int]:
        close = _match_bracket(s, pos)
        fields = OrderedDict()
        for item in _split_top_level(s[pos + 1 : close], ";"):
            item = item.strip()
            if not item:
                continue
            name, _, rest = item.partition(" ")
            if not rest or name in {"struct", "interface", "func", "map", "chan"} or name[0] in "*[<":
                # embedded field: only a type
                ty = self.parse(item)
                fname = _embedded_field_name(item)
            else:
                # drop a trailing tag string if present
                ty = self.parse(_strip_tag(rest))
                fname = name
            fields[fname] = ty
        return GoSimStruct(fields), close + 1

    def _parse_interface(self, s: str, pos: int) -> tuple[GoSimTypeInterface, int]:
        close = _match_bracket(s, pos)
        methods = []
        for item in _split_top_level(s[pos + 1 : close], ";"):
            item = item.strip()
            if not item:
                continue
            paren = item.find("(")
            if paren <= 0:
                # embedded interface: splice its methods in
                embedded = self.parse(item)
                if isinstance(embedded, GoSimTypeInterface):
                    methods.extend(embedded.methods)
                continue
            name = item[:paren]
            sig, _ = self._parse_func(item, paren)
            methods.append((name, sig))
        return GoSimTypeInterface(methods), close + 1


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


def _match_bracket(s: str, pos: int) -> int:
    """Index of the bracket closing the one at ``pos``."""
    stack = [_OPEN[s[pos]]]
    i = pos + 1
    while i < len(s):
        c = s[i]
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
    cur = []
    for c in s:
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    tail = "".join(cur).strip()
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
    s = s.strip()
    if s.endswith(("`", '"')):
        quote = s[-1]
        start = s.rfind(quote, 0, len(s) - 1)
        if start > 0:
            return s[:start].strip()
    return s


def _embedded_field_name(type_str: str) -> str:
    base = type_str.lstrip("*")
    if "[" in base:
        base = base[: base.index("[")]
    return base.rsplit(".", 1)[-1]

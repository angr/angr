"""KnownPattern: declarative metadata around a pattern-AST.

A :class:`KnownPattern` couples a structural pattern (see :mod:`.dsl`) with the
information needed to turn a match into a synthesized call: the call name, the
ordered parameters (mapping captures to call arguments and types), the return
type, and applicability guards.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from angr.ailment.expression import Call, Const
from angr.errors import AngrMissingTypeError
from angr.procedures.definitions import SIM_TYPE_COLLECTIONS
from angr.sim_type import SimType, SimTypeFunction, SimTypePointer, parse_type

from .dsl import PatternExpr, PatternStmt, PGraphPat

if TYPE_CHECKING:
    import archinfo

    from angr.ailment.expression import Expression
    from angr.project import Project


@dataclass(frozen=True)
class CppRef:
    """A reference to a C++ class type registered in the ``cpp::std``
    SimTypeCollection, keyed by its unique (mangled-style) name."""

    unique_name: str
    ptr: bool = True  # wrap in SimTypePointer

    def resolve(self, arch: archinfo.Arch) -> SimType | None:
        try:
            ty = SIM_TYPE_COLLECTIONS["cpp::std"].get(self.unique_name)
        except AngrMissingTypeError:
            return None
        ty = ty.with_arch(arch)
        if self.ptr:
            ty = SimTypePointer(ty).with_arch(arch)
        return ty


TypeRef = str | CppRef


def resolve_typeref(ref: TypeRef | None, arch: archinfo.Arch) -> SimType | None:
    """Resolve a TypeRef into a SimType: a C declaration string is parsed with
    ``parse_type``; a CppRef is looked up in the cpp::std collection."""
    if ref is None:
        return None
    if isinstance(ref, CppRef):
        return ref.resolve(arch)
    return parse_type(ref).with_arch(arch)


@dataclass(frozen=True)
class PatternParam:
    """One parameter of the synthesized call.

    :ivar capture:   Name of the pattern capture bound to this parameter.
    :ivar type:      Argument type for the synthesized call's prototype; flows
                     into Typehoon as a per-argument subtype constraint.
    :ivar type_hint: Optional cpp::std unique name emitted as a direct vvar
                     type hint (for by-value captures where the vvar *is* the
                     object rather than a pointer to it).
    """

    capture: str
    type: TypeRef | None = None
    type_hint: str | None = None


@dataclass(frozen=True)
class KnownPattern:
    """A known code idiom, described declaratively.

    :ivar name:               Identifier, e.g. ``"std_string_length"``.
    :ivar display_name:       Human-readable name, e.g. ``"std::string::length"``.
    :ivar call_name:          Target name of the synthesized Call.
    :ivar pattern:            The structural pattern to match.
    :ivar params:             Ordered parameters; their captures become the call
                              arguments, in order.
    :ivar returnty:           Return type of the synthesized call.
    :ivar returnty_factory:   Optional callable building a call-site-specific
                              return type from the values of the constant
                              ``extra_args`` captures (e.g. CONTAINING_RECORD
                              returns a pointer to a record whose layout
                              depends on the matched field offset). Falls back
                              to ``returnty`` when it returns None or when the
                              constant values are unavailable.
    :ivar extra_args:         Names of (typically constant) captures appended to
                              the call arguments after ``params``.
    :ivar arches:             Allowed ``archinfo.Arch.name`` values; None = any.
    :ivar platforms:          Allowed OS names (``project.simos.name``,
                              lowercased); None = any.
    :ivar where:              Optional cross-capture predicate evaluated on the
                              bindings after a structural match.
    :ivar binary_guard:       Optional predicate on the Project; the pattern is
                              only used when it returns True (e.g. require C++
                              evidence for STL patterns to avoid false
                              positives on plain C binaries).
    :ivar enabled_by_default: Whether the pattern is used when the caller does
                              not explicitly select patterns. Generic patterns
                              prone to false positives should set this False.
    """

    name: str
    display_name: str
    call_name: str
    pattern: PatternExpr | PatternStmt | PGraphPat
    params: tuple[PatternParam, ...]
    returnty: TypeRef | None = None
    returnty_factory: Callable[[archinfo.Arch, dict[str, int]], SimType | None] | None = None
    extra_args: tuple[str, ...] = ()
    arches: tuple[str, ...] | None = None
    platforms: tuple[str, ...] | None = None
    where: Callable[[dict[str, Expression]], bool] | None = None
    binary_guard: Callable[[Project], bool] | None = None
    enabled_by_default: bool = True

    def applicable(self, arch_name: str, platform: str | None) -> bool:
        if self.arches is not None and arch_name not in self.arches:
            return False
        return not (self.platforms is not None and (platform is None or platform.lower() not in self.platforms))

    def const_args_of_call(self, call: Call) -> dict[str, int] | None:
        """Recover the ``extra_args`` constant values from a synthesized call's
        trailing arguments. Returns None when the call does not carry them."""
        if not self.extra_args:
            return {}
        args = call.args
        if args is None or len(args) != len(self.params) + len(self.extra_args):
            return None
        const_args: dict[str, int] = {}
        for name, arg in zip(self.extra_args, args[len(self.params) :]):
            if not isinstance(arg, Const) or not isinstance(arg.value, int):
                return None
            const_args[name] = arg.value
        return const_args

    def prototype(self, arch: archinfo.Arch, const_args: dict[str, int] | None = None) -> SimTypeFunction | None:
        """Build the synthesized call's prototype. ``const_args`` (the values of
        the constant ``extra_args`` captures, see :meth:`const_args_of_call`)
        enables call-site-specific return types via ``returnty_factory``.
        Returns None if any declared type fails to resolve."""
        args = []
        for param in self.params:
            ty = resolve_typeref(param.type, arch)
            if ty is None and param.type is not None:
                return None
            if ty is None:
                ty = parse_type("void *").with_arch(arch)
            args.append(ty)
        for _ in self.extra_args:
            args.append(parse_type("unsigned long long").with_arch(arch))
        returnty: SimType | None = None
        if self.returnty_factory is not None and const_args is not None:
            returnty = self.returnty_factory(arch, const_args)
        if returnty is None:
            returnty = resolve_typeref(self.returnty, arch)
            if returnty is None and self.returnty is not None:
                return None
        return SimTypeFunction(args, returnty).with_arch(arch)

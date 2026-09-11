"""KnownPatternTemplate: a single, context-parameterized definition of an
idiom that instantiates itself into a concrete :class:`KnownPattern` for a
target's :class:`PatternContext`.

One template replaces the per-architecture / per-runtime copies of a pattern:
its ``build(ctx)`` computes the concrete field offsets, load sizes, and return
types from the context, so the same definition covers 32- and 64-bit,
libstdc++ and MSVC, and so on.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context import PatternContext
    from .gating import GateContext, PatternGate
    from .pattern import KnownPattern


@dataclass(frozen=True)
class KnownPatternTemplate:
    """A context-aware pattern definition.

    :ivar call_name:          The synthesized call name (unique across templates).
    :ivar build:              ``build(ctx) -> KnownPattern | None`` — emits the
                              concrete pattern for ``ctx`` (None if it cannot).
    :ivar arches:             Allowed ``Arch.name`` values; None = any.
    :ivar languages:          Allowed languages ({"c","cpp"}); None = any.
    :ivar runtimes:           Allowed C++ runtimes ({"libstdcxx","msvc"});
                              None = any.
    :ivar platforms:          Allowed platforms ({"linux","windows"});
                              None = any.
    :ivar enabled_by_default: Whether the template is used when the caller does
                              not explicitly select patterns.
    :ivar gate:               Optional :class:`~.gating.PatternGate` that turns
                              an opt-in template on for targets (or functions)
                              where the evidence says the idiom is real — see
                              :mod:`.gating`. A gate can only open a template,
                              never close a default-on one.
    """

    call_name: str
    build: Callable[[PatternContext], KnownPattern | None]
    arches: frozenset[str] | None = None
    languages: frozenset[str] | None = None
    runtimes: frozenset[str] | None = None
    platforms: frozenset[str] | None = None
    enabled_by_default: bool = True
    # human label, defaults to call_name
    name: str = ""
    gate: PatternGate | None = None
    #: Per-context memo of :meth:`instantiate`. Building the library costs ~9 ms
    #: on a C++ target -- four figures of templates, most of them the generated
    #: std::vector set -- and it was rebuilt for every function, twice (the
    #: optimization pass's applicability check and the finder itself) and again
    #: for every extra matching round. The memo lives on the template rather
    #: than in a lookup keyed by name, because names are not unique among
    #: templates built on the fly.
    _cache: dict = field(default_factory=dict, compare=False, repr=False, hash=False)

    def enabled_for(self, gate_ctx: GateContext) -> bool:
        """Whether this template is on for the given target/function, taking the
        default flag and the gate (but not an explicit user selection) into
        account."""
        if self.enabled_by_default:
            return True
        return self.gate is not None and self.gate(gate_ctx)

    def applicable(self, ctx: PatternContext) -> bool:
        if self.arches is not None and ctx.arch_name not in self.arches:
            return False
        if self.languages is not None and ctx.language not in self.languages:
            return False
        if self.runtimes is not None and ctx.cxx_runtime not in self.runtimes:
            return False
        return not (self.platforms is not None and (ctx.platform is None or ctx.platform not in self.platforms))

    def instantiate(self, ctx: PatternContext) -> KnownPattern | None:
        """The concrete pattern for ``ctx``, or None if this template does not
        apply there. Memoized: a KnownPattern is a frozen tree that depends on
        nothing but the context, and callers treat it read-only."""
        if not self.applicable(ctx):
            return None
        cached = self._cache.get(ctx, False)
        if cached is False:
            cached = self._cache[ctx] = self.build(ctx)
        return cached


def make_template(
    call_name: str,
    build: Callable[[PatternContext], KnownPattern | None],
    *,
    arches: frozenset[str] | tuple[str, ...] | None = None,
    languages: frozenset[str] | tuple[str, ...] | None = None,
    runtimes: frozenset[str] | tuple[str, ...] | None = None,
    platforms: frozenset[str] | tuple[str, ...] | None = None,
    enabled_by_default: bool = True,
    name: str = "",
    gate: PatternGate | None = None,
) -> KnownPatternTemplate:
    def _fs(x):
        return frozenset(x) if x is not None else None

    return KnownPatternTemplate(
        call_name=call_name,
        build=build,
        arches=_fs(arches),
        languages=_fs(languages),
        runtimes=_fs(runtimes),
        platforms=_fs(platforms),
        enabled_by_default=enabled_by_default,
        name=name or call_name,
        gate=gate,
    )

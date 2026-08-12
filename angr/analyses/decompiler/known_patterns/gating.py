"""Criteria gates: per-target (and per-function) enablement for pattern templates.

A :class:`~.templates.KnownPatternTemplate` carries static applicability filters
(arch / language / runtime / platform) and a boolean ``enabled_by_default``.
Many idioms are deliberately opt-in because their *shape* is too generic to ship
on every binary — ``Load(p) == 0`` is a list-emptiness test in a kernel module
and a null check everywhere else.

A *gate* is the third channel: it lets an opt-in template say "turn me on when
**this** evidence is present". Two kinds of evidence are modelled:

* **target evidence** (:class:`TargetGate`) — a fact about the binary as a
  whole, derived once into the :class:`~.context.PatternContext`: this is a
  Linux kernel module, this is a Windows kernel-mode driver. Cheap, exact, and
  evaluated before any matching happens.
* **corroboration** (:class:`CorroboratedBy`) — another, unambiguous pattern
  already matched *in the same function*. This is what converts "too generic to
  ship" into "safe here": ``Load(Load(s))`` is meaningless on its own, but in a
  function where ``std::string::length`` (a load at the string's size offset)
  or ``std::string::capacity`` (the self-referential SSO select) already
  matched, the object really is a ``std::string`` and the load really is
  ``front()``.

Corroboration needs the match results, so it is resolved by
:class:`~.finder.KnownPatternFinder` in a second matching stage: the finder
matches with the ungated set, collects the evidence, re-evaluates the gates that
asked for it, and — only if that opens something — matches again with the
enlarged set. Gates that do not need evidence are resolved up front.

A gate can only *open* an opt-in template; it never disables a default-on one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from angr.project import Project

    from .context import PatternContext


@dataclass(frozen=True)
class GateContext:
    """Everything a gate may look at.

    :ivar ctx:      The target's :class:`~.context.PatternContext` (arch,
                    platform, C++ runtime, and the binary-evidence facts).
    :ivar project:  The Project, for gates that need to look past the context.
    :ivar evidence: Names *and* call names of the patterns established in the
                    function currently being matched — both the patterns that
                    matched in the first stage and the known-pattern calls
                    already present in the graph (outlined by an earlier round).
                    Empty when gates are evaluated outside a function.
    """

    ctx: PatternContext
    project: Project | None = None
    evidence: frozenset[str] = frozenset()

    def with_evidence(self, evidence: Iterable[str]) -> GateContext:
        return GateContext(ctx=self.ctx, project=self.project, evidence=frozenset(evidence))


@dataclass(frozen=True)
class PatternGate:
    """Base class for template gates. Instances are callables so that a gate can
    be used anywhere a ``Callable[[GateContext], bool]`` is expected."""

    def opens(self, gctx: GateContext) -> bool:
        raise NotImplementedError

    def __call__(self, gctx: GateContext) -> bool:
        return self.opens(gctx)

    @property
    def requires_evidence(self) -> bool:
        """Whether this gate can only be decided once the function's matches are
        known. Such gates are evaluated a second time by the finder."""
        return False

    @property
    def label(self) -> str:
        return self.__class__.__name__


@dataclass(frozen=True)
class TargetGate(PatternGate):
    """Opens when a predicate over the target's :class:`PatternContext` holds.

    The predicate reads facts that were derived once from the loaded binary, so
    evaluating it is free and its result is the same for every function.
    """

    name: str
    predicate: Callable[[PatternContext], bool]

    def opens(self, gctx: GateContext) -> bool:
        return bool(self.predicate(gctx.ctx))

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True)
class CorroboratedBy(PatternGate):
    """Opens in a function where at least one of ``witnesses`` already matched.

    Witnesses are given as template ``name``s or ``call_name``s; the finder puts
    both spellings of every established pattern into the evidence set.
    """

    witnesses: frozenset[str]

    def opens(self, gctx: GateContext) -> bool:
        return bool(self.witnesses & gctx.evidence)

    @property
    def requires_evidence(self) -> bool:
        return True

    @property
    def label(self) -> str:
        return "corroborated by " + " or ".join(sorted(self.witnesses))


@dataclass(frozen=True)
class AnyOf(PatternGate):
    """Opens when any sub-gate opens."""

    gates: tuple[PatternGate, ...] = field(default_factory=tuple)

    def opens(self, gctx: GateContext) -> bool:
        return any(g.opens(gctx) for g in self.gates)

    @property
    def requires_evidence(self) -> bool:
        return any(g.requires_evidence for g in self.gates)

    @property
    def label(self) -> str:
        return "(" + " or ".join(g.label for g in self.gates) + ")"


@dataclass(frozen=True)
class AllOf(PatternGate):
    """Opens when every sub-gate opens."""

    gates: tuple[PatternGate, ...] = field(default_factory=tuple)

    def opens(self, gctx: GateContext) -> bool:
        return all(g.opens(gctx) for g in self.gates)

    @property
    def requires_evidence(self) -> bool:
        return any(g.requires_evidence for g in self.gates)

    @property
    def label(self) -> str:
        return "(" + " and ".join(g.label for g in self.gates) + ")"


def corroborated_by(*witnesses: str) -> CorroboratedBy:
    """A gate that opens in a function where one of ``witnesses`` matched."""
    if not witnesses:
        raise ValueError("corroborated_by() needs at least one witness pattern")
    return CorroboratedBy(frozenset(witnesses))


def any_of(*gates: PatternGate) -> AnyOf:
    return AnyOf(tuple(gates))


def all_of(*gates: PatternGate) -> AllOf:
    return AllOf(tuple(gates))


# --- prebuilt target gates --------------------------------------------------

#: The binary is a Linux kernel module (or the kernel image itself): it carries
#: the module metadata sections, or exports symbols through ``__ksymtab``.
LINUX_KERNEL = TargetGate("linux-kernel-object", lambda ctx: ctx.is_linux_kernel_object)

#: The binary is a Windows kernel-mode driver: it imports ntoskrnl/hal/a kernel
#: -mode port or miniport library rather than the user-mode Win32 DLLs.
WINDOWS_KERNEL_DRIVER = TargetGate("windows-kernel-driver", lambda ctx: ctx.is_windows_kernel_driver)

#: Either of the two kernel targets — the audience for the intrusive
#: doubly-linked-list idioms, which ``list_head`` and ``LIST_ENTRY`` share.
KERNEL_TARGET = any_of(LINUX_KERNEL, WINDOWS_KERNEL_DRIVER)

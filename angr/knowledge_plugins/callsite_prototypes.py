from __future__ import annotations

from collections.abc import Iterator
from enum import Enum

from angr.calling_conventions import SimCC
from angr.enums import Flavors
from angr.sim_type import SimTypeFunction

from .plugin import KnowledgeBasePlugin


def _flavor_key(flavor: str | None) -> str:
    return Flavors.DEFAULT_FLAVOR if flavor is None else flavor


class CallsitePrototypeKind(Enum):
    """
    Describes the type of a callsite prototype.
    """

    INFERRED = 1
    PROPAGATED = 2
    MANUAL = 3  # user specified


class CallsitePrototypes(KnowledgeBasePlugin):
    """
    CallsitePrototypes manages callee prototypes at call sites, per decompilation flavor. Every method takes a flavor
    (None: the default flavor). A non-default flavor reads its own entry of a kind at a call site, or the default
    flavor's entry of that kind when it has none, like Function.get_prototype().
    """

    def __init__(self, kb):
        super().__init__(kb=kb)

        # flavor -> call-site block address -> kind -> (cc, prototype)
        self._prototypes: dict[str, dict[int, dict[CallsitePrototypeKind, tuple[SimCC, SimTypeFunction]]]] = {}

    def _kinds(self, callsite_block_addr: int, flavor: str | None) -> dict[CallsitePrototypeKind, tuple]:
        key = _flavor_key(flavor)
        kinds = self._prototypes.get(Flavors.DEFAULT_FLAVOR, {}).get(callsite_block_addr, {})
        if key != Flavors.DEFAULT_FLAVOR:
            own = self._prototypes.get(key, {}).get(callsite_block_addr)
            if own:
                kinds = {**kinds, **own}
        return kinds

    @property
    def flavors(self) -> list[str]:
        """The flavors that have entries of their own."""
        return [flavor for flavor, protos in self._prototypes.items() if protos]

    def set_prototype(
        self,
        callsite_block_addr: int,
        cc: SimCC,
        prototype: SimTypeFunction,
        *,
        kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED,
        manual: bool = False,
        propagated: bool = False,
        flavor: str | None = None,
    ) -> None:
        if manual:
            kind = CallsitePrototypeKind.MANUAL
        elif propagated:
            kind = CallsitePrototypeKind.PROPAGATED

        protos = self._prototypes.setdefault(_flavor_key(flavor), {})
        protos.setdefault(callsite_block_addr, {})[kind] = cc, prototype

    def remove_prototype(
        self,
        callsite_block_addr: int,
        *,
        kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED,
        flavor: str | None = None,
    ) -> None:
        """Remove the flavor's own entry of a kind; a non-default flavor then falls back to the default one."""
        protos = self._prototypes.get(_flavor_key(flavor), {})
        kinds = protos.get(callsite_block_addr)
        if kinds is not None:
            kinds.pop(kind, None)
            if not kinds:
                del protos[callsite_block_addr]

    def get_cc(
        self,
        callsite_block_addr: int,
        *,
        kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED,
        flavor: str | None = None,
    ) -> SimCC | None:
        entry = self._kinds(callsite_block_addr, flavor).get(kind)
        return entry[0] if entry is not None else None

    def get_prototype(
        self,
        callsite_block_addr: int,
        *,
        kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED,
        flavor: str | None = None,
    ) -> SimTypeFunction | None:
        entry = self._kinds(callsite_block_addr, flavor).get(kind)
        return entry[1] if entry is not None else None

    def is_prototype_manual(self, callsite_block_addr: int, *, flavor: str | None = None) -> bool | None:
        kinds = self._kinds(callsite_block_addr, flavor)
        if not kinds:
            return None
        return CallsitePrototypeKind.MANUAL in kinds

    def is_prototype_certain(self, callsite_block_addr: int, *, flavor: str | None = None) -> bool | None:
        kinds = self._kinds(callsite_block_addr, flavor)
        if not kinds:
            return None
        return CallsitePrototypeKind.MANUAL in kinds or CallsitePrototypeKind.PROPAGATED in kinds

    def has_some_prototype(self, callsite_block_addr: int, *, flavor: str | None = None) -> bool:
        return len(self._kinds(callsite_block_addr, flavor)) > 0

    def has_prototype(
        self,
        callsite_block_addr: int,
        *,
        kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED,
        flavor: str | None = None,
    ) -> bool:
        return kind in self._kinds(callsite_block_addr, flavor)

    def has_prototype_for_flavor(
        self,
        callsite_block_addr: int,
        *,
        kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED,
        flavor: str | None = None,
    ) -> bool:
        """Whether the flavor has its own entry of the kind (as opposed to falling back to the default flavor's)."""
        return kind in self._prototypes.get(_flavor_key(flavor), {}).get(callsite_block_addr, {})

    def items(self, flavor: str | None = None) -> Iterator[tuple[int, CallsitePrototypeKind, SimCC, SimTypeFunction]]:
        """The flavor's own entries (no fallback)."""
        for callsite_addr, kinds in self._prototypes.get(_flavor_key(flavor), {}).items():
            for kind, (cc, prototype) in kinds.items():
                yield callsite_addr, kind, cc, prototype

    def __len__(self) -> int:
        return sum(len(kinds) for protos in self._prototypes.values() for kinds in protos.values())

    def copy(self):
        o = CallsitePrototypes(self._kb)
        for flavor, protos in self._prototypes.items():
            o._prototypes[flavor] = {addr: kinds.copy() for addr, kinds in protos.items()}
        return o


KnowledgeBasePlugin.register_default("callsite_prototypes", CallsitePrototypes)

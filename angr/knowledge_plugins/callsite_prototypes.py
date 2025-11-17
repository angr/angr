from __future__ import annotations

from enum import Enum

from .plugin import KnowledgeBasePlugin
from angr.sim_type import SimTypeFunction
from angr.calling_conventions import SimCC


class CallsitePrototypeKind(Enum):
    """
    Describes the type of a callsite prototype.
    """

    INFERRED = 1
    PROPAGATED = 2
    MANUAL = 3  # user specified


class CallsitePrototypes(KnowledgeBasePlugin):
    """
    CallsitePrototypes manages callee prototypes at call sites.
    """

    def __init__(self, kb):
        super().__init__(kb=kb)

        self._prototypes: dict[int, dict[CallsitePrototypeKind, tuple[SimCC, SimTypeFunction]]] = {}

    def set_prototype(
        self,
        callsite_block_addr: int,
        cc: SimCC,
        prototype: SimTypeFunction,
        *,
        kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED,
        manual: bool = False,
        propagated: bool = False,
    ) -> None:
        if manual:
            kind = CallsitePrototypeKind.MANUAL
        elif propagated:
            kind = CallsitePrototypeKind.PROPAGATED

        if callsite_block_addr not in self._prototypes:
            self._prototypes[callsite_block_addr] = {}
        self._prototypes[callsite_block_addr][kind] = cc, prototype

    def get_cc(
        self, callsite_block_addr: int, *, kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED
    ) -> SimCC | None:
        try:
            return self._prototypes[callsite_block_addr][kind][0]
        except KeyError:
            return None

    def get_prototype(
        self, callsite_block_addr: int, *, kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED
    ) -> SimTypeFunction | None:
        try:
            return self._prototypes[callsite_block_addr][kind][1]
        except KeyError:
            return None

    def is_prototype_manual(self, callsite_block_addr: int) -> bool | None:
        try:
            return CallsitePrototypeKind.MANUAL in self._prototypes[callsite_block_addr]
        except KeyError:
            return None

    def is_prototype_certain(self, callsite_block_addr: int) -> bool | None:
        try:
            return (
                CallsitePrototypeKind.MANUAL in self._prototypes[callsite_block_addr]
                or CallsitePrototypeKind.PROPAGATED in self._prototypes[callsite_block_addr]
            )
        except KeyError:
            return None

    def has_some_prototype(self, callsite_block_addr: int) -> bool:
        return callsite_block_addr in self._prototypes and len(self._prototypes[callsite_block_addr]) > 0

    def has_prototype(
        self, callsite_block_addr: int, *, kind: CallsitePrototypeKind = CallsitePrototypeKind.INFERRED
    ) -> bool:
        return callsite_block_addr in self._prototypes and kind in self._prototypes[callsite_block_addr]

    def copy(self):
        o = CallsitePrototypes(self._kb)
        for callsite_addr, kinds in self._prototypes.items():
            o._prototypes[callsite_addr] = kinds.copy()
        return o


KnowledgeBasePlugin.register_default("callsite_prototypes", CallsitePrototypes)

from typing import Dict, Tuple, Optional

from .plugin import KnowledgeBasePlugin
from ..sim_type import SimTypeFunction
from ..calling_conventions import SimCC


class CallsitePrototypes(KnowledgeBasePlugin):
    """
    CallsitePrototypes manages callee prototypes at call sites.
    """

    def __init__(self, kb):
        super().__init__()
        self._kb = kb

        self._prototypes: Dict[int, Tuple[SimCC, SimTypeFunction, bool]] = {}

    def set_prototype(
        self,
        callsite_block_addr: int,
        cc: SimCC,
        prototype: SimTypeFunction,
        manual: bool = False,
    ) -> None:
        self._prototypes[callsite_block_addr] = cc, prototype, manual

    def get_cc(self, callsite_block_addr: int) -> Optional[SimCC]:
        try:
            return self._prototypes[callsite_block_addr][0]
        except KeyError:
            return None

    def get_prototype(self, callsite_block_addr: int) -> Optional[SimTypeFunction]:
        try:
            return self._prototypes[callsite_block_addr][1]
        except KeyError:
            return None

    def get_prototype_type(self, callsite_block_addr: int) -> Optional[bool]:
        try:
            return self._prototypes[callsite_block_addr][2]
        except KeyError:
            return None

    def has_prototype(self, callsite_block_addr: int) -> bool:
        return callsite_block_addr in self._prototypes

    def copy(self):
        o = CallsitePrototypes(self._kb)
        o._prototypes.update(self._prototypes)
        return o


KnowledgeBasePlugin.register_default("callsite_prototypes", CallsitePrototypes)

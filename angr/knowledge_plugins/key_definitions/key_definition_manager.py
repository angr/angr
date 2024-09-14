from __future__ import annotations
from typing import TYPE_CHECKING
from collections.abc import Iterable

from .. import KnowledgeBasePlugin
from .rd_model import ReachingDefinitionsModel
from .constants import OP_BEFORE, OP_AFTER

if TYPE_CHECKING:
    from ...knowledge_base import KnowledgeBase


class RDAObserverControl:
    def __init__(self, func_addr: int, call_site_block_addrs: Iterable[int], call_site_ins_addrs: Iterable[int]):
        self.func_addr = func_addr
        self.call_site_block_addrs = set(call_site_block_addrs)
        self.call_site_ins_addrs = set(call_site_ins_addrs)

    def rda_observe_callback(self, ob_type, **kwargs):
        if ob_type == "node":
            block_addr = kwargs.pop("addr", None)
            op_type = kwargs.pop("op_type", None)
            return block_addr in self.call_site_block_addrs and op_type == OP_AFTER
        if ob_type == "insn":
            ins_addr = kwargs.pop("addr", None)
            op_type = kwargs.pop("op_type", None)
            return ins_addr in self.call_site_ins_addrs and op_type == OP_BEFORE

        return False


class KeyDefinitionManager(KnowledgeBasePlugin):
    """
    KeyDefinitionManager manages and caches reaching definition models for each function.

    For each function, by default we cache the entire reaching definitions model with observed results at the following
    locations:
    - Before each call instruction: ('insn', address of the call instruction, OP_BEFORE)
    - After returning from each call: ('node', address of the block that ends with a call, OP_AFTER)
    """

    def __init__(self, kb: KnowledgeBase):
        super().__init__(kb=kb)
        self.model_by_funcaddr: dict[int, ReachingDefinitionsModel] = {}

    def has_model(self, func_addr: int):
        return func_addr in self.model_by_funcaddr

    def get_model(self, func_addr: int):
        if func_addr not in self.model_by_funcaddr:
            if not self._kb.functions.contains_addr(func_addr):
                return None
            func = self._kb.functions[func_addr]
            if func.is_simprocedure or func.is_plt or func.alignment:
                return None
            callsites = list(func.get_call_sites())
            if not callsites:
                return None
            call_insn_addrs = set()
            for block_addr in callsites:
                block = func._get_block(block_addr)
                if block is None:
                    continue
                if not block.instruction_addrs:
                    continue
                call_insn_addr = block.instruction_addrs[-1]
                call_insn_addrs.add(call_insn_addr)
            observer = RDAObserverControl(func_addr, callsites, call_insn_addrs)
            rda = self._kb._project.analyses.ReachingDefinitions(
                subject=self._kb.functions[func_addr], observe_callback=observer.rda_observe_callback
            )
            self.model_by_funcaddr[func_addr] = rda.model

        return self.model_by_funcaddr[func_addr]

    def copy(self) -> KeyDefinitionManager:
        dm = KeyDefinitionManager(self._kb)
        dm.model_by_funcaddr = {x[0]: x[1].copy() for x in self.model_by_funcaddr.items()}
        return dm


KnowledgeBasePlugin.register_default("defs", KeyDefinitionManager)

from __future__ import annotations

from collections import deque

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.knowledge_plugins.functions.function import Function
from angr.rust.utils.demangler import normalize

CLEANUP_FUNCTIONS = (
    "free",
    "__rust_dealloc",
    "close",
    "core::ptr::drop_in_place",
    "core::ops::drop::Drop::drop",
    "alloc::raw_vec::RawVecInner::deallocate",
    "smallvec::deallocate",
)


class CleanupFunctionIdentification(Analysis):
    """Identify cleanup functions (deallocators, drop glue, etc.) in Rust binaries."""

    def __init__(self):
        self._normalize_cache: dict[str, str] = {}  # raw name to normalized name
        self._nullstub_cache: dict[int, bool] = {}  # function address to is_nullstub result
        self._analyze()

    def _normalize_name(self, raw_name: str) -> str:
        cached = self._normalize_cache.get(raw_name)
        if cached is None:
            cached = normalize(raw_name, monopolize=True, use_trait_name=True)
            self._normalize_cache[raw_name] = cached
        return cached

    @staticmethod
    def _compute_nullstub(func: Function) -> bool:
        # TODO: Support architectures beyond x86 and x86-64
        if func.size == 0 and not func.is_plt:
            return True
        if len(func.block_addrs_set) == 1:
            block = next(iter(func.blocks))
            if len(block.capstone.insns) == 4 and [insn.mnemonic for insn in block.capstone.insns] == [
                "push",
                "mov",
                "pop",
                "ret",
            ]:
                return True
            if len(block.capstone.insns) == 1 and [insn.mnemonic for insn in block.capstone.insns] == ["ret"]:
                return True
        return False

    def _is_nullstub_function(self, func_addr: int) -> bool:
        cached = self._nullstub_cache.get(func_addr)
        if cached is not None:
            return cached
        functions = self.project.kb.functions
        block_count = functions.get_func_block_count(func_addr)
        # a null-stub is either a size-0 function (no blocks) or a single block; anything with more than
        # one block can be rejected.
        if block_count is not None and block_count > 1:  # noqa: SIM108
            result = False
        else:
            result = self._compute_nullstub(functions[func_addr])
        self._nullstub_cache[func_addr] = result
        return result

    def _is_cleanup_function(self, func_addr: int) -> bool:
        functions = self.project.kb.functions
        if not functions.contains_addr(func_addr):
            return False
        raw_name = functions.get_func_name(func_addr)
        if raw_name is None:
            raw_name = functions.get_by_addr(func_addr, meta_only=True).name
        if self._normalize_name(raw_name) in CLEANUP_FUNCTIONS:
            return True
        return self._is_nullstub_function(func_addr)

    def _analyze(self):
        functions = self.project.kb.functions
        callgraph = self.project.kb.callgraph
        queue: deque[int] = deque()
        for func_addr in functions:
            if self._is_cleanup_function(func_addr):
                queue.append(func_addr)
                func_meta = functions.get_by_addr(func_addr, meta_only=True)
                if func_meta.is_default_name:
                    func = functions.get_by_addr(func_addr)
                    func.name = "core::ptr::drop_in_place"
                    func.from_signature = "flirt"
                    func.is_default_name = False

        while queue:
            current_func_addr = queue.popleft()
            raw_name = functions.get_func_name(current_func_addr)
            if raw_name is None:
                func_meta = functions.get_by_addr(current_func_addr, meta_only=True)
                raw_name = func_meta.name
            name = self._normalize_name(raw_name)
            for caller_addr in callgraph.predecessors(current_func_addr):
                callee_addrs = callgraph.successors(caller_addr)
                if all(self._is_cleanup_function(callee_addr) for callee_addr in callee_addrs):
                    caller_func_meta = functions.get_by_addr(caller_addr, meta_only=True)
                    if caller_func_meta.is_default_name:
                        caller_func = functions.get_by_addr(caller_addr)
                        caller_func.name = name
                        caller_func.from_signature = "flirt"
                        caller_func.is_default_name = False
                        queue.append(caller_addr)


AnalysesHub.register_default("CleanupFunctionIdentification", CleanupFunctionIdentification)

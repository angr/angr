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
        # cache normalized names by raw name (normalize() is a pure function of its input) and null-stub
        # results by function address (the null-stub check is purely structural and never changes). The
        # combined cleanup status is intentionally NOT cached: a function can become a cleanup function
        # mid-analysis when a caller is renamed, so the name-match half is always recomputed from the
        # current (cached) name.
        self._normalize_cache: dict[str, str] = {}
        self._nullstub_cache: dict[int, bool] = {}
        self._analyze()

    def _normalize_name(self, raw_name: str) -> str:
        cached = self._normalize_cache.get(raw_name)
        if cached is None:
            cached = normalize(raw_name, monopolize=True, use_trait_name=True)
            self._normalize_cache[raw_name] = cached
        return cached

    @staticmethod
    def _compute_nullstub(func: Function) -> bool:
        if func.size == 0 and not func.is_plt:
            return True
        if len(list(func.blocks)) == 1:
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
        # one block can be rejected without loading and disassembling the Function. This must stay an
        # if/else (not a ternary) so _compute_nullstub -- which loads and disassembles the function -- is
        # never evaluated for a multi-block function.
        if block_count is not None and block_count > 1:  # noqa: SIM108
            result = False
        else:
            result = self._compute_nullstub(functions[func_addr])
        self._nullstub_cache[func_addr] = result
        return result

    def _is_cleanup_function(self, func_addr: int) -> bool:
        functions = self.project.kb.functions
        raw_name = functions.get_func_name(func_addr)
        if raw_name is None:
            # defensive fallback: the name cache should always know a valid function
            raw_name = functions[func_addr].name
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
                func = functions[func_addr]
                if func.is_default_name:
                    func.name = "core::ptr::drop_in_place"
                    func.from_signature = "flirt"
                    func.is_default_name = False

        while queue:
            current_func_addr = queue.popleft()
            raw_name = functions.get_func_name(current_func_addr)
            if raw_name is None:
                raw_name = functions[current_func_addr].name
            name = self._normalize_name(raw_name)
            for caller_addr in callgraph.predecessors(current_func_addr):
                callee_addrs = callgraph.successors(caller_addr)
                if all(self._is_cleanup_function(callee_addr) for callee_addr in callee_addrs):
                    caller_func = functions[caller_addr]
                    if caller_func.is_default_name:
                        caller_func.name = name
                        caller_func.from_signature = "flirt"
                        caller_func.is_default_name = False
                        queue.append(caller_addr)


AnalysesHub.register_default("CleanupFunctionIdentification", CleanupFunctionIdentification)

from angr.rust.utils.demangler import normalize
from angr.knowledge_plugins.functions.function import Function
from ...analyses import Analysis, AnalysesHub

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
    def __init__(self):
        self._analyze()

    def _is_nullstub_function(self, func: Function):
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

    def _is_cleanup_function(self, func: Function):
        name = normalize(func.name, monopolize=True, use_trait_name=True)
        return name in CLEANUP_FUNCTIONS or self._is_nullstub_function(func)

    def _analyze(self):
        proj = self.project
        queue = []
        for func in proj.kb.functions.values():
            if self._is_cleanup_function(func):
                queue.append(func.addr)
                if func.is_default_name:
                    func.name = "core::ptr::drop_in_place"
                    func.from_signature = "flirt"
                    func.is_default_name = False

        while queue:
            current_func_addr = queue.pop(0)
            current_func = proj.kb.functions[current_func_addr]
            name = normalize(current_func.name, monopolize=True, use_trait_name=True)
            callers = proj.kb.callgraph.predecessors(current_func_addr)
            for caller_addr in callers:
                callees = proj.kb.callgraph.successors(caller_addr)
                callees = [proj.kb.functions[callee] for callee in callees]
                if all(self._is_cleanup_function(callee) for callee in callees):
                    caller_func = proj.kb.functions[caller_addr]
                    if caller_func.is_default_name:
                        caller_func.name = name
                        caller_func.from_signature = "flirt"
                        caller_func.is_default_name = False
                        queue.append(caller_addr)


AnalysesHub.register_default("CleanupFunctionIdentification", CleanupFunctionIdentification)

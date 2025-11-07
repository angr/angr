from angr.rust.utils.library import normalize
from angr.knowledge_plugins.functions.function import Function
from ...analyses import Analysis, AnalysesHub


CLEANUP_FUNCTIONS = ("free", "__rust_dealloc", "close", "core::ptr::drop_in_place", "core::ops::drop::Drop::drop")


class CleanupFunctionIdentification(Analysis):
    def __init__(self):
        self._analyze()

    def _is_cleanup_function(self, func: Function):
        name = normalize(func.name, monopolize=True, use_trait_name=True)
        return name in CLEANUP_FUNCTIONS or (not func.is_plt and func.size == 0)

    def _analyze(self):
        proj = self.project
        queue = []
        for func in proj.kb.functions.values():
            if self._is_cleanup_function(func):
                queue.append(func.addr)

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
                        caller_func.is_default_name = False
                        queue.append(caller_addr)


AnalysesHub.register_default("CleanupFunctionIdentification", CleanupFunctionIdentification)

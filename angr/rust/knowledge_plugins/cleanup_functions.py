import logging

from angr.knowledge_plugins.plugin import KnowledgeBasePlugin

l = logging.getLogger(name=__name__)


class CleanupFunctions(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__(kb)
        self._cleanup_functions = set()
        self._finished = False

    def identify_cleanup_functions(self):
        if self._finished:
            return self._cleanup_functions
        cfg = self._kb.cfgs.get_most_accurate()
        proj = self._kb._project
        free_symbol = proj.loader.find_symbol("free")
        if cfg and free_symbol:
            free_addr = free_symbol.rebased_addr
            self._cleanup_functions.add(free_addr)
            for func in proj.kb.functions.values():
                if func.size == 0 and not func.is_plt and not func.is_syscall and not func.is_simprocedure:
                    self._cleanup_functions.add(func.addr)
            queue = [free_addr]
            while queue:
                current_func_addr = queue.pop(0)
                callers = proj.kb.callgraph.predecessors(current_func_addr)
                for caller_addr in callers:
                    callees = proj.kb.callgraph.successors(caller_addr)
                    if all(callee in self._cleanup_functions for callee in callees):
                        if caller_addr not in self._cleanup_functions:
                            self._cleanup_functions.add(caller_addr)
                            queue.append(caller_addr)
        self._finished = True
        for addr in self._cleanup_functions:
            l.debug(f"Identified cleanup function: {proj.kb.functions[addr].demangled_name} at {hex(addr)}")
        return self._cleanup_functions


KnowledgeBasePlugin.register_default("cleanup_functions", CleanupFunctions)

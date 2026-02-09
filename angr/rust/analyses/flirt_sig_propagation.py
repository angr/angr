from ...analyses import Analysis, AnalysesHub


class FlirtSigPropagation(Analysis):
    def __init__(self, cfg):
        self.cfg = cfg

        self._analyze()

    def _is_simple_function(self, func):
        """A simple function is defined as a function that only contains jmp instructions."""
        for block in func.blocks:
            for insn in block.capstone.insns:
                if insn.mnemonic not in ("jmp", "mov", "push", "pop"):
                    return False
        return True

    def _analyze(self):
        """Propagate FLIRT signatures to simple functions that call FLIRT-matched functions."""
        cfg = self.cfg
        queue = [func.addr for func in self.project.kb.functions.values() if func.from_signature == "flirt"]
        while queue:
            func_addr = queue.pop(0)
            func = self.project.kb.functions[func_addr]
            for pred_addr in self.project.kb.callgraph.predecessors(func_addr):
                pred_func = self.project.kb.functions[pred_addr]
                if self._is_simple_function(pred_func):
                    if not pred_func.from_signature:
                        pred_func.from_signature = "flirt"
                        pred_func.is_default_name = False
                        pred_func.name = func.name
                        queue.append(pred_addr)


AnalysesHub.register_default("FlirtSigPropagation", FlirtSigPropagation)

from __future__ import annotations

from collections import deque

from angr.analyses.analysis import AnalysesHub, Analysis


class FlirtSigPropagation(Analysis):
    """Propagate FLIRT signatures through simple wrapper functions."""

    def __init__(self, cfg):
        self.cfg = cfg

        self._analyze()

    def _is_simple_function(self, func_addr):
        """A simple function is a single block that only contains jmp/mov/push/pop instructions.

        The single-block requirement is checked first via the FunctionManager block-count cache, so
        that multi-block functions are rejected without loading and disassembling the Function object.
        """
        functions = self.project.kb.functions
        if functions.get_func_block_count(func_addr) != 1:
            return False
        func = functions[func_addr]
        for block in func.blocks:
            for insn in block.capstone.insns:
                if insn.mnemonic not in ("jmp", "mov", "push", "pop"):
                    return False
        return True

    def _analyze(self):
        """Propagate FLIRT signatures to simple functions that call FLIRT-matched functions."""
        functions = self.project.kb.functions
        # read the FLIRT-matched function addresses from the FunctionManager cache instead of loading
        # every Function object just to inspect from_signature
        queue: deque[int] = deque(functions.get_func_addrs_from_signature("flirt"))
        while queue:
            func_addr = queue.popleft()
            for pred_addr in self.project.kb.callgraph.predecessors(func_addr):
                # skip predecessors that already carry a signature, and non-simple ones, using cached
                # metadata before touching the (possibly spilled) Function objects
                if functions.get_func_from_signature(pred_addr):
                    continue
                if not self._is_simple_function(pred_addr):
                    continue
                # only now do we need the matched function's name and an editable predecessor object
                func_name = functions.get_func_name(func_addr)
                pred_func = functions[pred_addr]
                pred_func.from_signature = "flirt"
                pred_func.is_default_name = False
                pred_func.name = func_name
                queue.append(pred_addr)


AnalysesHub.register_default("FlirtSigPropagation", FlirtSigPropagation)

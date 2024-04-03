import ailment
from ...analyses.decompiler.optimization_passes.engine_base import SimplifierAILState
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from .utils import extract_callee


class DeallocSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Rust Memory De-allocation Simplifier"

    RUST_DEALLOC_FUNCTIONS = ["__rust_dealloc"]

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            block: ailment.Block
            new_statements = []
            for stmt in block.statements:
                callee = extract_callee(stmt, self.kb)
                if callee and callee.name in DeallocSimplifier.RUST_DEALLOC_FUNCTIONS:
                    continue
                new_statements.append(stmt)
            block.statements = new_statements

import ailment

from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from .utils import *
from ...utils.library import get_rust_function_name


class JunkRemover(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Remove redundant statements"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _try_remove_error_handling(self):
        pass

    def _try_remove_boundary_check(self):
        """
        Remove boundary check,
        Boundary check could also be a hint of type inference
        """
        pass

    def _analyze(self, cache=None):
        def handle_node(node: ailment.Block):
            pass

        AILGraphWalker(self._graph, handle_node, replace_nodes=True).walk()
        # for block in list(self._graph.nodes()):
        #     block: ailment.Block
        #     new_statements = block.statements
        #     for stmt in block.statements:
        #         target = extract_callee(stmt, self.kb)
        #         if target and get_rust_function_name(target.demangled_name) == "core::panicking::panic_bounds_check":
        #             new_statements = []
        #     block.statements = new_statements
        #     preds = list(pred for pred in self._graph.predecessors(block) if pred is not block)
        #     if len(preds) == 1 and len(block.statements) == 0:
        #         remove_branch(preds[0], block.addr)

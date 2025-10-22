from collections import defaultdict

from angr.ailment import AILBlockWalker
from angr.ailment.expression import VirtualVariable
from angr.rust.mixins import SRDAMixin, CFAMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.ailment.statement import Assignment


DEREF_COERCION_FUNCTIONS = [
    "core::ops::deref::Deref::deref",
    "core::ops::deref_mut::DerefMut::deref_mut",
]


class DerefCoercionSimplifierUninlined(OptimizationPass, SRDAMixin, CFAMixin, AILBlockWalker):
    """
    Simplify explicit deref coercion operations that have not been inlined.
    1. Identify assignments where a VirtualVariable is assigned the result of a deref coercion function call.
    2. Record the mapping from the VirtualVariable to the argument of the deref coercion function.
    3. Traverse the AIL graph and replace occurrences of the VirtualVariable with the recorded argument.
    4. Remove the original assignment statements that performed the deref coercion.
    5. Update the AIL graph to reflect these changes.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Simplify explicit deref coercion operations (uninlined)"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        CFAMixin.__init__(self, self._graph, self.project)
        AILBlockWalker.__init__(self)

        self._vvar_replacements = {}
        self._stmts_to_remove = defaultdict(list)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _handle_VirtualVariable(self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt, block):
        if isinstance(stmt, Assignment) and stmt.dst == expr and expr.varid in self._vvar_replacements:
            self._stmts_to_remove[block].append(stmt)
            return None
        if expr.varid in self._vvar_replacements:
            return self._vvar_replacements[expr.varid]
        return None

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            for stmt in block.statements:
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and self.match_call(stmt.src, DEREF_COERCION_FUNCTIONS)
                    and len(stmt.src.args) == 1
                ):
                    self._vvar_replacements[stmt.dst.varid] = stmt.src.args[0]
                    self._stmts_to_remove[block].append(stmt)

        for block in self._graph.nodes:
            self.walk(block)

        for block in self._graph.nodes:
            for stmt in self._stmts_to_remove[block]:
                if stmt in block.statements:
                    block.statements.remove(stmt)

        self.out_graph = self._graph

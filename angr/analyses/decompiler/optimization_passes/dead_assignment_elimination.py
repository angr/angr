import ailment

from ... import AnalysesHub
from .optimization_pass import OptimizationPass


class DeadAssignmentRemoval(OptimizationPass):

    ARCHES = ['X86', 'AMD64', 'ARMEL']

    PLATFORMS = ['linux']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, ailment.Stmt.Assignment):
                    return True, {}

    def _analyze(self, cache=None):
        lv = self.project.analyses.LiveVariables(self._func, self._graph)
        for block in self._graph.nodes:
            new_block = block.copy()
            for stmt in block.statements:
                if isinstance(stmt, ailment.Stmt.Assignment):
                    live_after = lv._state_store.after(stmt.ins_addr)._frozenset
                    dst_var = stmt.dst.referenced_variable
                    if dst_var is not None and dst_var not in live_after:
                        new_block.statements.remove(stmt)
            self._update_block(block, new_block)

AnalysesHub.register_default('DeadAssignmentRemoval', DeadAssignmentRemoval)

from ailment import Assignment
from ailment.expression import VirtualVariable
from ailment.statement import Call

from ..sim_type import is_composite_type
from ...analyses import Analysis, AnalysesHub


class RustTypeHintsAnalysis(Analysis):
    def __init__(self, func, graph):
        self._func = func
        self._graph = graph
        self.vvar_type_hints = {}

        self._analyze()

    def _analyze(self):
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
                    if isinstance(stmt.src, Call):
                        call = stmt.src
                        if is_composite_type(call.prototype.returnty):
                            # import ipdb
                            #
                            # ipdb.set_trace()
                            pass


AnalysesHub.register_default("RustTypeHints", RustTypeHintsAnalysis)

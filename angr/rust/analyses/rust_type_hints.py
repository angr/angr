from angr.ailment import Assignment
from angr.ailment.expression import VirtualVariable, Struct, StringLiteral
from angr.ailment.statement import Call, FunctionLikeMacro

from ..sim_type import is_composite_type, RustSimTypeFunction, RustSimTypeStrRef
from ...analyses import Analysis, AnalysesHub


class RustTypeHintsAnalysis(Analysis):
    def __init__(self, func, graph):
        self._func = func
        self._graph = graph

        self._analyze()

    def _analyze(self):
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    if isinstance(stmt.src, (Call, FunctionLikeMacro)):
                        call = stmt.src
                        returnty = None
                        if (
                            isinstance(call, Call)
                            and isinstance(call.prototype, RustSimTypeFunction)
                            and is_composite_type(call.prototype.returnty)
                        ):
                            returnty = call.prototype.returnty
                        elif isinstance(call, FunctionLikeMacro) and is_composite_type(call.returnty):
                            returnty = call.returnty
                        if returnty:
                            self.project.kb.type_hints.add_type_hint(stmt.dst, returnty)
                    elif isinstance(stmt.src, StringLiteral):
                        self.project.kb.type_hints.add_type_hint(
                            stmt.dst, RustSimTypeStrRef().with_arch(self.project.arch)
                        )


AnalysesHub.register_default("RustTypeHints", RustTypeHintsAnalysis)

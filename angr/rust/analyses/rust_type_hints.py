from ailment import Assignment
from ailment.expression import VirtualVariable
from ailment.statement import Call, FunctionLikeMacro

from ..sim_type import is_composite_type, RustSimTypeFunction
from ..typehoon.lifter import RustTypeLifter
from ...analyses import Analysis, AnalysesHub


class RustTypeHintsAnalysis(Analysis):
    def __init__(self, func, graph):
        self._func = func
        self._graph = graph
        self.vvar_type_hints = {}

        self._analyze()

    def _analyze(self):
        lifter = RustTypeLifter(self.project.arch.bits)
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
                            ty_const = lifter.lift(returnty)
                            self.vvar_type_hints[stmt.dst.varid] = ty_const


AnalysesHub.register_default("RustTypeHints", RustTypeHintsAnalysis)

from __future__ import annotations

from angr.ailment import Assignment
from angr.ailment.expression import Call, FunctionLikeMacro, StringLiteral, VirtualVariable
from angr.analyses.analysis import AnalysesHub, Analysis
from angr.rust.sim_type import RustSimTypeFunction, RustSimTypeStrRef, is_composite_type


class RustTypeHintsAnalysis(Analysis):
    """Collect type hints from Rust-specific patterns in the AIL graph."""

    def __init__(self, func, graph, variable_map=None):
        self._func = func
        self._graph = graph
        self._variable_map = variable_map

        self._analyze()

    def _analyze(self):
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    if isinstance(stmt.src, (Call, FunctionLikeMacro)):
                        call = stmt.src
                        returnty = None
                        call_prototype = (
                            self._variable_map.prototype(call)
                            if isinstance(call, Call) and self._variable_map is not None
                            else None
                        )
                        if (
                            isinstance(call, Call)
                            and isinstance(call_prototype, RustSimTypeFunction)
                            and is_composite_type(call_prototype.returnty)
                        ):
                            returnty = call_prototype.returnty
                        elif isinstance(call, FunctionLikeMacro) and self._variable_map is not None:
                            macro_returnty = self._variable_map.returnty(call)
                            if is_composite_type(macro_returnty):
                                returnty = macro_returnty
                        if returnty:
                            self.project.kb.type_hints.add_type_hint(stmt.dst, returnty, self._func.addr)
                    elif isinstance(stmt.src, StringLiteral):
                        self.project.kb.type_hints.add_type_hint(
                            stmt.dst, RustSimTypeStrRef().with_arch(self.project.arch), self._func.addr
                        )


AnalysesHub.register_default("RustTypeHints", RustTypeHintsAnalysis)

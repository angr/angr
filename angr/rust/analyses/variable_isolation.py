from ailment import Const
from ailment.expression import BasePointerOffset
from ailment.statement import Call

from ...analyses import Analysis, AnalysesHub


class VariableIsolation(Analysis):
    def __init__(self, func, func_graph):
        self.func = func
        self.func_graph = func_graph
        self._varloc_to_variable = {}
        self._analyze()

    def _analyze(self):
        for block in sorted(self.func_graph.nodes, key=lambda b: b.addr):
            for stmt_idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Call) and (stmt.args or stmt.ret_expr):
                    for arg_idx, arg in [(-1, stmt.ret_expr)] + list(enumerate(stmt.args)):
                        if isinstance(arg, BasePointerOffset):
                            var = self.kb.variables[self.func.addr].find_variables_by_atom(
                                block.addr, stmt_idx, arg if arg_idx != -1 else stmt, block_idx=block.idx
                            )
                            if var and len(var):
                                var = next(iter(var))[0]
                                unified_var = var
                                if isinstance(stmt.target, Const) and stmt.target.value in self.kb.functions:
                                    name = self.kb.functions[stmt.target.value].name
                                    varloc = (name, arg_idx, arg.offset)
                                    if varloc not in self._varloc_to_variable:
                                        self._varloc_to_variable[varloc] = var
                                    unified_var = self._varloc_to_variable[varloc]
                                self.kb.variable_isolation.unified_variables[var] = unified_var


AnalysesHub.register_default("VariableIsolation", VariableIsolation)

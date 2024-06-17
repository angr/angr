from ailment import Const
from ailment.expression import BasePointerOffset
from ailment.statement import Call

from ...analyses import Analysis, AnalysesHub


class ArgumentIsolation(Analysis):
    def __init__(self, func, func_graph):
        self.func = func
        self.func_graph = func_graph
        self._argloc_to_variable = {}
        self._analyze()

    def _analyze(self):
        for block in self.func_graph.nodes:
            for stmt_idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Call) and stmt.args:
                    for arg_idx, arg in enumerate(stmt.args):
                        if isinstance(arg, BasePointerOffset):
                            var = self.kb.variables[self.func.addr].find_variables_by_atom(
                                block.addr, stmt_idx, arg, block_idx=block.idx
                            )
                            if var and len(var):
                                var = next(iter(var))[0]
                                if isinstance(stmt.target, Const) and stmt.target.value in self.kb.functions:
                                    name = self.kb.functions[stmt.target.value].name
                                    argloc = (name, arg_idx)
                                    if argloc in self._argloc_to_variable:
                                        self.kb.argument_isolation.unified_arg_variables[
                                            var
                                        ] = self._argloc_to_variable[argloc]
                                        continue
                                    else:
                                        self._argloc_to_variable[argloc] = var
                                self.kb.argument_isolation.unified_arg_variables[var] = var


AnalysesHub.register_default("ArgumentIsolation", ArgumentIsolation)

from ailment import Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset
from ailment.statement import Call, Statement

from ...analyses import Analysis, AnalysesHub


class VariableIsolation(Analysis):
    def __init__(self, func, func_graph):
        self.func = func
        self.func_graph = func_graph
        self._varloc_to_variable = {}
        self._analyze()

    def _analyze(self):
        class CallWalker(AILBlockWalker):
            def __init__(self, analysis):
                super().__init__()
                self.analysis = analysis

            def _handle_Call_Unified(self, call: Call, stmt_idx):
                if call.args or call.ret_expr:
                    for arg_idx, arg in [(-1, call.ret_expr)] + list(enumerate(call.args if call.args else [])):
                        if isinstance(arg, BasePointerOffset):
                            var = self.analysis.kb.variables[self.analysis.func.addr].find_variables_by_atom(
                                block.addr, stmt_idx, arg if arg_idx != -1 else call, block_idx=block.idx
                            )
                            if var and len(var):
                                var = next(iter(var))[0]
                                unified_var = var
                                if isinstance(call.target, Const) and call.target.value in self.analysis.kb.functions:
                                    name = self.analysis.kb.functions[call.target.value].name
                                    varloc = (name, arg_idx, arg.offset)
                                    if varloc not in self.analysis._varloc_to_variable:
                                        self.analysis._varloc_to_variable[varloc] = var
                                    unified_var = self.analysis._varloc_to_variable[varloc]
                                self.analysis.kb.variable_isolation.unified_variables[var] = unified_var

            def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
                self._handle_Call_Unified(stmt, stmt_idx)

            def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
                self._handle_Call_Unified(expr, stmt_idx)

        for block in sorted(self.func_graph.nodes, key=lambda b: b.addr):
            CallWalker(self).walk(block)


AnalysesHub.register_default("VariableIsolation", VariableIsolation)

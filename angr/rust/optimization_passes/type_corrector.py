import ailment
from ailment.statement import Call, Store

from ..sim_type import RustSimStruct
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ..ailment.expression import Struct


class TypeCorrector(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Correct variable types overridden by other Rust optimization passes"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.variable_manager = self._variable_kb.variables.get_function_manager(self._func.addr)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _set_variable_type(self, var, type_):
        self.variable_manager.set_variable_type(var, type_, mark_manual=True)

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            block: ailment.Block
            for stmt in block.statements:
                if isinstance(stmt, Store) and isinstance(stmt.data, Struct):
                    var = stmt.variable if stmt.variable is not None else stmt.addr.variable
                    self._set_variable_type(var, stmt.data.type)
                elif isinstance(stmt, Call) and stmt.prototype and isinstance(stmt.prototype.returnty, RustSimStruct):
                    self._set_variable_type(stmt.ret_expr.variable, stmt.prototype.returnty)

import ailment

from ...analyses.decompiler.optimization_passes.engine_base import SimplifierAILState
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ..sim_type import RustSimTypeString, RustSimTypePointer, RustSimTypeStr, RustSimTypeVec
from ..ailment.expression import String, Vec


class TypeCorrector(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Correct variable types overridden by other Rust optimization passes"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self._func_manager = self._variable_kb.variables.get_function_manager(self._func.addr)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _set_variable_type(self, stmt, type_):
        var = stmt.variable if stmt.variable is not None else stmt.addr.variable
        self._func_manager.set_variable_type(var, type_, mark_manual=True)

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            block: ailment.Block
            for stmt in block.statements:
                if isinstance(stmt, ailment.statement.Store):
                    data = stmt.data
                    if isinstance(data, String):
                        if data.is_heap_str:
                            self._set_variable_type(stmt, RustSimTypeString())
                        else:
                            self._set_variable_type(
                                stmt, RustSimTypePointer(RustSimTypeStr().with_arch(self.project.arch))
                            )
                    elif isinstance(data, Vec):
                        self._set_variable_type(stmt, RustSimTypeVec())

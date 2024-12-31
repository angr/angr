import ailment
from ailment.expression import VirtualVariable
from ailment.statement import Call, Store, Assignment

from ..ailment.statement import FunctionLikeMacro
from ..sim_type import RustSimStruct, RustSimEnum, is_composite_type
from ...utils.graph import GraphUtils
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ..ailment.expression import Struct
from ...analyses.decompiler.structured_codegen.rust import unpack_typeref
from ...knowledge_plugins.variables.variable_manager import VariableManagerInternal
from ...sim_variable import SimVariable


class TypeCorrector(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Correct variable types overridden by other Rust optimization passes"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.variable_manager: VariableManagerInternal = self._variable_kb.variables.get_function_manager(
            self._func.addr
        )
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _set_variable_type(self, var, type_):
        self.variable_manager.set_variable_type(var, type_, mark_manual=True)

    def _set_unified_variable(self, variable: SimVariable, unified: SimVariable) -> None:
        old_unified = self.variable_manager._variables_to_unified_variables.get(variable, None)
        if old_unified is not None and old_unified is not unified:
            if old_unified.name is not None and not unified.renamed:
                unified.name = old_unified.name
                unified.renamed = old_unified.renamed

        self.variable_manager._unified_variables.add(unified)
        self.variable_manager._variables_to_unified_variables[variable] = unified

        if old_unified is not None and old_unified not in self.variable_manager._variables_to_unified_variables:
            self.variable_manager._unified_variables.discard(old_unified)

    def force_new_variable(self, var):
        self._set_unified_variable(var, var)
        unified_variable = None
        for other_var in self.variable_manager.get_variables():
            if other_var != var and self.variable_manager.unified_variable(other_var) == var:
                if not unified_variable:
                    unified_variable = other_var
                self._set_unified_variable(other_var, unified_variable)
        self.variable_manager.assign_unified_variable_names(
            labels=self.kb.labels,
            arg_names=self._func.prototype.arg_names if self._func.prototype else None,
            reset=True,
        )

    def _analyze(self, cache=None):
        for block in list(GraphUtils.quasi_topological_sort_nodes(self._graph, list(self._graph.nodes))):
            block: ailment.Block
            for stmt in block.statements:
                if isinstance(stmt, Store) and isinstance(stmt.data, Struct):
                    var = stmt.variable if stmt.variable is not None else stmt.addr.variable
                    self._set_variable_type(var, stmt.data.type)
                elif (
                    isinstance(stmt, Call)
                    and stmt.prototype
                    and isinstance(stmt.prototype.returnty, RustSimStruct)
                    and stmt.ret_expr
                ):
                    self._set_variable_type(stmt.ret_expr.variable, stmt.prototype.returnty)
                elif (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.src, Call)
                    and stmt.src.prototype
                    and is_composite_type(stmt.src.prototype.returnty)
                ):
                    self._set_variable_type(stmt.dst.variable, stmt.src.prototype.returnty)
                elif (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.src, FunctionLikeMacro)
                    and is_composite_type(stmt.src.returnty)
                ):
                    self._set_variable_type(stmt.dst.variable, stmt.src.returnty)
                elif (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and isinstance(stmt.src, VirtualVariable)
                ):
                    struct_ty = unpack_typeref(self.variable_manager.get_variable_type(stmt.src.variable))
                    if is_composite_type(struct_ty):
                        self._set_variable_type(stmt.dst.variable, struct_ty)

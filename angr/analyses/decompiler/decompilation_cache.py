from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .clinic import Clinic

if TYPE_CHECKING:
    from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor
    from angr.analyses.typehoon.typevars import TypeConstraint, TypeVariable

    from .structured_codegen import BaseStructuredCodeGenerator


class DecompilationCache:
    """
    Caches key data structures that can be used later for refining decompilation results, such as retyping variables.
    """

    __slots__ = (
        "addr",
        "arg_vvars",
        "binop_operators",
        "clinic",
        "codegen",
        "errors",
        "func_typevar",
        "function_summary",
        "ite_exprs",
        "max_tv_id",
        "notes",
        "parameters",
        "stack_offset_typevars",
        "stackvar_max_sizes",
        "type_constraints",
        "var_to_typevar",
    )

    def __init__(self, addr):
        self.parameters: dict[str, Any] = {}
        self.addr = addr
        self.type_constraints: dict[TypeVariable, set[TypeConstraint]] | None = None
        self.arg_vvars: dict | None = None
        self.func_typevar: TypeVariable | None = None
        self.var_to_typevar: dict | None = None
        self.stackvar_max_sizes: dict | None = None
        self.stack_offset_typevars: dict | None = None
        self.codegen: BaseStructuredCodeGenerator | None = None
        self.clinic: Clinic | None = None
        self.ite_exprs: set[tuple[int, Any]] | None = None
        self.binop_operators: dict[OpDescriptor, str] | None = None
        self.errors: list[str] = []
        self.function_summary: str | None = None
        self.notes: dict[str, str] = {}
        self.max_tv_id: int = 0

    @property
    def local_types(self):
        if self.clinic is None or self.clinic.variable_kb is None:
            return None
        return self.clinic.variable_kb.variables[self.addr].types

from __future__ import annotations
from typing import Any, TYPE_CHECKING

from .clinic import Clinic
from .structured_codegen import BaseStructuredCodeGenerator

if TYPE_CHECKING:
    from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor
    from angr.analyses.typehoon.typevars import TypeVariable, TypeConstraint


class DecompilationCache:
    """
    Caches key data structures that can be used later for refining decompilation results, such as retyping variables.
    """

    __slots__ = (
        "addr",
        "binop_operators",
        "clinic",
        "codegen",
        "errors",
        "func_typevar",
        "ite_exprs",
        "parameters",
        "type_constraints",
        "var_to_typevar",
    )

    def __init__(self, addr):
        self.parameters: dict[str, Any] = {}
        self.addr = addr
        self.type_constraints: dict[TypeVariable, set[TypeConstraint]] | None = None
        self.func_typevar: TypeVariable | None = None
        self.var_to_typevar: dict | None = None
        self.codegen: BaseStructuredCodeGenerator | None = None
        self.clinic: Clinic | None = None
        self.ite_exprs: set[tuple[int, Any]] | None = None
        self.binop_operators: dict[OpDescriptor, str] | None = None
        self.errors: list[str] = []

    @property
    def local_types(self):
        if self.clinic is None or self.clinic.variable_kb is None:
            return None
        return self.clinic.variable_kb.variables[self.addr].types

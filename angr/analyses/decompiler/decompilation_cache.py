from __future__ import annotations
from typing import Any, TYPE_CHECKING

from .clinic import Clinic
from .structured_codegen import BaseStructuredCodeGenerator

if TYPE_CHECKING:
    from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor


class DecompilationCache:
    """
    Caches key data structures that can be used later for refining decompilation results, such as retyping variables.
    """

    __slots__ = (
        "parameters",
        "addr",
        "type_constraints",
        "func_typevar",
        "var_to_typevar",
        "codegen",
        "clinic",
        "ite_exprs",
        "binop_operators",
        "errors",
    )

    def __init__(self, addr):
        self.parameters: dict[str, Any] = {}
        self.addr = addr
        self.type_constraints: set | None = None
        self.func_typevar = None
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

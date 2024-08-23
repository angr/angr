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
        "addr",
        "type_constraints",
        "func_typevar",
        "var_to_typevar",
        "codegen",
        "clinic",
        "ite_exprs",
        "binop_operators",
    )

    def __init__(self, addr):
        self.addr = addr
        self.type_constraints: set | None = None
        self.func_typevar = None
        self.var_to_typevar: dict | None = None
        self.codegen: BaseStructuredCodeGenerator | None = None
        self.clinic: Clinic | None = None
        self.ite_exprs: set[tuple[int, Any]] | None = None
        self.binop_operators: dict[OpDescriptor, str] | None = None

    @property
    def local_types(self):
        return self.clinic.variable_kb.variables[self.addr].types

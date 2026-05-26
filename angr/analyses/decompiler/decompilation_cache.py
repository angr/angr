from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .clinic import Clinic

if TYPE_CHECKING:
    from angr import ailment
    from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor
    from angr.analyses.typehoon.typevars import TypeConstraint, TypeVariable
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.cfg import CFGModel

    from .notes import DecompilationNote
    from .structured_codegen import BaseStructuredCodeGenerator
    from .variable_map import VariableMap


class DecompilationCache:
    """
    Caches key data structures that can be used later for refining decompilation results, such as retyping variables.
    """

    # ``cfg`` and ``variable_kb`` are not part of the decompilation result: they are inputs supplied by the parent
    # Project at decompile time and are used only for in-memory cache-validity checks. They are intentionally not
    # serialized; on deserialization they come back as None and must be re-attached by the caller.
    __slots__ = (
        "addr",
        "arg_vvars",
        "binop_operators",
        "cfg",
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
        "variable_kb",
        "variable_map",
    )

    def __init__(self, addr):
        self.parameters: dict[str, Any] = {}
        self.addr = addr
        self.cfg: CFGModel | None = None
        self.variable_kb: KnowledgeBase | None = None
        self.type_constraints: dict[TypeVariable, set[TypeConstraint]] | None = None
        self.arg_vvars: dict | None = None
        self.func_typevar: TypeVariable | None = None
        self.var_to_typevar: dict | None = None
        self.stackvar_max_sizes: dict | None = None
        self.stack_offset_typevars: dict | None = None
        self.codegen: BaseStructuredCodeGenerator | None = None
        self.clinic: Clinic | None = None
        self.variable_map: VariableMap | None = None
        self.ite_exprs: set[tuple[int, ailment.Expression]] | None = None
        self.binop_operators: dict[OpDescriptor, str] | None = None
        self.errors: list[str] = []
        self.function_summary: str | None = None
        self.notes: dict[str, DecompilationNote] = {}
        self.max_tv_id: int = 0

    @property
    def local_types(self):
        if self.clinic is None or self.clinic.variable_kb is None:
            return None
        return self.clinic.variable_kb.variables[self.addr].types

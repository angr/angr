from __future__ import annotations
from collections import defaultdict

from angr.analyses.typehoon.typeconsts import TypeConstant
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.rust.typehoon.translator import RustTypeTranslator


class TypeHints(KnowledgeBasePlugin):
    """Store type hints for virtual variables inferred from Rust patterns."""

    def __init__(self, kb):
        super().__init__(kb)
        self.vvar_type_hints_by_func: defaultdict[int, dict[int, TypeConstant]] = defaultdict(dict)
        self._translator = RustTypeTranslator(self._kb._project.arch)

    def add_type_hint(self, vvar, ty, func_addr: int) -> None:
        ty_const = self._translator.simtype2tc(ty)
        self.vvar_type_hints_by_func[func_addr][vvar.varid] = ty_const

    def get_type_hints(self, func_addr: int) -> dict[int, TypeConstant]:
        return dict(self.vvar_type_hints_by_func.get(func_addr, {}))

    def copy(self) -> TypeHints:
        o = TypeHints(self._kb)
        o.vvar_type_hints_by_func = defaultdict(
            dict, {func_addr: dict(type_hints) for func_addr, type_hints in self.vvar_type_hints_by_func.items()}
        )
        return o


KnowledgeBasePlugin.register_default("type_hints", TypeHints)

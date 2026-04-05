from __future__ import annotations
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.rust.typehoon.translator import RustTypeTranslator


class TypeHints(KnowledgeBasePlugin):
    """Store type hints for virtual variables inferred from Rust patterns."""

    def __init__(self, kb):
        super().__init__(kb)
        self.vvar_type_hints = {}
        self._translator = RustTypeTranslator(self._kb._project.arch)

    def add_type_hint(self, vvar, ty):
        ty_const = self._translator.simtype2tc(ty)
        self.vvar_type_hints[vvar.varid] = ty_const


KnowledgeBasePlugin.register_default("type_hints", TypeHints)

from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.rust.typehoon.lifter import RustTypeLifter


class TypeHints(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__(kb)
        self.vvar_type_hints = {}
        self._lifter = RustTypeLifter(self._kb._project.arch.bits)

    def add_type_hint(self, vvar, ty):
        ty_const = self._lifter.lift(ty)
        self.vvar_type_hints[vvar.varid] = ty_const


KnowledgeBasePlugin.register_default("type_hints", TypeHints)

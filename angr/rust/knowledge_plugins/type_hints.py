from ...knowledge_plugins.plugin import KnowledgeBasePlugin


class TypeHints(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__(kb)
        self.test = []


KnowledgeBasePlugin.register_default("type_hints", TypeHints)

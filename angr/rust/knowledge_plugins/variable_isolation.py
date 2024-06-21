from ...knowledge_plugins.plugin import KnowledgeBasePlugin


class VariableIsolation(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__(kb)
        self.unified_variables = {}


KnowledgeBasePlugin.register_default("variable_isolation", VariableIsolation)

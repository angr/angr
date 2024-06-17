from ...knowledge_plugins.plugin import KnowledgeBasePlugin


class ArgumentIsolation(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__(kb)
        self.unified_arg_variables = {}


KnowledgeBasePlugin.register_default("argument_isolation", ArgumentIsolation)

from .plugin import KnowledgeBasePlugin


class Data(KnowledgeBasePlugin):
    def copy(self):
        raise NotImplementedError


KnowledgeBasePlugin.register_default("data", Data)

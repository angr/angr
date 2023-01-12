from .plugin import KnowledgeBasePlugin


class Data(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__()
        self._kb = kb

    def copy(self):
        raise NotImplementedError


KnowledgeBasePlugin.register_default("data", Data)

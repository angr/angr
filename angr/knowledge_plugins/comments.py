from .plugin import KnowledgeBasePlugin


class Comments(KnowledgeBasePlugin, dict):

    def __init__(self, kb):
        super(Comments, self).__init__()
        self._kb = kb

    def copy(self):
        o = Comments(self._kb)
        o.update({k: v for k, v in self.items()})


KnowledgeBasePlugin.register_default('comments', Comments)

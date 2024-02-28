from .plugin import KnowledgeBasePlugin


class Comments(KnowledgeBasePlugin, dict):
    def copy(self):
        o = Comments(self._kb)
        o.update(self)
        return o


KnowledgeBasePlugin.register_default("comments", Comments)

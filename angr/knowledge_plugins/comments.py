from .plugin import KnowledgeBasePlugin


class Comments(KnowledgeBasePlugin, dict):

    def __init__(self, kb=None):
        super(Comments, self).__init__(kb)

    def copy(self):
        o = Comments()
        o.update({k: v for k, v in self.iteritems()})
        return o

from .plugin import KnowledgeBasePlugin


class Comments(KnowledgeBasePlugin, dict):

    def __init__(self):
        super(Comments, self).__init__()

    def copy(self):
        o = Comments()
        o.update({k: v for k, v in self.iteritems()})


KnowledgeBasePlugin.register_default('comments', Comments)

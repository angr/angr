from .plugin import KnowledgeBasePlugin


class Data(KnowledgeBasePlugin):

    def __init__(self, kb=None):
        super(Data, self).__init__(kb)

    def copy(self):
        raise NotImplementedError

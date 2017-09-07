from .plugin import KnowledgeBasePlugin


class Data(KnowledgeBasePlugin):

    def __init__(self):
        super(Data, self).__init__()

    def copy(self):
        raise NotImplementedError


KnowledgeBasePlugin.register_default('data', Data)

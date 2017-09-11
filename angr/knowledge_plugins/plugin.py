

class KnowledgeBasePlugin(object):

    def __init__(self, kb):
        self._kb = kb

    def copy(self):
        raise NotImplementedError



class KnowledgeBaseView(object):

    def __init__(self, kb):
        self._kb = kb

    def reconstruct(self):
        pass

    def copy(self):
        raise NotImplementedError

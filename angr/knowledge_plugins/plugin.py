

class KnowledgeBasePlugin(object):
    """
    This is a knowledge base plugin.

    The purpose of this class is to provide a generic interface for plugin registration,
    by requiering the `kb` as a mandatory argument.
    """

    def __init__(self, kb):
        super(KnowledgeBasePlugin, self).__init__()
        self._kb = kb

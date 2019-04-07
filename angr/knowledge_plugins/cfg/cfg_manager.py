
from ..plugin import KnowledgeBasePlugin


class CFGManager(KnowledgeBasePlugin):

    def __init__(self):
        pass


KnowledgeBasePlugin.register_default("cfgs", CFGManager)

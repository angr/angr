from .plugin import KnowledgeBasePlugin


class IndirectJumps(KnowledgeBasePlugin, dict):

    def __init__(self, kb=None):
        super(IndirectJumps, self).__init__(kb)
        self.resolved = set()
        self.unresolved = set()

    def copy(self):
        o = IndirectJumps()
        o.resolved.update(self.resolved)
        o.unresolved.update(self.unresolved)

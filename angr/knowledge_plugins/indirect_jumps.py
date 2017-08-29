from .plugin import KnowledgeBasePlugin


class IndirectJumps(KnowledgeBasePlugin, dict):

    def __init__(self, kb):
        super(IndirectJumps, self).__init__()
        self._kb = kb
        self.resolved = set()
        self.unresolved = set()

    def copy(self):
        o = IndirectJumps(self._kb)
        o.resolved.update(self.resolved)
        o.unresolved.update(self.unresolved)


KnowledgeBasePlugin.register_default('indirect_jumps', IndirectJumps)

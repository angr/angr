from .plugin import KnowledgeBasePlugin


class IndirectJumps(KnowledgeBasePlugin, dict):

    def __init__(self, kb):
        super(IndirectJumps, self).__init__()
        self._kb = kb
        self.resolved = set()
        self.unresolved = set()

        # variable for storing addresses actively being resolved
        # dict format:    {indirect_addr: [resolved_addr]}
        self.active_resolves = {}

    def copy(self):
        o = IndirectJumps(self._kb)
        o.resolved.update(self.resolved)
        o.unresolved.update(self.unresolved)
        o.active_resolves = self.active_resolves


KnowledgeBasePlugin.register_default('indirect_jumps', IndirectJumps)

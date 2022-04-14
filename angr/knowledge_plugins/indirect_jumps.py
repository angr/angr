from typing import List

from .plugin import KnowledgeBasePlugin


class IndirectJumps(KnowledgeBasePlugin, dict):

    def __init__(self, kb):
        super(IndirectJumps, self).__init__()
        self._kb = kb
        self.unresolved = set()

        # dict format: {indirect_address: [resolved_addresses]}
        self.resolved = {}

    def copy(self):
        o = IndirectJumps(self._kb)
        o.unresolved.update(self.unresolved)
        o.resolved = {}
        for k, v in self.resolved.items():
            o.resolved[k] = v

    def update_resolved_addrs(self, indirect_address: int, resolved_addresses: List[int]):
        # sanity check on usage
        if indirect_address is None:
            return

        if indirect_address in self.resolved:
            self.resolved[indirect_address] += list(resolved_addresses)
        else:
            self.resolved[indirect_address] = list(resolved_addresses)


KnowledgeBasePlugin.register_default('indirect_jumps', IndirectJumps)

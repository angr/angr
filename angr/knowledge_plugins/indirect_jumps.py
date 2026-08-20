from __future__ import annotations

from .plugin import KnowledgeBasePlugin


class IndirectJumps(KnowledgeBasePlugin, dict):
    """
    This plugin tracks the targets of indirect jumps.

    It is a dict of :class:`IndirectJump` records describing each indirect jump or call site that control-flow
    recovery encountered, keyed by the address of the block the site ends. Alongside those records it keeps the
    resolution outcome for each site: ``resolved`` maps a block address to the targets recovered for it, and
    ``unresolved`` holds the block addresses of the sites nothing could resolve. Note that a site resolved by a
    timeless resolver appears in ``resolved`` without a record of its own, since no record is ever built for it.
    """

    def __init__(self, kb):
        super().__init__(kb=kb)
        self.unresolved = set()

        # dict format: {indirect_address: [resolved_addresses]}
        self.resolved = {}

    def copy(self):
        o = IndirectJumps(self._kb)
        o.update(self)
        o.unresolved.update(self.unresolved)
        o.resolved = {k: list(v) for k, v in self.resolved.items()}
        return o

    def update_resolved_addrs(self, indirect_address: int, resolved_addresses: list[int]):
        # sanity check on usage
        if indirect_address is None:
            return

        if indirect_address in self.resolved:
            self.resolved[indirect_address] += list(resolved_addresses)
        else:
            self.resolved[indirect_address] = list(resolved_addresses)


KnowledgeBasePlugin.register_default("indirect_jumps", IndirectJumps)

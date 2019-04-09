
from ..plugin import KnowledgeBasePlugin


class Clinic(KnowledgeBasePlugin):
    def __init__(self, kb):

        self._kb = kb

        # A mapping from function addresses (or names if addresses are not available) to their decompiled output
        self.func_abstractions = { }

    def __setitem__(self, func_addr, abstraction):
        self.func_abstractions[func_addr] = abstraction

    def __getitem__(self, func_addr):
        return self.func_abstractions[func_addr]

    def __len__(self):
        return len(self.func_abstractions)

    def get_node(self, addr):
        # TODO: Optimize the implementation. We probably want to index all blocks inside functions.
        for node in self.func_abstractions.values():
            n = self._get_node(addr, node)
            if n is not None:
                return n
        return None

    def _get_node(self, addr, node):
        if node.addr == addr:
            return node
        for child in node.children:
            n = self._get_node(addr, child)
            if n is not None:
                return n
        return None


KnowledgeBasePlugin.register_default('clinic', Clinic)

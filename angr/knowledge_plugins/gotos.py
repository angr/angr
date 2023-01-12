from typing import Dict, Set
from collections import defaultdict

from .plugin import KnowledgeBasePlugin


class Goto:
    """
    Describe the existence of a goto (jump) statement.
    """

    def __init__(self, addr=None, target_addr=None):
        """
        addr: block_addr of the goto
        target_addr: target block address of the goto
        """
        self.addr = addr
        self.target_addr = target_addr

    def __hash__(self):
        return hash(f"{self.addr}{self.target_addr}")

    def __str__(self):
        if not self.addr or not self.target_addr:
            return f"<Goto {self.__hash__()}>"

        return f"<Goto: {hex(self.addr)} -> {hex(self.target_addr)}>"

    def __repr__(self):
        return self.__str__()


class Gotos(KnowledgeBasePlugin, dict):
    """
    Stores all goto (jump) statements of a project.
    """

    def __init__(self, kb):
        super().__init__()
        self._kb = kb
        # dict format: {func_addr: {goto}}
        self.locations: Dict[int, Set[Goto]] = defaultdict(set)

    def copy(self):
        g = Gotos(self._kb)
        g.locations = defaultdict(set)
        for k, v in self.locations.items():
            g.locations[k] = v.copy()

    def __str__(self):
        return f"<GotosKb: {len(self.locations)} functions>"

    def __repr__(self):
        return self.__str__()


KnowledgeBasePlugin.register_default("gotos", Gotos)

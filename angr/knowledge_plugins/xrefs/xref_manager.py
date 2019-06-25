
from collections import defaultdict

from ..plugin import KnowledgeBasePlugin


class XRefManager(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__()
        self._kb = kb

        self.xrefs_by_src = defaultdict(set)
        self.xrefs_by_dst = defaultdict(set)

    def add_xref(self, xref):
        self.xrefs_by_src[xref.src].add(xref)
        self.xrefs_by_dst[xref.dst].add(xref)

    def get_xrefs_by_src(self, src):
        return self.xrefs_by_src.get(src, set())

    def get_xrefs_by_dst(self, dst):
        return self.xrefs_by_dst.get(dst, set())


KnowledgeBasePlugin.register_default('xrefs', XRefManager)

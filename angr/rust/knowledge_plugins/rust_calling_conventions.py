from collections import defaultdict
from pprint import pformat

from ...knowledge_plugins.plugin import KnowledgeBasePlugin


class RustCallingConventionModel:
    def __init__(self):
        self.memory_writes = defaultdict(dict)
        self.callsite_memory_writes = defaultdict(dict)
        self.memory_reads = defaultdict(dict)
        self.inferred_prototype = None
        self.clinic = None
        self.caller_graph = None

    def __str__(self):
        return pformat({"Inferred prototype: ": self.inferred_prototype}, indent=2)


class RustCallingConventions(KnowledgeBasePlugin):
    def __init__(self, kb):
        super().__init__(kb)
        self.cache = {}


KnowledgeBasePlugin.register_default("rust_calling_conventions", RustCallingConventions)

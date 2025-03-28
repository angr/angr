from ...knowledge_plugins.plugin import KnowledgeBasePlugin


class KnownStructs(KnowledgeBasePlugin):

    STR_SLICE = "&str"
    SIMPLE_MESSAGE = "SimpleMessage"
    KNOWN_STRUCT_NAMES = (STR_SLICE, SIMPLE_MESSAGE)

    def __init__(self, kb):
        super().__init__(kb)
        self.cache = {}

    def __iter__(self):
        return iter(self.cache)

    def __setitem__(self, key, value):
        self.cache[key] = value

    def __getitem__(self, item):
        return self.cache.get(item, None)

    def __contains__(self, item):
        return item in self.cache


KnowledgeBasePlugin.register_default("known_structs", KnownStructs)

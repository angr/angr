from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.procedures.definitions import SimLibrary


class Librust(KnowledgeBasePlugin, SimLibrary):
    def __init__(self, kb):
        super().__init__(kb)
        SimLibrary.__init__(self)
        self.set_library_names("librust")


KnowledgeBasePlugin.register_default("librust", Librust)

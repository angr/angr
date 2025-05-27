from collections import defaultdict

from ..definitions.prototypes import generate_known_rust_prototypes
from ..utils.library import normalize
from ...knowledge_plugins.plugin import KnowledgeBasePlugin
from ...procedures.definitions import SimLibrary


class Librust(KnowledgeBasePlugin, SimLibrary):
    def __init__(self, kb):
        super().__init__(kb)
        SimLibrary.__init__(self)
        self.set_library_names("librust")
        self.regenerate()

    def regenerate(self):
        functions = defaultdict(list)
        for addr in self._kb.functions:
            func = self._kb.functions[addr]
            functions[normalize(func.demangled_name, monopolize=True, use_trait_name=True)].append(func)
        for name, prototype in generate_known_rust_prototypes(self._kb._project).items():
            self.set_prototype(name, prototype)
            for func in functions[name]:
                try:
                    func.prototype = prototype.with_arch(self._kb._project.arch)
                except:
                    import ipdb

                    ipdb.set_trace()


KnowledgeBasePlugin.register_default("librust", Librust)

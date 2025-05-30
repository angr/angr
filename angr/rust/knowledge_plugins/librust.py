from collections import defaultdict

from angr.rust.definitions.prototypes import generate_known_rust_prototypes
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.procedures.definitions import SimLibrary


class Librust(KnowledgeBasePlugin, SimLibrary):
    def __init__(self, kb):
        super().__init__(kb)
        SimLibrary.__init__(self)
        self.set_library_names("librust")

        self.project = self._kb._project

        self._name_to_func = defaultdict(list)
        for addr in self._kb.functions:
            func = self._kb.functions[addr]
            self._name_to_func[func.demangled_name].append(func)

        self.regenerate()

    def regenerate(self):
        for name, prototype in generate_known_rust_prototypes(self.project).items():
            if name not in self._name_to_func:
                continue
            prototype = prototype.with_arch(self.project.arch)
            for func in self._name_to_func[name]:
                func.prototype = prototype
            self.set_prototype(name, prototype)


KnowledgeBasePlugin.register_default("librust", Librust)

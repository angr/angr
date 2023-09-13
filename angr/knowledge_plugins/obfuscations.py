from .plugin import KnowledgeBasePlugin


class Obfuscations(KnowledgeBasePlugin):
    """
    Store discovered information and artifacts about (string) obfuscation techniques in the project.
    """

    def __init__(self, kb):
        super().__init__()
        self._kb = kb

        self.type1_deobfuscated_strings = {}
        self.type1_string_loader_candidates = set()
        self.type2_deobfuscated_strings = {}
        self.type2_string_loader_candidates = set()

    def copy(self):
        o = Obfuscations(self._kb)
        o.type1_deobfuscated_strings = dict(self.type1_deobfuscated_strings)
        o.type1_string_loader_candidates = self.type1_string_loader_candidates.copy()
        o.type2_deobfuscated_strings = dict(self.type2_deobfuscated_strings)
        o.type2_string_loader_candidates = self.type2_string_loader_candidates.copy()
        return o


KnowledgeBasePlugin.register_default("obfuscations", Obfuscations)

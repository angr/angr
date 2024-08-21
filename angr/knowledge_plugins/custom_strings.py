from .plugin import KnowledgeBasePlugin


class CustomStrings(KnowledgeBasePlugin):
    """
    Store new strings that are recovered during various analysis. Each string has a unique ID associated.
    """

    def __init__(self, kb):
        super().__init__(kb=kb)

        self.string_id = 0
        self.strings: dict[int, bytes] = {}

    def allocate(self, s: bytes) -> int:
        # de-duplication
        # TODO: Use a reverse map if this becomes a bottle-neck in the future
        for idx, string in self.strings.items():
            if string == s:
                return idx

        string_id = self.string_id
        self.strings[string_id] = s
        self.string_id += 1
        return string_id

    def __getitem__(self, idx):
        return self.strings[idx]

    def copy(self):
        o = CustomStrings(self._kb)
        o.strings = self.strings.copy()
        o.string_id = self.string_id
        return o


KnowledgeBasePlugin.register_default("custom_strings", CustomStrings)

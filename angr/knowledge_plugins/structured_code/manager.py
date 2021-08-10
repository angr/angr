from typing import TYPE_CHECKING

from .. import KnowledgeBasePlugin

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.analyses.decompiler.structured_codegen import StructuredCodeGenerator


class StructuredCodeManager(KnowledgeBasePlugin):
    def __init__(self, kb):
        self._kb = kb  # type: KnowledgeBase
        self.codegens = {}

    def _normalize_key(self, item):
        if type(item) is not tuple:
            raise TypeError("Structured code can only be queried by tuples of (func, flavor)")
        if type(item[0]) is str:
            item = (self._kb.labels.lookup(item[0]), *item[1:])
        return item

    def __getitem__(self, item) -> 'StructuredCodeGenerator':
        return self.codegens[self._normalize_key(item)]

    def __setitem__(self, key, value):
        self.codegens[self._normalize_key(key)] = value

    def __contains__(self, key):
        return self._normalize_key(key) in self.codegens

    def available_flavors(self, item):
        if type(item) is str:
            item = self._kb.labels.lookup(item)
        return [flavor for func, flavor in self.codegens if func == item]

    def copy(self):
        raise NotImplementedError


KnowledgeBasePlugin.register_default('structured_code', StructuredCodeManager)

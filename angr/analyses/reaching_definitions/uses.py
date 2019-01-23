
from collections import defaultdict


class Uses:

    __slots__ = ('_uses_by_definition', )

    def __init__(self):
        self._uses_by_definition = defaultdict(set)

    def add_use(self, definition, codeloc):
        self._uses_by_definition[definition].add(codeloc)

    def get_uses(self, definition):
        if definition not in self._uses_by_definition:
            return set()
        return self._uses_by_definition[definition]

    def copy(self):
        u = Uses()
        u._uses_by_definition = self._uses_by_definition.copy()

        return u

    def merge(self, other):
        for k, v in other._uses_by_definition.items():
            if k not in self._uses_by_definition:
                self._uses_by_definition[k] = v
            else:
                self._uses_by_definition[k] |= v

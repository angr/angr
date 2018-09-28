
from collections import defaultdict

from ...keyed_region import KeyedRegion


class Uses(object):
    def __init__(self):
        self._uses_by_definition = defaultdict(set)
        self._current_uses = KeyedRegion()

    def add_use(self, definition, codeloc):
        self._uses_by_definition[definition].add(codeloc)
        self._current_uses.set_object(definition.offset, definition, definition.size)

    def get_uses(self, definition):
        if definition not in self._uses_by_definition:
            return set()
        return self._uses_by_definition[definition]

    def get_current_uses(self, definition):
        # TODO: optimize it
        all_uses = set()

        offset = definition.offset
        for pos in range(definition.size):
            all_uses |= set(self._current_uses.get_objects_by_offset(offset + pos))

        return all_uses

    def copy(self):
        u = Uses()
        u._uses_by_definition = self._uses_by_definition.copy()
        u._current_uses = self._current_uses.copy()

        return u

    def merge(self, other):

        for k, v in other._uses_by_definition.items():
            if k not in self._uses_by_definition:
                self._uses_by_definition[k] = v
            else:
                self._uses_by_definition[k] |= v

        self._current_uses.merge(other._current_uses)

from typing import Dict, Set

import claripy


class MultiValues:

    __slots__ = ('values', )

    def __init__(self, offset_to_values=None):
        self.values: Dict[int,Set[claripy.ast.Base]] = offset_to_values if offset_to_values is not None else { }

        # sanity check
        for vs in self.values.values():
            if not isinstance(vs, set):
                raise TypeError("Each value in offset_to_values must be a set!")

    def add_value(self, offset, value) -> None:
        if offset not in self.values:
            self.values[offset] = set()
        self.values[offset].add(value)

    def one_value(self):
        if len(self.values) == 1 and len(self.values[0]) == 1:
            return next(iter(self.values[0]))
        return None

    def __len__(self) -> int:
        max_offset = max(self.values.keys())
        max_len = max(x.size() for x in self.values[max_offset])
        return max_len

    def merge(self, mv: 'MultiValues') -> 'MultiValues':
        new_mv = MultiValues(offset_to_values=self.values)
        for off, vs in mv.values.items():
            if off not in new_mv.values:
                new_mv.values[off] = set(vs)
            else:
                new_mv.values[off] |= vs
        return new_mv

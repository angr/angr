from typing import Dict, Optional, Set

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

    def one_value(self) -> Optional[claripy.ast.Base]:
        if len(self.values) == 1 and len(self.values[0]) == 1:
            return next(iter(self.values[0]))
        return None

    def __len__(self) -> int:
        max_offset = max(self.values.keys())
        max_len = max(x.size() for x in self.values[max_offset])
        return max_offset * 8 + max_len  # FIXME: we are assuming byte_width of 8

    def merge(self, mv: 'MultiValues') -> 'MultiValues':
        new_mv = MultiValues(offset_to_values=self.values)
        for off, vs in mv.values.items():
            if off not in new_mv.values:
                new_mv.values[off] = set(vs)
            else:
                new_mv.values[off] |= vs
        return new_mv

    def __eq__(self, other) -> bool:
        if not isinstance(other, MultiValues):
            return False
        if set(self.values.keys()) != set(other.values.keys()):
            return False
        for k in self.values.keys():
            if self.values[k] != other.values[k]:
                return False
        return True

    def __repr__(self):
        return f"<{self.__class__.__name__}({self.values})>"

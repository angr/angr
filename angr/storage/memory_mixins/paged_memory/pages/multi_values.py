from typing import Dict, Set

import claripy


class MultiValues:

    __slots__ = ('values', )

    def __init__(self, offset_to_values=None):
        self.values: Dict[int,Set[claripy.ast.Base]] = offset_to_values if offset_to_values is not None else { }

    def add_value(self, offset, value) -> None:
        if offset not in self.values:
            self.values[offset] = set()
        self.values[offset].add(value)

    def one_value(self):
        if len(self.values) == 1 and len(self.values[0]) == 1:
            return next(iter(self.values[0]))
        return None

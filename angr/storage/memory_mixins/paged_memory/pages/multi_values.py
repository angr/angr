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

    def add_value(self, offset: int, value: claripy.ast.Base) -> None:
        if offset not in self.values:
            self.values[offset] = set()

        # if value overlaps with existing values, we need to break them down

        succ_offset = self._adjacent_offset(offset, before=False)
        if succ_offset is not None:
            value_end = offset + value.length // 8
            if value_end > succ_offset:
                # value is too long. we need to break value into two
                mid_value_size = succ_offset - offset
                remaining_value = value[value.length - mid_value_size * 8 - 1 : 0]
                # update value
                value = value[value.length - 1: value.length - mid_value_size * 8]
                self.add_value(succ_offset, remaining_value)

        if self.values[offset]:
            curr_value_size = next(iter(self.values[offset])).length // 8
            if curr_value_size > value.length // 8:
                # we need to break existing values
                new_curr_values = set()
                remaining_values = set()
                for v in self.values[offset]:
                    new_curr_values.add(v[v.length - 1 : v.length - value.length])
                    remaining_values.add(v[v.length - value.length - 1 : 0])
                self.values[offset] = new_curr_values
                for v in remaining_values:
                    self.add_value(offset + value.length // 8, v)
            elif curr_value_size < value.length // 8:
                # value is too long. we need to break value into two
                remaining_value = value[value.length - curr_value_size * 8 - 1 : 0]
                # update value
                value = value[value.length - 1 : value.length - curr_value_size * 8]
                self.add_value(offset + curr_value_size, remaining_value)

        self.values[offset].add(value)

        pre_offset = self._adjacent_offset(offset, before=True)
        if pre_offset is not None:
            pre_values = self.values[pre_offset]
            pre_values_size = next(iter(pre_values)).length // 8
            if pre_offset + pre_values_size > offset:
                # we need to break the preceding values
                new_pre_value_size = offset - pre_offset
                new_pre_values = set()
                remaining_values = set()
                for v in pre_values:
                    new_pre_values.add(v[v.length - 1 : v.length - new_pre_value_size * 8])
                    remaining_values.add(v[v.length - new_pre_value_size * 8 - 1 : 0])
                self.values[pre_offset] = new_pre_values
                for v in remaining_values:
                    self.add_value(offset, v)

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

    #
    # Private methods
    #

    def _adjacent_offset(self, offset: int, before: bool=True) -> Optional[int]:
        """
        Find the offset that is right before or after the given offset.

        :param offset:  The specified offset.
        :param before:  True if we want to find the offset right before the specified offset, False if we want to find
                        the offset right after the specified offset.
        :return:        The adjacent offset as requested. If the requested adjacent offset does not exist, return None.
        """

        sorted_offsets = list(sorted(self.values.keys()))

        for i, off in enumerate(sorted_offsets):
            if off == offset:
                if before:
                    return sorted_offsets[i - 1] if i > 0 else None
                else:
                    return sorted_offsets[i + 1] if i + 1 < len(sorted_offsets) else None
            if off > offset:
                # we missed it...
                return None
        return None

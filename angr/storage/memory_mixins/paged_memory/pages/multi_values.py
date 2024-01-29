from typing import Dict, Optional, Set, Tuple, Iterator, Union
import archinfo

import claripy

from angr.storage.memory_object import bv_slice


class MultiValues:
    """
    Represents a byte vector where each byte can have one or multiple values.

    As an implementation optimization (so that we do not create excessive sets and dicts), self._single_value stores a
    claripy AST when this MultiValues object represents only one value at offset 0.
    """

    __slots__ = (
        "_values",
        "_single_value",
    )

    _single_value: Optional[claripy.ast.Bits]
    _values: Optional[Dict[int, Set[claripy.ast.Bits]]]

    def __init__(
        self,
        v: Union[claripy.ast.Bits, "MultiValues", None, Dict[int, Set[claripy.ast.Bits]]] = None,
        offset_to_values=None,
    ):
        if v is not None and offset_to_values is not None:
            raise TypeError("You cannot specify v and offset_to_values at the same time!")

        self._single_value = (
            None
            if v is None
            else v if isinstance(v, claripy.ast.Bits) else v._single_value if isinstance(v, MultiValues) else None
        )
        self._values = (
            offset_to_values
            if offset_to_values is not None
            else v if isinstance(v, dict) else v._values if isinstance(v, MultiValues) else None
        )

        if self._single_value is None and self._values is None:
            self._values = {}

        # if only one value is passed in, assign it to self._single_value
        if self._values:
            if len(self._values) == 1 and 0 in self._values and len(self._values[0]) == 1:
                self._single_value = next(iter(self._values[0]))
                self._values = None

        if self._values:
            # sanity check
            for vs in self._values.values():
                if not isinstance(vs, set):
                    raise TypeError("Each value in offset_to_values must be a set!")

    def add_value(self, offset: int, value: claripy.ast.Bits) -> None:
        if len(value) == 0:
            return
        if self._single_value is not None:
            if len(self._single_value) == 0:
                if offset == 0:
                    self._single_value = value
                else:
                    self._single_value = None
                    self._values = {offset: {value}}
                return
            self._values = {0: {self._single_value}}
            self._single_value = None

        if self._values is None:
            self._values = {}

        if offset not in self._values:
            self._values[offset] = set()

        # if value overlaps with existing values, we need to break them down

        succ_offset = self._adjacent_offset(offset, before=False)
        if succ_offset is not None:
            value_end = offset + value.length // 8
            if value_end > succ_offset:
                # value is too long. we need to break value into two
                mid_value_size = succ_offset - offset
                remaining_value = value[value.length - mid_value_size * 8 - 1 : 0]
                # update value
                value = value[value.length - 1 : value.length - mid_value_size * 8]
                self.add_value(succ_offset, remaining_value)

        if self._values[offset]:
            curr_value_size = next(iter(self._values[offset])).length // 8
            if curr_value_size > value.length // 8:
                # we need to break existing values
                new_curr_values = set()
                remaining_values = set()
                for v in self._values[offset]:
                    new_curr_values.add(v[v.length - 1 : v.length - value.length])
                    remaining_values.add(v[v.length - value.length - 1 : 0])
                self._values[offset] = new_curr_values
                for v in remaining_values:
                    self.add_value(offset + value.length // 8, v)
            elif curr_value_size < value.length // 8:
                # value is too long. we need to break value into two
                remaining_value = value[value.length - curr_value_size * 8 - 1 : 0]
                # update value
                value = value[value.length - 1 : value.length - curr_value_size * 8]
                self.add_value(offset + curr_value_size, remaining_value)

        self._values[offset].add(value)

        pre_offset = self._adjacent_offset(offset, before=True)
        if pre_offset is not None:
            pre_values = self._values[pre_offset]
            pre_values_size = next(iter(pre_values)).length // 8
            if pre_offset + pre_values_size > offset:
                # we need to break the preceding values
                new_pre_value_size = offset - pre_offset
                new_pre_values = set()
                remaining_values = set()
                for v in pre_values:
                    new_pre_values.add(v[v.length - 1 : v.length - new_pre_value_size * 8])
                    remaining_values.add(v[v.length - new_pre_value_size * 8 - 1 : 0])
                self._values[pre_offset] = new_pre_values
                for v in remaining_values:
                    self.add_value(offset, v)

    def one_value(self, strip_annotations: bool = False) -> Optional[claripy.ast.Bits]:
        if self._single_value is not None:
            return self._single_value

        assert self._values is not None

        if len(self._values) == 1 and len(self._values[0]) == 1:
            return next(iter(self._values[0]))
        if strip_annotations:
            all_values_wo_annotations = {
                bv.remove_annotations(bv.annotations) if bv.annotations else bv for bv in self._values[0]
            }
            if len(all_values_wo_annotations) == 1:
                return next(iter(all_values_wo_annotations))
        return None

    def __len__(self) -> int:
        if self._single_value is not None:
            return self._single_value.length

        assert self._values is not None

        if len(self._values) == 0:
            return 0

        max_offset = max(self._values.keys())
        max_len = max(x.size() for x in self._values[max_offset])
        return max_offset * 8 + max_len  # FIXME: we are assuming byte_width of 8

    def merge(self, mv: "MultiValues") -> "MultiValues":
        new_values = {k: set(v) for k, v in self.items()}
        for off, vs in mv.items():
            if off not in new_values:
                new_values[off] = set(vs)
            else:
                new_values[off] |= vs
        return MultiValues(offset_to_values=new_values)

    def __eq__(self, other) -> bool:
        if not isinstance(other, MultiValues):
            return False
        if self._single_value is not None and other._single_value is not None:
            return self._single_value is other._single_value
        if self._single_value is not None and other._single_value is None:
            return False
        if self._single_value is None and other._single_value is not None:
            return False
        assert self._values is not None
        assert other._values is not None
        if set(self._values.keys()) != set(other._values.keys()):
            return False
        for k in self._values.keys():
            if self._values[k] != other._values[k]:
                return False
        return True

    def __repr__(self):
        if self._single_value is not None:
            return f"<{self.__class__.__name__}({self._single_value})>"
        return f"<{self.__class__.__name__}({self._values})>"

    def __contains__(self, offset: int) -> bool:
        if self._single_value is not None:
            return offset == 0
        return False if not self._values else offset in self._values

    def __getitem__(self, offset: int) -> Set[claripy.ast.Bits]:
        if self._single_value is not None:
            if offset == 0:
                return {self._single_value}
            raise KeyError()
        elif not self._values:
            raise KeyError()
        return self._values[offset]

    def keys(self) -> Set[int]:
        if self._single_value is not None:
            return {0}
        return set() if not self._values else set(self._values.keys())

    def values(self) -> Iterator[Set[claripy.ast.Bits]]:
        if self._single_value is not None:
            yield {self._single_value}
        else:
            if self._values is None:
                return
            yield from self._values.values()

    def items(self) -> Iterator[Tuple[int, Set[claripy.ast.Bits]]]:
        if self._single_value is not None:
            yield 0, {self._single_value}
        else:
            if self._values is None:
                yield 0, set()
            else:
                yield from self._values.items()

    def count(self) -> int:
        if self._single_value is not None:
            return 1
        if self._values is None:
            return 0
        return len(self._values)

    def extract(self, offset: int, length: int, endness: str) -> "MultiValues":
        end = offset + length
        result = MultiValues(claripy.BVV(b""))
        for obj_offset, values in self.items():
            if obj_offset >= end:
                break
            for value in values:
                obj_length = len(value) // 8
                if obj_offset + obj_length < offset:
                    continue

                slice_start = max(0, offset - obj_offset)
                slice_end = min(obj_length, end - obj_offset)
                sliced = bv_slice(value, slice_start, slice_end - slice_start, endness == archinfo.Endness.LE, 8)
                if len(sliced):
                    result.add_value(max(0, obj_offset - offset), sliced)

        return result

    def concat(self, other: Union["MultiValues", claripy.ast.Bits, bytes]) -> "MultiValues":
        if isinstance(other, bytes):
            other = claripy.BVV(other)
        if isinstance(other, claripy.ast.Bits):
            other = MultiValues(other)
        offset = len(self) // 8
        result = MultiValues(self)
        for k, v in other.items():
            for v2 in v:
                result.add_value(k + offset, v2)
        return result

    #
    # Private methods
    #

    def _adjacent_offset(self, offset: int, before: bool = True) -> Optional[int]:
        """
        Find the offset that is right before or after the given offset.

        :param offset:  The specified offset.
        :param before:  True if we want to find the offset right before the specified offset, False if we want to find
                        the offset right after the specified offset.
        :return:        The adjacent offset as requested. If the requested adjacent offset does not exist, return None.
        """

        sorted_offsets = list(sorted(self._values.keys())) if self._values is not None else [0]

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

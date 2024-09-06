from __future__ import annotations
import copy
from typing import Any

from .. import MemoryMixin


class Segment:
    """Segment represents a continuous memory region."""

    def __init__(self, offset, size=0):
        self.offset = offset
        self.size = size

    def __repr__(self):
        return "Seg (%s [ %d ])" % (hex(self.offset), self.size)


class AbstractLocation:
    """AbstractLocation represents a location in memory."""

    def __init__(self, bbl_key, stmt_id, region_id, segment_list=None, region_offset=None, size=None):
        self._bbl_key = -1 if bbl_key is None else bbl_key
        self._stmt_id = -1 if stmt_id is None else stmt_id
        self._region_id = region_id
        self._segment_list = [] if not segment_list else segment_list[::]

        if region_offset and size:
            self._add_segment(region_offset, size)

    def _add_segment(self, offset, size):
        segment_added = False

        last_pos = 0
        segment_end = offset + size

        for i, s in enumerate(self._segment_list):
            # Case 1
            s_end = s.offset + s.size

            if offset >= s.offset and segment_end <= s_end:
                # It has been covered
                return False

            if offset - 1 <= s.offset <= offset + 1:
                s.offset = min(s.offset, offset)
                s.size = max(s_end, segment_end) - s.offset
                segment_added = True
                break

            # Case 2
            if segment_end - 1 <= s_end <= segment_end + 1:
                s.offset = min(s.offset, offset)
                s.size = max(s_end, segment_end) - s.offset
                segment_added = True
                break

            if s.offset < offset:
                last_pos = i + 1

        if not segment_added:
            # We create a new segment and add it to the list
            s = Segment(offset, size)
            self._segment_list.insert(last_pos, s)

        # Check for possible merges
        i = 0
        while i < len(self._segment_list) - 1:
            s = self._segment_list[i]
            t = self._segment_list[i + 1]

            if s.offset + s.size >= t.offset:
                # They should be merged!
                new_s = Segment(s.offset, max(s.offset + s.size, t.offset + t.size) - s.offset)
                self._segment_list[i : i + 2] = [new_s]

            else:
                i += 1

        return True

    @property
    def basicblock_key(self):
        return self._bbl_key

    @property
    def statement_id(self):
        return self._stmt_id

    @property
    def region(self):
        return self._region_id

    @property
    def segments(self):
        return self._segment_list

    def update(self, region_offset, size):
        return self._add_segment(region_offset, size)

    def copy(self):
        return AbstractLocation(self._bbl_key, self._stmt_id, self._region_id, self._segment_list)

    def merge(self, other):
        merged = False

        for s in other._segment_list:
            merged |= self.update(s.offset, s.size)

        return merged

    def __contains__(self, offset):
        for s in self._segment_list:
            if s.offset <= offset < s.offset + s.size:
                return True

            if s.offset > offset:
                break

        return False

    def __repr__(self):
        return "(%xh, %d) %s" % (
            (self.basicblock_key if self.basicblock_key is not None else -1),
            (self.statement_id if self.statement_id is not None else -1),
            self._segment_list,
        )


class MemoryRegionMetaMixin(MemoryMixin):
    __slots__ = (
        "_endness",
        "_id",
        "_state",
        "_is_stack",
        "_related_function_addr",
        "_alocs",
        "_memory",
    )

    def __init__(self, related_function_addr=None, **kwargs):
        super().__init__(**kwargs)
        self._related_function_addr = related_function_addr
        # This is a map from tuple (basicblock_key, stmt_id) to AbstractLocation objects
        self.alocs: dict[tuple[Any, int], AbstractLocation] = {}

        self._is_stack = None

    @MemoryMixin.memo
    def copy(self, memo):
        r: MemoryRegionMetaMixin = super().copy(memo)
        r.alocs = copy.deepcopy(self.alocs)
        r._related_function_addr = self._related_function_addr
        r._is_stack = self._is_stack
        return r

    @property
    def is_stack(self):
        if self.id is None:
            return None
        if self._is_stack is None:
            self._is_stack = self.id.startswith("stack_")
        return self._is_stack

    @property
    def related_function_addr(self):
        return self._related_function_addr

    def get_abstract_locations(self, addr, size):
        """
        Get a list of abstract locations that is within the range of [addr, addr + size]

        This implementation is pretty slow. But since this method won't be called frequently, we can live with the bad
        implementation for now.

        :param addr:    Starting address of the memory region.
        :param size:    Size of the memory region, in bytes.
        :return:        A list of covered AbstractLocation objects, or an empty list if there is none.
        """

        ret = []
        for aloc in self.alocs.values():
            for seg in aloc.segments:
                if seg.offset >= addr and seg.offset < addr + size:
                    ret.append(aloc)
                    break

        return ret

    def store(self, addr, data, bbl_addr=None, stmt_id=None, ins_addr=None, endness=None, **kwargs):
        # It comes from a SimProcedure. We'll use bbl_addr as the aloc_id
        aloc_id = ins_addr if ins_addr is not None else bbl_addr

        if aloc_id not in self.alocs:
            self.alocs[aloc_id] = AbstractLocation(
                bbl_addr, stmt_id, self.id, region_offset=addr, size=len(data) // self.state.arch.byte_width
            )
            return super().store(addr, data, endness=endness, **kwargs)
        if self.alocs[aloc_id].update(addr, len(data) // self.state.arch.byte_width):
            return super().store(addr, data, endness=endness, **kwargs)
        return super().store(addr, data, endness=endness, **kwargs)

    def load(
        self, addr, size=None, bbl_addr=None, stmt_idx=None, ins_addr=None, **kwargs
    ):  # pylint:disable=unused-argument
        # if bbl_addr is not None and stmt_id is not None:
        return super().load(addr, size=size, **kwargs)

    def _merge_alocs(self, other_region):
        """
        Helper function for merging.
        """
        merging_occurred = False
        for aloc_id, aloc in other_region.alocs.items():
            if aloc_id not in self.alocs:
                self.alocs[aloc_id] = aloc.copy()
                merging_occurred = True
            else:
                # Update it
                merging_occurred |= self.alocs[aloc_id].merge(aloc)
        return merging_occurred

    def merge(self, others, merge_conditions, common_ancestor=None) -> bool:
        r = False
        for other_region in others:
            self._merge_alocs(other_region)
            r |= super().merge([other_region], merge_conditions, common_ancestor=common_ancestor)
        return r

    def widen(self, others):
        for other_region in others:
            self._merge_alocs(other_region)
            super().widen([other_region.memory])

    def dbg_print(self, indent=0):
        """
        Print out debugging information
        """
        print("%sA-locs:" % (" " * indent))
        for aloc_id, aloc in self.alocs.items():
            print("{}<0x{:x}> {}".format(" " * (indent + 2), aloc_id, aloc))

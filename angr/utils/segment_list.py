# pylint:disable=no-else-break
from __future__ import annotations
import logging

from sortedcontainers import SortedDict

from angr.errors import AngrCFGError, AngrRuntimeError


l = logging.getLogger(name=__name__)


class Segment:
    """
    Representing a memory block. This is not the "Segment" in ELF memory model
    """

    __slots__ = ["end", "sort", "start"]

    def __init__(self, start: int, end: int, sort: str | None):
        """
        :param start:   Start address.
        :param end:     End address.
        :param sort:    Type of the segment, can be code, data, etc.
        :return: None
        """

        self.start = start
        self.end = end
        self.sort = sort

    def __repr__(self):
        return f"[{self.start:#x}-{self.end:#x}, {self.sort}]"

    @property
    def size(self):
        """
        Calculate the size of the Segment.

        :return: Size of the Segment.
        :rtype: int
        """
        return self.end - self.start

    def copy(self):
        """
        Make a copy of the Segment.

        :return: A copy of the Segment instance.
        :rtype: angr.analyses.cfg_fast.Segment
        """
        return Segment(self.start, self.end, self.sort)

    def __eq__(self, other: Segment):
        return self.start == other.start and self.end == other.end and self.sort == other.sort

    def __hash__(self):
        return hash((self.start, self.end, self.sort))


class SegmentList:
    """
    SegmentList describes a series of segmented memory blocks. You may query whether an address belongs to any of the
    blocks or not, and obtain the exact block(segment) that the address belongs to.
    """

    __slots__ = ["_bytes_occupied", "_posmap"]

    def __init__(self):
        self._posmap: dict[int, Segment] | SortedDict = SortedDict()
        self._bytes_occupied = 0

    #
    # Overridden methods
    #

    def __len__(self):
        return len(self._posmap)

    #
    # Private methods
    #

    def _insert_and_merge(self, address: int, size: int, sort: str) -> None:
        """
        Determines whether the block specified by (address, size) should be merged with adjacent blocks.

        :param address: Starting address of the block to be merged.
        :param size: Size of the block to be merged.
        :param sort: Type of the block.
        :param idx: ID of the address.
        """

        # Create the block first, but do not insert it into the map
        # _insert_and_merge_core will fix the overlapping and do the insertion
        segment = Segment(address, address + size, sort)
        if address not in self._posmap:
            self._posmap[address] = segment
            self._bytes_occupied += size
        else:
            # This is an overlapping block. We need to merge them.
            existing_segment = self._posmap[address]
            if existing_segment.end == segment.end:
                # replace the existing segment and return
                self._posmap[address] = segment
                return
            if existing_segment.end < segment.end:
                # split the new segment into two, then replace the existing segment first
                self._posmap[address] = Segment(existing_segment.start, existing_segment.end, sort)
                self._insert_and_merge(existing_segment.end, size - existing_segment.size, sort)
                return
            if existing_segment.end > segment.end:
                # split the existing segment into two and replace the first one
                self._posmap[address] = segment
                self._insert_and_merge(segment.end, existing_segment.size - size, existing_segment.sort)
                return

        # Search forward to merge blocks if necessary
        next_addr = address
        while True:
            merged, next_addr, bytes_change = self._insert_and_merge_core(next_addr, "forward")

            if not merged:
                break

        self._bytes_occupied += bytes_change

        # Search backward to merge blocks if necessary
        next_addr = address
        while True:
            merged, next_addr, bytes_change = self._insert_and_merge_core(next_addr, "backward")

            if not merged:
                break

            self._bytes_occupied += bytes_change

    def _insert_and_merge_core(self, addr: int, direction: str):
        """
        The core part of method _insert_and_merge.

        :param pos:         The starting position.
        :param direction:   If we are traversing forwards or backwards in the posmap. It determines where the "sort"
                                of the overlapping memory block comes from. If everything works as expected, "sort" of
                                the overlapping block is always equal to the segment occupied most recently.
        :return: A tuple of (merged (bool), new position to begin searching (int), change in total bytes (int)
        :rtype: tuple
        """

        bytes_changed = 0

        if direction == "forward":
            it = self._posmap.irange(minimum=addr)
            previous_segment_addr = next(it, None)
            segment_addr = next(it, None)
        else:  # if direction == "backward":
            it = self._posmap.irange(maximum=addr, reverse=True)
            segment_addr = next(it, None)
            previous_segment_addr = next(it, None)

        if previous_segment_addr is None or segment_addr is None:
            return False, addr, 0
        previous_segment = self._posmap[previous_segment_addr]
        segment = self._posmap[segment_addr]

        merged = False
        next_addr = addr

        if segment.start <= previous_segment.end:
            # we should always have new_start+new_size >= segment.start

            if segment.sort == previous_segment.sort:
                # They are of the same sort - we should merge them!
                new_end = max(previous_segment.end, segment.start + segment.size)
                new_start = min(previous_segment.start, segment.start)
                new_size = new_end - new_start
                self._posmap.pop(segment_addr)
                self._posmap[new_start] = Segment(new_start, new_end, segment.sort)
                bytes_changed = -(segment.size + previous_segment.size - new_size)

                merged = True
                next_addr = previous_segment_addr

            else:
                # Different sorts. It's a bit trickier.
                if segment.start == previous_segment.end:
                    # They are adjacent. Just don't merge.
                    pass
                else:
                    # They are overlapping. We will create one, two, or three different blocks based on how they are
                    # overlapping
                    new_segments = []
                    if segment.start < previous_segment.start:
                        new_segments.append(Segment(segment.start, previous_segment.start, segment.sort))

                        sort = previous_segment.sort if direction == "forward" else segment.sort
                        new_segments.append(Segment(previous_segment.start, previous_segment.end, sort))

                        if segment.end < previous_segment.end:
                            new_segments.append(Segment(segment.end, previous_segment.end, previous_segment.sort))
                        elif segment.end > previous_segment.end:
                            new_segments.append(Segment(previous_segment.end, segment.end, segment.sort))
                    else:  # segment.start >= previous_segment.start
                        if segment.start > previous_segment.start:
                            new_segments.append(Segment(previous_segment.start, segment.start, previous_segment.sort))
                        sort = previous_segment.sort if direction == "forward" else segment.sort
                        if segment.end > previous_segment.end:
                            new_segments.append(Segment(segment.start, previous_segment.end, sort))
                            new_segments.append(Segment(previous_segment.end, segment.end, segment.sort))
                        elif segment.end < previous_segment.end:
                            new_segments.append(Segment(segment.start, segment.end, sort))
                            new_segments.append(Segment(segment.end, previous_segment.end, previous_segment.sort))
                        else:
                            new_segments.append(Segment(segment.start, segment.end, sort))

                    # merge segments in new_segments array if they are of the same sort
                    i = 0
                    while len(new_segments) > 1 and i < len(new_segments) - 1:
                        s0 = new_segments[i]
                        s1 = new_segments[i + 1]
                        if s0.sort == s1.sort:
                            new_segments = (
                                new_segments[:i] + [Segment(s0.start, s1.end, s0.sort)] + new_segments[i + 2 :]
                            )
                        else:
                            i += 1

                    # Put new segments into posmap
                    old_size = sum(seg.size for seg in [previous_segment, segment])
                    new_size = sum(seg.size for seg in new_segments)
                    bytes_changed = new_size - old_size

                    self._posmap.pop(segment_addr)
                    self._posmap.pop(previous_segment_addr)
                    for seg in new_segments:
                        self._posmap[seg.start] = seg

                    merged = True

                    if direction == "forward":
                        next_addr = new_segments[-1].start
                    else:
                        next_addr = previous_segment_addr

        return merged, next_addr, bytes_changed

    def _remove(self, init_address: int, init_size: int, addr_before: int) -> None:
        address = init_address
        size = init_size

        while True:
            segment = self._posmap[addr_before]
            if segment.start <= address:
                if address < segment.start + segment.size < address + size:
                    # |---segment---|
                    #      |---address + size---|
                    # shrink segment
                    segment.end = address
                    # adjust address
                    new_address = segment.start + segment.size
                    # adjust size
                    size = address + size - new_address
                    address = new_address
                    # update idx
                    addr_before = self.search(address)
                elif address < segment.start + segment.size and address + size <= segment.start + segment.size:
                    # |--------segment--------|
                    #    |--address + size--|
                    # break segment
                    seg0 = Segment(segment.start, address, segment.sort)
                    seg1 = Segment(address + size, segment.start + segment.size, segment.sort)
                    # remove the current segment
                    self._posmap.pop(addr_before)
                    if seg1.size > 0:
                        self._posmap[seg1.start] = seg1
                    if seg0.size > 0:
                        self._posmap[seg0.start] = seg0
                    # done
                    break
                else:
                    raise AngrRuntimeError("Unreachable reached")
            else:  # if segment.start > address
                if address + size <= segment.start:
                    #                      |--- segment ---|
                    # |-- address + size --|
                    # no overlap
                    break
                if segment.start < address + size <= segment.start + segment.size:
                    #            |---- segment ----|
                    # |-- address + size --|
                    #
                    # update the start of the segment
                    segment.start = address + size
                    if segment.size == 0:
                        # remove the segment
                        self._posmap.pop(addr_before)
                    break
                if address + size > segment.start + segment.size:
                    #            |---- segment ----|
                    # |--------- address + size ----------|
                    self._posmap.pop(addr_before)
                    new_address = segment.end
                    size = address + size - new_address
                    address = new_address
                    addr_before = self.search(address)
                else:
                    raise AngrRuntimeError("Unreachable reached")

    def _dbg_output(self):
        """
        Returns a string representation of the segments that form this SegmentList

        :return: String representation of contents
        :rtype: str
        """
        s = "["
        lst = []
        for segment in self._posmap.values():
            lst.append(repr(segment))
        s += ", ".join(lst)
        s += "]"
        return s

    def _debug_check(self):
        """
        Iterates over list checking segments with same sort do not overlap

        :raise: Exception: if segments overlap space with same sort
        """
        # old_start = 0
        old_end = 0
        old_sort = ""
        for segment in self._posmap.values():
            if segment.start <= old_end and segment.sort == old_sort:
                raise AngrCFGError("Error in SegmentList: blocks are not merged")
            # old_start = start
            old_end = segment.end
            old_sort = segment.sort

    #
    # Public methods
    #

    def search(self, addr: int) -> int | None:
        """
        Checks which segment that the address `addr` should belong to, and, returns the offset of that segment.
        Note that the address may not actually belong to the block.

        :param addr:    The address to search
        :return:        The address of the segment that is either before addr or covers addr.
        """

        try:
            return next(self._posmap.irange(maximum=addr, reverse=True))
        except StopIteration:
            return None

    def next_free_pos(self, address: int):
        """
        Returns the next free position with respect to an address, including that address itself

        :param address: The address to begin the search with (including itself)
        :return: The next free position
        """

        addr_before = self.search(address)
        if addr_before is None:
            # no segment exist before address
            it = iter(self._posmap)
        else:
            it = self._posmap.irange(minimum=addr_before)

        last_seg: Segment | None = None
        for a in it:
            seg = self._posmap[a]
            if last_seg is not None and last_seg.end != seg.start:
                return last_seg.end
            last_seg = seg

        # not occupied
        return address if last_seg is None else last_seg.end

    def next_pos_with_sort_not_in(self, address, sorts, max_distance=None):
        """
        Returns the address of the next occupied block whose sort is not one of the specified ones.

        :param int address: The address to begin the search with (including itself).
        :param sorts:       A collection of sort strings.
        :param max_distance:    The maximum distance between `address` and the next position. Search will stop after
                                we come across an occupied position that is beyond `address` + max_distance. This check
                                will be disabled if `max_distance` is set to None.
        :return:            The next occupied position whose sort is not one of the specified ones, or None if no such
                            position exists.
        :rtype:             int or None
        """

        addr_before = self.search(address)
        if addr_before is None:
            # no segment exist before address
            it = iter(self._posmap)
        else:
            it = self._posmap.irange(minimum=addr_before)

        for a in it:
            seg = self._posmap[a]
            if seg.start <= address < seg.end and seg.sort not in sorts:
                # the address is inside the current block
                return address
            if max_distance is not None and address + max_distance < seg.start:
                return None
            if seg.sort not in sorts:
                return seg.start

        return None

    def is_occupied(self, address) -> bool:
        """
        Check if an address belongs to any segment

        :param address: The address to check
        :return: True if this address belongs to a segment, False otherwise
        """

        addr_before = self.search(address)
        if addr_before is None:
            return False
        seg = self._posmap[addr_before]
        return seg.start <= address < seg.end

    def occupied_by_sort(self, address: int) -> str | None:
        """
        Check if an address belongs to any segment, and if yes, returns the sort of the segment

        :param address: The address to check
        :return: Sort of the segment that occupies this address
        """

        addr_before = self.search(address)
        if addr_before is None:
            return None
        seg = self._posmap[addr_before]
        return seg.sort if seg.start <= address < seg.end else None

    def occupied_by(self, address: int) -> tuple[int, int, str] | None:
        """
        Check if an address belongs to any segment, and if yes, returns the beginning, the size, and the sort of the
        segment.

        :param address: The address to check
        """

        addr_before = self.search(address)
        if addr_before is None:
            return None
        seg = self._posmap[addr_before]
        return (seg.start, seg.size, seg.sort) if seg.start <= address < seg.end else None

    def occupy(self, address: int, size: int, sort: str) -> None:
        """
        Include a block, specified by (address, size), in this segment list.

        :param address:     The starting address of the block.
        :param size:        Size of the block.
        :param sort:        Type of the block.
        :return: None
        """

        if size is None or size <= 0:
            # Cannot occupy a non-existent block
            return

        # l.debug("Occupying 0x%08x-0x%08x", address, address + size)
        if not self._posmap:
            self._posmap[address] = Segment(address, address + size, sort)
            self._bytes_occupied += size
            return
        self._insert_and_merge(address, size, sort)

    def release(self, address: int, size: int) -> None:
        """
        Remove a block, specified by (address, size), in this segment list.

        :param address: The starting address of the block.
        :param size:    Size of the block.
        """

        if size is None or size <= 0:
            # cannot release a non-existent block
            return
        if not self._posmap:
            return

        addr_before = self.search(address)
        if addr_before is None:
            return
        seg = self._posmap[addr_before]
        if seg.start <= address < seg.end:
            self._remove(address, size, addr_before)

        # self._debug_check()

    def copy(self) -> SegmentList:
        """
        Make a copy of the SegmentList.

        :return: A copy of the SegmentList instance.
        """
        n = SegmentList()

        n._posmap = self._posmap.copy()
        n._bytes_occupied = self._bytes_occupied
        return n

    #
    # Properties
    #

    @property
    def occupied_size(self):
        """
        The sum of sizes of all blocks

        :return: An integer
        """

        return self._bytes_occupied

    @property
    def has_blocks(self):
        """
        Returns if this segment list has any block or not. !is_empty

        :return: True if it's not empty, False otherwise
        """

        return len(self._posmap) > 0

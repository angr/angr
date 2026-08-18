from . import ailment, automaton, fuzzer, icicle

class Segment:
    """
    A memory block
    """

    start: int
    end: int
    sort: str | None

    def __init__(self, start: int, end: int, sort: str | None = None) -> None:
        """
        Initialize a Segment

        :arg start: Start address.
        :arg end: End address.
        :arg sort: Type of the segment, can be code, data, etc.
        :raises ValueError: If ``end`` precedes ``start``.
        """

    def copy(self) -> Segment:
        """
        Make a copy of the Segment

        :returns: A copy of the Segment instance.
        """

    @property
    def size(self) -> int:
        """
        Calculate the size of the Segment

        :returns: Size of the Segment
        """

class SegmentList:
    """
    SegmentList describes a series of segmented memory blocks. You may query whether an address belongs to any of the
    blocks or not, and obtain the exact block(segment) that the address belongs to.
    """

    def __init__(self) -> None:
        """
        Initialize an empty SegmentList.
        """

    def __len__(self) -> int:
        """
        Get the number of segments in the list.

        :returns: Number of segments.
        """

    def __getitem__(self, idx: int) -> Segment:
        """
        Get a segment by index.

        :arg idx: Index of the segment.
        :returns: The segment at the specified index.
        :raises IndexError: If the index is out of range.
        """

    @property
    def occupied_size(self) -> int:
        """
        The sum of sizes of all blocks.

        :returns: An integer representing the total occupied size.
        """

    @property
    def has_blocks(self) -> bool:
        """
        Returns if this segment list has any block or not.

        :returns: True if it's not empty, False otherwise.
        """

    def search(self, addr: int) -> int:
        """
        Checks which segment that the address `addr` should belong to, and, returns the offset of that segment.
        Note that the address may not actually belong to the block.

        This is O(n): an index into the segment list cannot be computed any faster. Prefer the point-query methods
        (:meth:`occupied_by`, :meth:`occupied_by_sort`, ...) wherever an index is not strictly needed.

        :arg addr: The address to search.
        :returns: The offset of the segment.
        """

    def sort_ratio_backwards(self, addr: int, window_size: int, sort: str | None) -> float:
        """
        The fraction of bytes belonging to segments of sort `sort`, among the last `window_size` occupied bytes at or
        before `addr`.

        The walk starts at the segment :meth:`search` would return for `addr` and moves backwards, skipping over gaps,
        until `window_size` bytes have been covered.

        :arg addr: The address to start the backwards walk at.
        :arg window_size: The number of occupied bytes to cover.
        :arg sort: The sort to measure.
        :returns: The ratio, or 0.0 if the starting segment has a different sort or fewer than `window_size` occupied
                  bytes are available.
        """

    def next_free_pos(self, address: int) -> int:
        """
        Returns the next free position with respect to an address, including that address itself.

        :arg address: The address to begin the search with (including itself).
        :returns: The next free position.
        :raises ValueError: If no free space is found after the address.
        """

    def next_pos_with_sort_not_in(
        self, address: int, sorts: set[str | None], max_distance: int | None = None
    ) -> int | None:
        """
        Returns the address of the next occupied block whose sort is not one of the specified ones.

        :arg address: The address to begin the search with (including itself).
        :arg sorts: A collection of sort strings.
        :arg max_distance: The maximum distance between `address` and the next position. Search will stop after
                          we come across an occupied position that is beyond `address` + max_distance. This check
                          will be disabled if `max_distance` is set to None.
        :returns: The next occupied position whose sort is not one of the specified ones, or None if no such position exists.
        """

    def is_occupied(self, address: int) -> bool:
        """
        Check if an address belongs to any segment.

        :arg address: The address to check.
        :returns: True if this address belongs to a segment, False otherwise.
        """

    def occupied_by_sort(self, address: int) -> str | None:
        """
        Check if an address belongs to any segment, and if yes, returns the sort of the segment.

        :arg address: The address to check.
        :returns: Sort of the segment that occupies this address, or None if the address is not occupied.
        """

    def occupied_by(self, address: int) -> tuple[int, int, str | None] | None:
        """
        Check if an address belongs to any segment, and if yes, returns the beginning, the size, and the sort of the
        segment.

        :arg address: The address to check.
        :returns: A tuple of (start, size, sort) if the address is occupied, or None if it's not.
        """

    def occupy(self, address: int, size: int, sort: str | None = None) -> None:
        """
        Include a block, specified by (address, size), in this segment list.

        :arg address: The starting address of the block.
        :arg size: Size of the block.
        :arg sort: Type of the block.
        """

    def release(self, address: int, size: int) -> None:
        """
        Remove a block, specified by (address, size), in this segment list.

        :arg address: The starting address of the block.
        :arg size: Size of the block.
        """

    def update(self, other: SegmentList) -> None:
        """
        Update this SegmentList with all segments from another SegmentList.

        :arg other: Another SegmentList to merge into this one.
        """

    def copy(self) -> SegmentList:
        """
        Make a copy of the SegmentList.

        :returns: A copy of the SegmentList instance.
        """

__all__ = ["Segment", "SegmentList", "ailment", "automaton", "fuzzer", "icicle"]

from __future__ import annotations

import time
import unittest

from angr.rustylib import SegmentList


def _ratio_reference(seg_list: SegmentList, addr: int, window_size: int, sort: str | None) -> float:
    """
    The O(n) algorithm ``SegmentList.sort_ratio_backwards()`` replaced: search() for the starting index, then walk
    backwards through the list by index.
    """
    idx = seg_list.search(addr)
    if idx is None or idx >= len(seg_list):
        return 0.0
    if seg_list[idx].sort != sort:
        return 0.0

    total_bytes = 0
    matching_bytes = 0
    while idx >= 0:
        segment = seg_list[idx]
        if segment.sort == sort:
            matching_bytes += segment.size
        total_bytes += segment.size
        if total_bytes >= window_size:
            break
        idx -= 1

    if total_bytes < window_size:
        return 0.0
    return matching_bytes / total_bytes


class TestSegmentList(unittest.TestCase):
    """
    Test the SegmentList class.
    """

    # pylint: disable=no-self-use

    def test_occupy(self):
        seg_list = SegmentList()
        seg_list.occupy(0, 1, "code")
        seg_list.occupy(2, 3, "code")

        assert len(seg_list) == 2
        assert seg_list[0].end == 1
        assert seg_list[1].end == 5
        assert seg_list.is_occupied(4)
        assert seg_list.is_occupied(5) is False

    def test_merging(self):
        seg_list = SegmentList()

        # They should be merged
        seg_list.occupy(0, 1, "code")
        seg_list.occupy(1, 2, "code")

        assert len(seg_list) == 1
        assert seg_list[0].start == 0
        assert seg_list[0].end == 3

    def test_not_merged(self):
        seg_list = SegmentList()

        # They should not be merged
        seg_list.occupy(0, 1, "code")
        seg_list.occupy(1, 2, "data")

        assert len(seg_list) == 2
        assert seg_list[0].start == 0
        assert seg_list[0].end == 1
        assert seg_list[1].start == 1
        assert seg_list[1].end == 3

    def test_multi_merge(self):
        seg_list = SegmentList()

        # They should be merged, and create three different segments
        seg_list.occupy(0, 5, "code")
        seg_list.occupy(5, 5, "code")
        seg_list.occupy(1, 2, "data")

        assert len(seg_list) == 3

        assert seg_list[0].start == 0
        assert seg_list[0].end == 1
        assert seg_list[0].sort == "code"

        assert seg_list[1].start == 1
        assert seg_list[1].end == 3
        assert seg_list[1].sort == "data"

        assert seg_list[2].start == 3
        assert seg_list[2].end == 10
        assert seg_list[2].sort == "code"

    def test_fully_overlapping(self):
        seg_list = SegmentList()

        seg_list.occupy(5, 5, "code")
        seg_list.occupy(4, 1, "code")
        seg_list.occupy(2, 2, "code")

        assert len(seg_list) == 1
        assert seg_list[0].start == 2
        assert seg_list[0].end == 10

    def test_overlapping_not_merged(self):
        seg_list = SegmentList()

        seg_list.occupy(5, 5, "data")
        seg_list.occupy(4, 1, "code")
        seg_list.occupy(2, 2, "data")

        assert len(seg_list) == 3
        assert seg_list[0].start == 2
        assert seg_list[2].end == 10

        seg_list.occupy(3, 2, "data")

        assert len(seg_list) == 1
        assert seg_list[0].start == 2
        assert seg_list[0].end == 10

    def test_partially_overlapping_not_merged(self):
        seg_list = SegmentList()

        seg_list.occupy(10, 20, "code")
        seg_list.occupy(9, 2, "data")

        assert len(seg_list) == 2
        assert seg_list[0].start == 9
        assert seg_list[0].end == 11
        assert seg_list[0].sort == "data"

        assert seg_list[1].start == 11
        assert seg_list[1].end == 30
        assert seg_list[1].sort == "code"

    def test_iteration(self):
        seg_list = SegmentList()
        seg_list.occupy(0, 10, "code")
        seg_list.occupy(20, 5, "data")

        assert [(s.start, s.end, s.sort) for s in seg_list] == [(0, 10, "code"), (20, 25, "data")]
        assert list(SegmentList()) == []

    def test_sort_ratio_backwards(self):
        seg_list = SegmentList()
        seg_list.occupy(0, 100, "code")
        seg_list.occupy(100, 100, "nodecode")
        seg_list.occupy(200, 100, "code")
        seg_list.occupy(300, 100, "nodecode")

        # the walk starts in the last segment and covers as many segments as the window needs
        assert seg_list.sort_ratio_backwards(399, 100, "nodecode") == 1.0
        assert seg_list.sort_ratio_backwards(399, 200, "nodecode") == 0.5
        assert seg_list.sort_ratio_backwards(399, 400, "nodecode") == 0.5
        # the starting segment has the wrong sort
        assert seg_list.sort_ratio_backwards(250, 100, "nodecode") == 0.0
        # fewer than window_size occupied bytes are available
        assert seg_list.sort_ratio_backwards(399, 500, "nodecode") == 0.0
        # beyond every segment
        assert seg_list.sort_ratio_backwards(500, 100, "nodecode") == 0.0
        assert SegmentList().sort_ratio_backwards(0, 100, "nodecode") == 0.0

    def test_sort_ratio_backwards_skips_gaps(self):
        seg_list = SegmentList()
        seg_list.occupy(0, 40, "nodecode")
        seg_list.occupy(60, 40, "code")
        # a 900-byte gap, which the backwards walk steps over without counting it
        seg_list.occupy(1000, 40, "nodecode")

        assert seg_list.sort_ratio_backwards(1039, 40, "nodecode") == 1.0
        assert seg_list.sort_ratio_backwards(1039, 80, "nodecode") == 0.5
        assert seg_list.sort_ratio_backwards(1039, 120, "nodecode") == 2 / 3
        assert seg_list.sort_ratio_backwards(1039, 121, "nodecode") == 0.0

    def test_sort_ratio_backwards_matches_reference(self):
        # single-byte segments and gaps are both common in CFGFast's segment list
        seg_list = SegmentList()
        addr = 0
        for i in range(80):
            addr += i % 3
            size = 1 + (i * 7) % 9
            seg_list.occupy(addr, size, "nodecode" if i % 5 < 2 else "code")
            addr += size

        for probe in range(addr + 4):
            for window in (1, 7, 32, 4096):
                assert seg_list.sort_ratio_backwards(probe, window, "nodecode") == _ratio_reference(
                    seg_list, probe, window, "nodecode"
                ), f"probe {probe:#x}, window {window}"

    def test_sort_ratio_backwards_is_not_quadratic(self):
        # regression test for angr#6765: CFGFast._nodecode_bytes_ratio used to search() and then walk backwards by
        # index, both linear in the segment count, which made the smart scan quadratic in input size
        seg_list = SegmentList()
        for i in range(100_000):
            seg_list.occupy(i * 2, 1, "nodecode" if i % 4 else "code")
        assert len(seg_list) == 100_000

        start = time.time()
        for i in range(1000):
            seg_list.sort_ratio_backwards(199_999 - i, 512, "nodecode")
        elapsed = time.time() - start
        # the old implementation needs minutes here; the current one needs milliseconds
        assert elapsed < 5.0, f"1000 queries over 100k segments took {elapsed:.1f}s"

    def test_iteration_is_not_quadratic(self):
        seg_list = SegmentList()
        for i in range(100_000):
            seg_list.occupy(i * 2, 1, "nodecode" if i % 4 else "code")

        start = time.time()
        assert len(list(seg_list)) == 100_000
        elapsed = time.time() - start
        assert elapsed < 5.0, f"iterating 100k segments took {elapsed:.1f}s"


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

from angr.rustylib import SegmentList


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


if __name__ == "__main__":
    unittest.main()

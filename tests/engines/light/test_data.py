#!/usr/bin/env python3
from unittest import main, TestCase

from angr.engines.light.data import SpOffset


class TestSpOffset(TestCase):
    def test_difference_between_two_sp_offset_is_concrete(self):
        size = 8
        first_offset = SpOffset(size, 10)
        second_offset = SpOffset(size, 20)

        self.assertEqual(first_offset - second_offset, -10)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations
import unittest

from angr.utils.bits import truncate_bits


# pylint: disable=missing-class-docstring,disable=no-self-use
class TestBits(unittest.TestCase):

    def test_truncate_bits(self):
        with self.assertRaises(ValueError):
            truncate_bits(0, -1)
        assert truncate_bits(0, 0) == 0
        assert truncate_bits(0, 8) == 0
        assert truncate_bits(0x1234, 0) == 0
        assert truncate_bits(0x1234, 8) == 0x34
        assert truncate_bits(0x1234, 16) == 0x1234
        assert truncate_bits(0x1234, 32) == 0x1234


if __name__ == "__main__":
    unittest.main()

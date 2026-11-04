#!/usr/bin/env python3
# pylint:disable=missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.engines.vex"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.engines.vex.light.light import VEXMixin


class TestCompositeVpc(unittest.TestCase):
    """A VM branch's stand-in VPC identifies its target pair."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "amd64")

    def test_sum_when_unused(self):
        self.assertEqual(VEXMixin.composite_vpc(self.proj, (0x6E362, 0x60542)), 0x6E362 + 0x60542)
        # order of the targets does not matter
        self.assertEqual(VEXMixin.composite_vpc(self.proj, (0x60542, 0x6E362)), 0x6E362 + 0x60542)
        self.assertIn(0x6E362 + 0x60542, self.proj.composite_vpc_values)

    def test_colliding_sums_get_distinct_labels(self):
        # CNIC sub_275a4: two branches whose target sums differ by 0x12 walk down to equal sums
        a = VEXMixin.composite_vpc(self.proj, (0x6E362 - 9, 0x60542 - 9))
        b = VEXMixin.composite_vpc(self.proj, (0x6E000, 0x60892))
        self.assertEqual(a, 0x6E000 + 0x60892)
        self.assertNotEqual(a, b)
        self.assertIn(b, self.proj.composite_vpc_values)
        # stable per pair
        self.assertEqual(VEXMixin.composite_vpc(self.proj, (0x60892, 0x6E000)), b)
        self.assertEqual(VEXMixin.composite_vpc(self.proj, (0x6E362 - 9, 0x60542 - 9)), a)


if __name__ == "__main__":
    unittest.main()

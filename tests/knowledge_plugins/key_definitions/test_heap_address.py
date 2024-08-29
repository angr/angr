#!/usr/bin/env python3
from __future__ import annotations
from unittest import main, TestCase

from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress


class TestHeapAddress(TestCase):
    def test_expose_its_value_as_a_property(self):
        address = HeapAddress(0x42)
        self.assertEqual(address.value, 0x42)

    def test_add_fails_if_value_added_is_not_int(self):
        address = HeapAddress(0x0)
        self.assertRaises(TypeError, address + 0x8)

    def test_add_increase_the_heap_address_value_by_the_right_amount(self):
        address = HeapAddress(0x0)
        new_address = address + 0x8
        self.assertEqual(new_address.value, 0x8)

    def test_add_is_commutative(self):
        address = HeapAddress(0x0)
        self.assertEqual(address + 0x8, 0x8 + address)


if __name__ == "__main__":
    main()

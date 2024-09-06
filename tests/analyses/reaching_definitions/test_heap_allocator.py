#!/usr/bin/env python3
from __future__ import annotations
from unittest import main, TestCase

from angr.analyses.reaching_definitions.heap_allocator import HeapAllocator
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.unknown_size import UNKNOWN_SIZE


class TestHeapAllocator(TestCase):
    UNKNOWN_SIZE_DEFAULT_CONCRETE_VALUE = 8

    def setUp(self):
        self.heap_allocator = HeapAllocator(self.UNKNOWN_SIZE_DEFAULT_CONCRETE_VALUE)

    def test_allocate_returns_an_entry_address(self):
        address = self.heap_allocator.allocate(0x10)
        self.assertTrue(isinstance(address, HeapAddress))

    def test_allocate_create_an_entry_after_the_previous_one(self):
        size_of_first_chunk = 0x10
        address = self.heap_allocator.allocate(size_of_first_chunk)
        other_address = self.heap_allocator.allocate(0x10)

        self.assertEqual(other_address.value - address.value, size_of_first_chunk)

    def test_allocate_given_an_undefined_size_still_gives_a_concrete_address(self):
        size_of_first_chunk = UNKNOWN_SIZE
        address = self.heap_allocator.allocate(size_of_first_chunk)
        other_address = self.heap_allocator.allocate(0x10)

        self.assertEqual(other_address.value - address.value, self.UNKNOWN_SIZE_DEFAULT_CONCRETE_VALUE)

    def test_allocated_addresses_keeps_track_of_memory_chunks_in_use(self):
        address = self.heap_allocator.allocate(0x10)

        self.assertTrue(address in self.heap_allocator.allocated_addresses)

    def test_free_removes_the_address_from_list_of_allocated_ones(self):
        address = self.heap_allocator.allocate(0x10)
        self.heap_allocator.free(address)

        self.assertFalse(address in self.heap_allocator.allocated_addresses)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.state_plugins"  # pylint:disable=redefined-builtin

import os
import pickle
import unittest

import claripy

import angr
from angr import SimHeapBrk, SimHeapPTMalloc, SimState
from angr.state_plugins.heap.heap_base import HEAP_INITIAL_MAPPED_SIZE, HEAP_MAPPING_GROWTH_FACTOR
from tests.common import bin_location

gdb_data_location = os.path.join(bin_location, "tests_data", "test_gdb_plugin")

# unconstrained reads out of a fresh heap are noisy and (for SimHeapPTMalloc) slow; nothing here depends on the
# filler, so pin it to zero
ZERO_FILL = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}


def make_state(heap=None, add_options=None):
    """
    A bare SimState is enough for everything here and keeps the tests fast: the heap plugin only ever talks to
    ``state.memory``.
    """
    plugins = {"heap": heap} if heap is not None else None
    return SimState(arch="AMD64", plugins=plugins, add_options=ZERO_FILL | (add_options or set()))


def resident_heap_pages(state):
    """
    The number of pages the memory plugin has actually materialized inside the heap region.

    This deliberately reaches into ``memory._pages``: the whole point of the lazy mapping is that page objects do
    not exist, and only the memory object knows that. ``_mapped_end`` alone would not catch a regression that
    re-introduces eager mapping somewhere else.
    """
    page_size = state.memory.page_size
    lo = state.heap.heap_base // page_size
    hi = (state.heap.heap_base + state.heap.heap_size) // page_size
    return sum(1 for pageno, page in state.memory._pages.items() if page is not None and lo <= pageno < hi)


def pattern(i, n):
    """A deterministic n-byte pattern that differs for every i."""
    return bytes((i * 7 + j * 31 + 0x41) & 0xFF for j in range(n))


def store_pattern(state, addr, i, n):
    state.memory.store(addr, claripy.BVV(pattern(i, n), n * 8))


def load_pattern(state, addr, n):
    return state.solver.eval(state.memory.load(addr, n), cast_to=bytes)


class TestHeapLazyMapping(unittest.TestCase):
    """
    The heap region is mapped lazily and grown on demand; ``heap_size`` is the maximum extent, not the amount that
    is mapped.
    """

    def test_blank_state_maps_only_the_initial_extent(self):
        # THE regression guard: before the heap mapping became lazy, init_state() mapped all of heap_size (2048
        # UltraPages, ~17 MB of Python objects) for every single state, including the throwaway states CFG
        # recovery makes by the thousand.
        state = make_state()
        page_size = state.memory.page_size

        assert state.heap._mapped_end == state.heap.heap_base + HEAP_INITIAL_MAPPED_SIZE
        assert resident_heap_pages(state) == HEAP_INITIAL_MAPPED_SIZE // page_size
        # a bare SimState maps nothing but the heap, so the heap pages are all the pages there are
        assert len(state.memory._pages) == HEAP_INITIAL_MAPPED_SIZE // page_size

    def test_project_blank_state_maps_only_the_initial_extent(self):
        # same guard, but through the path everything else in angr actually uses
        proj = angr.load_shellcode(b"\x90" * 16, "amd64")
        state = proj.factory.blank_state()

        assert state.heap._mapped_end == state.heap.heap_base + HEAP_INITIAL_MAPPED_SIZE
        assert resident_heap_pages(state) == HEAP_INITIAL_MAPPED_SIZE // state.memory.page_size

    def test_growth_is_geometric(self):
        state = make_state()
        base = state.heap.heap_base
        page_size = state.memory.page_size

        extents = []
        for _ in range(12):
            state.heap._malloc(0x1000)
            extents.append(state.heap._mapped_end - base)
            # the mapped extent must always cover everything that has been handed out
            assert state.heap._mapped_end >= state.heap.heap_location
            assert resident_heap_pages(state) == (state.heap._mapped_end - base) // page_size

        # 0x1000 handed out at a time against an 0x2000 initial extent that doubles every time it is overrun
        expected = [0x2000, 0x2000, 0x4000, 0x4000, 0x8000, 0x8000, 0x8000, 0x8000, 0x10000, 0x10000, 0x10000, 0x10000]
        assert extents == expected
        # ...which is exactly HEAP_INITIAL_MAPPED_SIZE scaled by powers of the growth factor
        for extent in extents:
            size = HEAP_INITIAL_MAPPED_SIZE
            while size < extent:
                size *= HEAP_MAPPING_GROWTH_FACTOR
            assert size == extent

    def test_growth_uses_a_logarithmic_number_of_mapping_operations(self):
        # geometric growth is what keeps a program that really does use megabytes of heap from paying a mapping
        # operation per allocation
        state = make_state()
        calls = []
        real_map_range = state.heap._map_range
        state.heap._map_range = lambda start, end: (calls.append((start, end)), real_map_range(start, end))[1]

        for _ in range(4096):
            state.heap._malloc(0x400)

        assert state.heap._mapped_end == state.heap.heap_base + 4096 * 0x400
        assert 1 <= len(calls) <= 16, f"{len(calls)} mapping operations for 4096 allocations is not logarithmic"

    def test_growth_never_maps_past_heap_size(self):
        state = make_state(SimHeapBrk(heap_base=0xD0000000, heap_size=0x10000))
        region_end = state.heap.heap_base + state.heap.heap_size

        state.heap._malloc(0x100000)  # sixteen times the whole region
        assert state.heap._mapped_end == region_end
        assert resident_heap_pages(state) == state.heap.heap_size // state.memory.page_size

        state.heap._malloc(0x100000)
        assert state.heap._mapped_end == region_end

    def test_allocation_landing_exactly_on_a_growth_boundary(self):
        state = make_state()
        base = state.heap.heap_base

        # exactly fills the initial extent: nothing has run past the end yet, so nothing grows
        first = state.heap._malloc(HEAP_INITIAL_MAPPED_SIZE)
        assert first == base
        assert state.heap._mapped_end == base + HEAP_INITIAL_MAPPED_SIZE

        # the last byte of the initial extent must be usable
        store_pattern(state, base + HEAP_INITIAL_MAPPED_SIZE - 16, 1, 16)
        assert load_pattern(state, base + HEAP_INITIAL_MAPPED_SIZE - 16, 16) == pattern(1, 16)

        # ...and the very next byte is the one that triggers the growth
        second = state.heap._malloc(16)
        assert second == base + HEAP_INITIAL_MAPPED_SIZE
        assert state.heap._mapped_end == base + HEAP_INITIAL_MAPPED_SIZE * HEAP_MAPPING_GROWTH_FACTOR
        store_pattern(state, second, 2, 16)
        assert load_pattern(state, second, 16) == pattern(2, 16)

    def test_many_small_allocations_keep_their_data(self):
        state = make_state()
        addrs = [state.heap._malloc(1) for _ in range(20000)]
        for i, addr in enumerate(addrs):
            state.memory.store(addr, claripy.BVV(i & 0xFF, 8))

        assert state.heap._mapped_end >= state.heap.heap_location
        bad = [i for i, addr in enumerate(addrs) if state.solver.eval(state.memory.load(addr, 1)) != (i & 0xFF)]
        assert not bad, f"{len(bad)} of {len(addrs)} one-byte allocations lost their data"

    def test_one_large_allocation_maps_everything_it_needs(self):
        state = make_state()
        size = 4 * 1024 * 1024
        addr = state.heap._malloc(size)

        assert state.heap._mapped_end == state.heap.heap_base + size
        assert resident_heap_pages(state) == size // state.memory.page_size

        # every page of it has to be usable, not just the first one
        for off in range(0, size, 0x1000):
            state.memory.store(addr + off, claripy.BVV(off, 32))
        bad = [off for off in range(0, size, 0x1000) if state.solver.eval(state.memory.load(addr + off, 4)) != off]
        assert not bad, f"{len(bad)} pages of the large allocation lost their data"

    def test_symbolic_size_allocation_keeps_its_data(self):
        state = make_state()
        state.libc.max_variable_size = 0x8000  # otherwise a symbolic size is clamped to 128 bytes and maps nothing
        size = claripy.BVS("size", 64)
        state.solver.add(size.UGE(0x1000), size.ULE(0x5000))

        addr = state.heap._malloc(size)
        # the symbolic size is maximized, so the whole 0x5000 has to be backed
        assert state.heap._mapped_end >= addr + 0x5000
        for i, off in enumerate((0, 0x1000, 0x2FFF, 0x5000 - 64)):
            store_pattern(state, addr + off, i, 64)
        for i, off in enumerate((0, 0x1000, 0x2FFF, 0x5000 - 64)):
            assert load_pattern(state, addr + off, 64) == pattern(i, 64)

    def test_release_does_not_shrink_and_does_not_lose_data(self):
        # deliberate: release() does not unmap, because unmapping would discard the page contents and a release
        # followed by an allocation would hand back blank memory instead of the old bytes
        state = make_state()
        first = state.heap._malloc(0x4000)
        store_pattern(state, first + 0x3000, 5, 64)
        extent_before = state.heap._mapped_end

        state.heap.release(0x4000)
        assert state.heap.heap_location == state.heap.heap_base
        assert state.heap._mapped_end == extent_before
        assert resident_heap_pages(state) == (extent_before - state.heap.heap_base) // state.memory.page_size

        second = state.heap._malloc(0x4000)
        assert second == first
        assert load_pattern(state, second + 0x3000, 64) == pattern(5, 64)

        # over-releasing is clamped at the base and still does not unmap anything
        state.heap.release(0x1000000)
        assert state.heap.heap_location == state.heap.heap_base
        assert state.heap._mapped_end == extent_before

    def test_copy_carries_the_mapped_extent(self):
        state = make_state()
        state.heap._malloc(0x9000)
        copy = state.copy()
        assert copy.heap._mapped_end == state.heap._mapped_end
        assert resident_heap_pages(copy) == resident_heap_pages(state)

    def test_divergent_copies_do_not_interfere(self):
        state = make_state()
        common = []
        for i in range(64):
            addr = state.heap._malloc(64)
            store_pattern(state, addr, i, 64)
            common.append((addr, i))

        first, second = state.copy(), state.copy()
        first_allocs, second_allocs = [], []
        for i in range(64):
            addr = first.heap._malloc(0x200)
            store_pattern(first, addr, i + 1000, 64)
            first_allocs.append((addr, i + 1000))

            addr = second.heap._malloc(0x2000)
            store_pattern(second, addr, i + 5000, 64)
            second_allocs.append((addr, i + 5000))

        # the two copies really did grow to different extents, so this is exercising something
        assert first.heap._mapped_end < second.heap._mapped_end
        for copy, allocs in ((first, first_allocs), (second, second_allocs)):
            for addr, i in common + allocs:
                assert load_pattern(copy, addr, 64) == pattern(i, 64)

    def test_merge_takes_the_minimum_mapped_extent(self):
        # understating the extent is safe (growing it skips pages that already exist); overstating it could leave
        # a hole in the middle of the region that nothing would ever map
        state = make_state()
        state.heap._malloc(64)
        first, second = state.copy(), state.copy()
        first.heap._malloc(0x10000)
        second.heap._malloc(0x40)
        assert first.heap._mapped_end > second.heap._mapped_end

        merged, _, _ = first.merge(second)
        assert merged.heap._mapped_end == min(first.heap._mapped_end, second.heap._mapped_end)

        # NOTE: SimHeapBrk._combine takes max() over `others` *excluding self*, so the merged break drops to the
        # other state's value instead of the high-water mark. That is a pre-existing angr bug, unrelated to (and
        # unchanged by) the lazy mapping; assert what actually happens rather than what should.
        assert merged.heap.heap_location == second.heap.heap_location

        # whatever the extent ended up being, allocating out of the merged state still has to work
        addr = merged.heap._malloc(0x20000)
        assert addr >= merged.heap.heap_base
        store_pattern(merged, addr, 7, 64)
        store_pattern(merged, addr + 0x20000 - 64, 8, 64)
        assert load_pattern(merged, addr, 64) == pattern(7, 64)
        assert load_pattern(merged, addr + 0x20000 - 64, 64) == pattern(8, 64)
        assert merged.heap._mapped_end >= merged.heap.heap_location

    def test_merge_with_an_unmanaged_extent_stays_unmanaged(self):
        # bookkeeping-only path, so it is tested directly: if any side does not manage the mapping, neither does
        # the result
        first, second = SimHeapBrk(), SimHeapBrk()
        first._mapped_end = first.heap_base + 0x4000
        second._mapped_end = None
        first._combine_mapped_end([second])
        assert first._mapped_end is None

    def test_unpickling_a_state_from_before_lazy_mapping(self):
        # states pickled before this change have no _mapped_end at all; back then init_state() mapped the whole
        # region, so that is the extent they have to come back with
        heap = SimHeapBrk()
        old_style = dict(heap.__dict__)
        del old_style["_mapped_end"]

        restored = SimHeapBrk.__new__(SimHeapBrk)
        restored.__setstate__(old_style)
        assert restored._mapped_end == restored.heap_base + restored.heap_size

        # and a state pickled *now* round-trips its actual extent
        state = make_state()
        state.heap._malloc(0x5000)
        extent = state.heap._mapped_end
        assert pickle.loads(pickle.dumps(state)).heap._mapped_end == extent

    def test_abstract_memory_does_not_manage_the_mapping(self):
        state = SimState(arch="AMD64", add_options={angr.options.ABSTRACT_MEMORY})
        assert state.heap._mapped_end is None
        # ...and _ensure_mapped stays a no-op forever after
        state.heap._ensure_mapped(state.heap.heap_base + 0x100000)
        assert state.heap._mapped_end is None

    def test_a_preexisting_mapping_is_left_alone(self):
        state = make_state()
        state.memory.map_region(0x50000000, 0x2000, 3)
        pages_before = len(state.memory._pages)

        # somebody else owns this region, so the heap plugin must not map or grow anything in it
        heap = SimHeapBrk(heap_base=0x50000000, heap_size=0x100000)
        state.register_plugin("heap", heap)
        assert heap._mapped_end is None
        assert len(state.memory._pages) == pages_before

        heap._ensure_mapped(0x50000000 + 0x80000)
        assert heap._mapped_end is None
        assert len(state.memory._pages) == pages_before

    def test_gdb_set_heap_grows_the_extent(self):
        state = make_state()
        base = state.heap.heap_base
        state.gdb.set_heap(os.path.join(gdb_data_location, "heap"), heap_base=base)

        dumped = os.path.getsize(os.path.join(gdb_data_location, "heap"))
        assert state.heap.heap_location == base + dumped
        assert state.heap._mapped_end >= base + dumped
        assert resident_heap_pages(state) == (state.heap._mapped_end - base) // state.memory.page_size

        # the tail of the dump has to have landed in memory, not in a page that was never mapped
        with open(os.path.join(gdb_data_location, "heap"), "rb") as f:
            f.seek(dumped - 16)
            tail = f.read(16)
        assert load_pattern(state, base + dumped - 16, 16) == tail

    def test_strict_page_access_now_rejects_writes_past_the_allocations(self):
        # DELIBERATE NARROWING: with the whole region mapped up front, a program could scribble anywhere in the
        # 8 MB heap under STRICT_PAGE_ACCESS and get away with it. Now only what has been handed out (rounded up
        # to the mapped extent) is backed, so writing past it faults. Pinned here so the change is visible.
        state = make_state(add_options={angr.options.STRICT_PAGE_ACCESS})
        addr = state.heap._malloc(64)
        beyond = state.heap.heap_base + HEAP_INITIAL_MAPPED_SIZE
        assert state.heap._mapped_end == beyond

        # inside the allocation, and anywhere inside the mapped extent, is still fine
        store_pattern(state, addr, 3, 64)
        assert load_pattern(state, addr, 64) == pattern(3, 64)
        state.memory.store(beyond - 1, claripy.BVV(0x5A, 8))

        with self.assertRaises(angr.errors.SimSegfaultException):
            state.memory.store(beyond, claripy.BVV(0x5A, 8))

    def test_writes_past_the_extent_still_work_without_strict_page_access(self):
        # the narrowing above is confined to STRICT_PAGE_ACCESS; the default memory still auto-maps
        state = make_state()
        beyond = state.heap.heap_base + HEAP_INITIAL_MAPPED_SIZE
        state.memory.store(beyond, claripy.BVV(0x5A, 8))
        assert state.solver.eval(state.memory.load(beyond, 1)) == 0x5A


class TestHeapPTMallocLazyMapping(unittest.TestCase):
    def test_final_word_page_is_mapped_at_init(self):
        # this heap keeps the last chunk's usage flag in the final word of the region, which init_state writes, so
        # that one page is mapped up front even though the extent stops far short of it
        state = make_state(SimHeapPTMalloc())
        page_size = state.memory.page_size
        region_end = state.heap.heap_base + state.heap.heap_size
        final_pageno = (region_end - 1) // page_size

        assert state.heap._mapped_end == state.heap.heap_base + HEAP_INITIAL_MAPPED_SIZE
        assert state.memory._pages.get(final_pageno) is not None
        # the initial extent plus the single final page, and nothing else
        assert resident_heap_pages(state) == HEAP_INITIAL_MAPPED_SIZE // page_size + 1

    def test_malloc_free_and_reuse_across_a_growth_boundary(self):
        state = make_state(SimHeapPTMalloc())
        base = state.heap.heap_base

        first = state.heap.malloc(0x1000)
        second = state.heap.malloc(0x2000)  # runs past the initial extent
        third = state.heap.malloc(0x4000)  # ...and past the next one too
        assert first and second and third
        assert state.heap._mapped_end > base + HEAP_INITIAL_MAPPED_SIZE
        assert state.heap._mapped_end >= third + 0x4000

        allocs = {first: 0x1000, second: 0x2000, third: 0x4000}
        for i, (addr, size) in enumerate(allocs.items()):
            store_pattern(state, addr, i, 64)
            store_pattern(state, addr + size - 64, i + 100, 64)
        chunks_before = [(c.base, c.is_free()) for c in state.heap.chunks()]

        # free the middle chunk and hand the same space back out
        state.heap.free(second)
        again = state.heap.malloc(0x2000)
        assert again == second
        store_pattern(state, again, 50, 64)

        # the untouched allocations on either side of the freed one kept their contents
        for i, (addr, size) in enumerate(allocs.items()):
            if addr == second:
                continue
            assert load_pattern(state, addr, 64) == pattern(i, 64)
            assert load_pattern(state, addr + size - 64, 64) == pattern(i + 100, 64)
        assert load_pattern(state, again, 64) == pattern(50, 64)

        # the chunk walk has to still terminate and describe the same heap
        chunks_after = [(c.base, c.is_free()) for c in state.heap.chunks()]
        assert chunks_before
        assert [c[0] for c in chunks_after] == [c[0] for c in chunks_before]

    def test_large_allocation_maps_the_whole_region(self):
        state = make_state(SimHeapPTMalloc())
        addr = state.heap.malloc(4 * 1024 * 1024)
        assert addr
        # the chunk plus the following chunk's metadata runs past half the region, so the extent doubles to cover
        # all of it
        assert state.heap._mapped_end == state.heap.heap_base + state.heap.heap_size

        store_pattern(state, addr, 11, 64)
        store_pattern(state, addr + 4 * 1024 * 1024 - 64, 12, 64)
        assert load_pattern(state, addr, 64) == pattern(11, 64)
        assert load_pattern(state, addr + 4 * 1024 * 1024 - 64, 64) == pattern(12, 64)

    def test_many_small_allocations_keep_their_data(self):
        state = make_state(SimHeapPTMalloc())
        allocs = []
        for i in range(200):
            addr = state.heap.malloc(0x100)
            assert addr
            store_pattern(state, addr, i, 64)
            allocs.append((addr, i))

        assert state.heap._mapped_end > state.heap.heap_base + HEAP_INITIAL_MAPPED_SIZE
        for addr, i in allocs:
            assert load_pattern(state, addr, 64) == pattern(i, 64)


if __name__ == "__main__":
    unittest.main()

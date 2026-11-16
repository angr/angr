""Regression for #7780: Symbolic Store that ends exactly at the end of a
page you should not create out-of-range keys in symbolic_data.

The 10.0.2 angr had _ultra_changed_candidates without top (`range(off, off + mo.length)`),
and the sentry key `addr + size` in page_size provoked IndexError in
symbolic_bitmap.get during VFG merges. Master limits candidates to `size`,
but the sentinel kept creating itself by violating the invariant `offsets < page_size`.
This test sets the invariant.
"""

from __future__ import annotations

from angr import SimState, claripy
from angr.storage.memory_mixins import (
    AddressConcretizationMixin,
    ConvenientMappingsMixin,
    DataNormalizationMixin,
    PagedMemoryMixin,
    SizeNormalizationMixin,
    SymbolicMergerMixin,
    UltraPagesMixin,
)
from tests.common import minimal_project


class UltraPageMemory(
    DataNormalizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    SymbolicMergerMixin,
    ConvenientMappingsMixin,
    UltraPagesMixin,
    PagedMemoryMixin,
):
    pass


class TestUltraPageEndSentinel:
    def test_overlapping_symbolic_store_at_page_end_creates_no_out_of_range_keys(self):
        page_size = 4096
        state = SimState(project=minimal_project("AMD64"), mode="symbolic", plugins={"memory": UltraPageMemory()})
        state.memory.store(page_size - 4, claripy.BVS("a", 32), endness="Iend_LE")
        state.memory.store(page_size - 4, claripy.BVS("b", 32), endness="Iend_LE")
        page = next(iter(state.memory._pages.values()))
        assert all(off < page_size for off in page.symbolic_data), list(page.symbolic_data)
        assert max(page.symbolic_data) == page_size - 4

    def test_page_end_store_merge_keeps_keys_in_range(self):
        page_size = 4096
        state0 = SimState(project=minimal_project("AMD64"), mode="symbolic", plugins={"memory": UltraPageMemory()})
        state0.memory.store(page_size - 4, claripy.BVS("a", 32), endness="Iend_LE")
        state0.memory.store(page_size - 4, claripy.BVS("b", 32), endness="Iend_LE")
        state1 = state0.copy()
        state0.memory.store(0x200, 1, 1)
        state1.memory.store(0x200, 2, 1)
        merged, _, _ = state0.merge(state1)
        for p in merged.memory._pages.values():
            assert all(off < page_size for off in p.symbolic_data), list(p.symbolic_data)

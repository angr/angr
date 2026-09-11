#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
"""Test cases for FunctionManager LMDB save/load and LRU cache functionality."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.errors import AngrRuntimeDbError
from angr.knowledge_plugins.functions.function_manager import SpillingFunctionDict
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestFunctionManagerLMDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin_path = os.path.join(test_location, "x86_64", "fauxware")

    def test_default_unlimited_cache(self):
        """Test that default cache is unlimited (no eviction)."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions

        assert fm.cache_limit is None, "Default should be None (unlimited)"
        assert fm.spilled_function_count == 0, "No functions should be spilled by default"
        assert fm.cached_function_count == fm.total_function_count, "All functions should be in memory"

    def test_set_cache_limit(self):
        """Test setting cache limit triggers eviction."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_count = len(fm)

        # Set cache limit
        cache_limit = 5
        fm.cache_limit = cache_limit

        assert fm.cached_function_count <= cache_limit, (
            f"Cache limit not respected: {fm.cached_function_count} > {cache_limit}"
        )
        assert fm.total_function_count == total_count, "Total function count should be preserved"
        assert fm.spilled_function_count == total_count - fm.cached_function_count, "Spilled count incorrect"

    def test_cache_properties(self):
        """Test cache monitoring properties."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total = len(fm)

        # Set small cache limit
        fm.cache_limit = 3

        # Verify properties
        assert fm.cached_function_count <= 3
        assert fm.spilled_function_count >= 0
        assert fm.total_function_count == total
        assert fm.cached_function_count + fm.spilled_function_count == fm.total_function_count

    def test_access_spilled_function(self):
        """Test that accessing a spilled function loads it from LMDB."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions

        # Set small cache limit
        fm.cache_limit = 3

        # Find a spilled function
        if fm.spilled_function_count == 0:
            self.skipTest("No spilled functions to test")

        spilled_addr = next(iter(fm._spilled_addrs))

        # Access the spilled function
        func = fm[spilled_addr]

        # Verify it was loaded
        assert func is not None, "Failed to load spilled function"
        assert func.addr == spilled_addr, "Loaded function has wrong address"

    def test_dynamic_cache_limit_decrease(self):
        """Test decreasing cache limit dynamically."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total = len(fm)

        # Start with larger limit
        fm.cache_limit = 10
        assert fm.cached_function_count <= 10

        # Decrease limit
        fm.cache_limit = 5
        assert fm.cached_function_count <= 5

        # Further decrease
        fm.cache_limit = 2
        assert fm.cached_function_count <= 2

        # Total should be preserved
        assert fm.total_function_count == total

    def test_dynamic_cache_limit_increase(self):
        """Test increasing cache limit dynamically."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total = len(fm)

        # Start with small limit
        fm.cache_limit = 3
        cached_before = fm.cached_function_count

        # Increase limit (shouldn't auto-load more)
        fm.cache_limit = 10
        assert fm.cached_function_count >= cached_before  # May increase due to access

        # Total preserved
        assert fm.total_function_count == total

    def test_contains_with_spilled(self):
        """Test __contains__ checks both in-memory and spilled functions."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        all_addrs = set(fm)

        # Set small cache limit
        fm.cache_limit = 3

        # All addresses should still be "in" the function manager
        for addr in all_addrs:
            assert addr in fm, f"Address {hex(addr)} should be in function manager"

    def test_iter_with_spilled(self):
        """Test __iter__ includes both in-memory and spilled functions."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        all_addrs_before = set(fm)

        # Set small cache limit
        fm.cache_limit = 3

        # Iteration should still include all addresses
        all_addrs_after = set(fm)
        assert all_addrs_before == all_addrs_after, "Iteration should include all functions"

    def test_len_with_spilled(self):
        """Test __len__ returns total count including spilled."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_before = len(fm)

        # Set small cache limit
        fm.cache_limit = 3

        # Length should still return total count
        assert len(fm) == total_before, "len() should return total count"

    def test_spilled_function_call_sites(self):
        """Test that call sites survive spilling to LMDB and reloading."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        main_func = fm.function(name="main")
        assert main_func is not None
        main_addr = main_func.addr
        fm[main_addr]._add_call_site(0x4007D3, None, None)
        call_sites_before = dict(fm[main_addr]._call_sites)
        assert len(call_sites_before) > 1

        # Evict main from the cache
        fm.cache_limit = 1
        other_addr = next(addr for addr in fm if addr != main_addr)
        _ = fm[other_addr]
        assert main_addr in fm._spilled_addrs

        loaded = fm[main_addr]
        assert dict(loaded._call_sites) == call_sites_before

    def test_delete_spilled_function(self):
        """Test deleting a spilled function."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_before = len(fm)

        # Set small cache limit
        fm.cache_limit = 3

        if fm.spilled_function_count == 0:
            self.skipTest("No spilled functions to test")

        # Get a spilled address
        spilled_addr = next(iter(fm._spilled_addrs))

        # Delete it
        del fm[spilled_addr]

        # Verify it's removed
        assert spilled_addr not in fm
        assert len(fm) == total_before - 1

    def test_delete_cached_function(self):
        """Test deleting a cached (in-memory) function."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total_before = len(fm)

        # Set cache limit
        fm.cache_limit = 5

        # Get a cached address
        cached_addr = next(iter(fm._function_map.keys()))

        # Delete it
        del fm[cached_addr]

        # Verify it's removed
        assert cached_addr not in fm
        assert len(fm) == total_before - 1

    def test_clear_with_spilled(self):
        """Test clear() removes both in-memory and spilled functions."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions

        # Set cache limit
        fm.cache_limit = 3

        # Clear
        fm.clear()

        assert len(fm) == 0
        assert fm.cached_function_count == 0
        assert fm.spilled_function_count == 0

    def test_copy_with_spilled(self):
        """Test copy() works with spilled functions."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()

        fm = proj.kb.functions
        total = len(fm)

        # Set cache limit
        fm.cache_limit = 5

        # Copy
        fm_copy = fm.copy()

        # Verify copy has all functions
        assert fm_copy.total_function_count == total

    def _spilled_function_map(self) -> tuple[angr.Project, SpillingFunctionDict]:
        """Recover a CFG and shrink the function cache until part of it has spilled to LMDB."""
        proj = angr.Project(self.bin_path, auto_load_libs=False)
        proj.analyses.CFGFast()
        fm = proj.kb.functions
        fm.cache_limit = 3
        assert fm.spilled_function_count > 0
        function_map = fm._function_map
        assert isinstance(function_map, SpillingFunctionDict)
        # the project owns the knowledge base the function map holds a weak reference back to
        return proj, function_map

    def test_spilling_dict_copy_carries_spilled_functions(self):
        """SpillingFunctionDict.copy() carries the spilled functions over as well as the cached ones."""
        _proj, function_map = self._spilled_function_map()
        addrs = set(function_map)
        cached, spilled = function_map.cached_count, function_map.spilled_count

        new_map = function_map.copy()

        assert set(new_map) == addrs
        assert new_map.cached_count == cached
        assert new_map.spilled_count == spilled
        for addr in addrs:
            assert new_map[addr].addr == addr

    def test_spilling_dict_copy_holds_one_transaction_at_a_time(self):
        """
        copy() writes the spilled records back out into a new sub-database, and that write may have to grow the
        LMDB map. Growing the map remaps the whole environment, so the read transaction has to be closed first.
        """
        proj, function_map = self._spilled_function_map()
        rtdb = proj.kb.rtdb
        original_transaction_opened = rtdb._transaction_opened
        open_counts = []

        def transaction_opened():
            original_transaction_opened()
            open_counts.append(rtdb._open_txns)

        rtdb._transaction_opened = transaction_opened
        try:
            function_map.copy()
        finally:
            del rtdb._transaction_opened

        assert open_counts, "copy() read nothing back out of LMDB"
        assert max(open_counts) == 1, "copy() opened a second transaction before closing the first"

    def test_unparseable_spilled_record_names_the_record(self):
        """A record that does not parse back must be reported as such, not as a bare protobuf DecodeError."""
        proj, function_map = self._spilled_function_map()
        fm = proj.kb.functions

        funcsdb = function_map._funcsdb
        assert funcsdb is not None
        spilled_addr = next(iter(fm._spilled_addrs))
        with proj.kb.rtdb.begin_txn(funcsdb, write=True) as txn:
            txn.put(str(spilled_addr).encode("utf-8"), b"\xff" * 16)

        with self.assertRaises(AngrRuntimeDbError) as ctx:
            _ = fm[spilled_addr]
        message = str(ctx.exception)
        assert hex(spilled_addr) in message
        assert "16 bytes" in message
        assert funcsdb in message


if __name__ == "__main__":
    unittest.main()

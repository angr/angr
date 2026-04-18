#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long

"""Tests for MSVC C++ exception handling struct identification in CFGFast."""

from __future__ import annotations

import os
import unittest

import angr
from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from angr.analyses.cfg.pe_msvc_eh_structs import (
    parse_funcinfo,
    parse_unwind_map,
    parse_eh4_scopetable,
    FUNCINFO_SIZE,
    UNWINDMAPENTRY_SIZE,
    EH4_SCOPETABLE_HEADER_SIZE,
    EH4_SCOPETABLE_RECORD_SIZE,
)

from tests.common import bin_location, is_testing

TEST_BINARY = os.path.join(
    bin_location,
    "tests",
    "i386",
    "windows",
    "fd32071ceb9ef9bb2cde570c57cd6bf34b10920a6894e0b7a176e3f64d1fc95d",
)


class TestCFGFastPEMsvcEH(unittest.TestCase):
    """Test that CFGFast correctly identifies MSVC C++ EH functions and structs."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(TEST_BINARY)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True, show_progressbar=not is_testing)

    #
    # Function identification
    #

    def test_cxxframehandler3_identified(self):
        """___CxxFrameHandler3 should be identified at its known address."""
        func = self.cfg.kb.functions.get_by_addr(0x50B21222)
        assert func.info.get("is_CxxFrameHandler3") is True

    def test_eh_prolog3_identified(self):
        """__EH_prolog3 should be identified at its known address."""
        func = self.cfg.kb.functions.get_by_addr(0x50B215BB)
        assert func.info.get("is_EH_prolog3") is True

    def test_eh_prolog3_catch_identified(self):
        """__EH_prolog3_catch should be identified at its known address."""
        func = self.cfg.kb.functions.get_by_addr(0x50B215F3)
        assert func.info.get("is_EH_prolog3_catch") is True

    def test_eh_prolog3_gs_identified(self):
        """__EH_prolog3_GS should be identified at its known address."""
        func = self.cfg.kb.functions.get_by_addr(0x50B2162E)
        assert func.info.get("is_EH_prolog3_GS") is True

    def test_seh_prolog4_identified(self):
        """__SEH_prolog4 should be identified at its known address."""
        func = self.cfg.kb.functions.get_by_addr(0x50B20E9C)
        assert func.info.get("is_SEH_prolog4") is True

    def test_seh_prolog4_gs_identified(self):
        """__SEH_prolog4_GS should be identified at its known address."""
        func = self.cfg.kb.functions.get_by_addr(0x50B22E8C)
        assert func.info.get("is_SEH_prolog4_GS") is True

    #
    # EH-related functions
    #

    def test_identified_functions_are_mutually_exclusive(self):
        """Each identified function should carry exactly one EH/SEH label."""
        labels = [
            "is_CxxFrameHandler3",
            "is_EH_prolog3",
            "is_EH_prolog3_catch",
            "is_EH_prolog3_GS",
            "is_SEH_prolog4",
            "is_SEH_prolog4_GS",
        ]
        known = {
            0x50B21222: "is_CxxFrameHandler3",
            0x50B215BB: "is_EH_prolog3",
            0x50B215F3: "is_EH_prolog3_catch",
            0x50B2162E: "is_EH_prolog3_GS",
            0x50B20E9C: "is_SEH_prolog4",
            0x50B22E8C: "is_SEH_prolog4_GS",
        }
        for addr, expected_label in known.items():
            func = self.cfg.kb.functions.get_by_addr(addr)
            for label in labels:
                if label == expected_label:
                    assert func.info.get(label) is True, f"Function at {addr:#x} should have {label}"
                else:
                    assert not func.info.get(label), f"Function at {addr:#x} should NOT have {label}"

    #
    # FuncInfo MemoryData items
    #

    def test_funcinfo_memory_data_created(self):
        """CFGFast should create EHFuncInfo MemoryData items."""
        fi_count = sum(1 for md in self.cfg.model.memory_data.values() if md.sort == MemoryDataSort.EHFuncInfo)
        assert fi_count == 132, f"Expected 132 FuncInfo entries, got {fi_count}"

    def test_funcinfo_memory_data_size(self):
        """Each EHFuncInfo MemoryData item should have size == FUNCINFO_SIZE."""
        for addr, md in self.cfg.model.memory_data.items():
            if md.sort == MemoryDataSort.EHFuncInfo:
                assert md.size == FUNCINFO_SIZE, f"FuncInfo at {addr:#x} has size {md.size}, expected {FUNCINFO_SIZE}"

    def test_specific_funcinfo_exists(self):
        """A known FuncInfo at 0x50b489ec should exist in memory_data."""
        assert 0x50B489EC in self.cfg.model.memory_data
        md = self.cfg.model.memory_data[0x50B489EC]
        assert md.sort == MemoryDataSort.EHFuncInfo

    #
    # UnwindMapEntry MemoryData items
    #

    def test_unwindmap_memory_data_created(self):
        """CFGFast should create EHUnwindMapEntry MemoryData items."""
        uw_count = sum(1 for md in self.cfg.model.memory_data.values() if md.sort == MemoryDataSort.EHUnwindMapEntry)
        assert uw_count == 132, f"Expected 132 UnwindMapEntry arrays, got {uw_count}"

    def test_specific_unwindmap_exists(self):
        """The UnwindMap for FuncInfo at 0x50b489ec should be at 0x50b48a38."""
        assert 0x50B48A38 in self.cfg.model.memory_data
        md = self.cfg.model.memory_data[0x50B48A38]
        assert md.sort == MemoryDataSort.EHUnwindMapEntry
        # FuncInfo.maxState == 6, so 6 * 8 = 48 bytes
        assert md.size == 6 * UNWINDMAPENTRY_SIZE

    #
    # Code references from UnwindMapEntry action pointers
    #

    def test_code_references_created_for_unwind_actions(self):
        """Non-null action pointers in UnwindMapEntry should produce CodeReference items."""
        coderef_count = sum(1 for md in self.cfg.model.memory_data.values() if md.sort == MemoryDataSort.CodeReference)
        assert coderef_count > 0, "Expected CodeReference items from unwind action pointers"

    #
    # Parsing helpers
    #

    def test_parse_funcinfo_known_struct(self):
        """parse_funcinfo should correctly parse the FuncInfo at 0x50b489ec."""
        fi = parse_funcinfo(self.proj.loader.memory, 0x50B489EC)
        assert fi is not None
        assert fi.magic_number == 0x19930522
        assert fi.max_state == 6
        assert fi.p_unwind_map == 0x50B48A38
        assert fi.n_try_blocks == 2
        assert fi.p_try_block_map == 0x50B48A10

    def test_parse_unwind_map_known_entries(self):
        """parse_unwind_map should correctly parse the UnwindMap for FuncInfo at 0x50b489ec."""
        entries = parse_unwind_map(self.proj.loader.memory, 0x50B48A38, 6)
        assert len(entries) == 6

        # First entry: toState=-1, action=0x50b43c16
        assert entries[0].to_state == -1
        assert entries[0].action == 0x50B43C16

        # Fourth entry: toState=-1, action=0x50b43c21
        assert entries[3].to_state == -1
        assert entries[3].action == 0x50B43C21

        # Entries with null actions
        assert entries[1].action == 0
        assert entries[2].action == 0

    def test_parse_funcinfo_invalid_address(self):
        """parse_funcinfo should return None for an address with invalid magic."""
        fi = parse_funcinfo(self.proj.loader.memory, 0x50B01000)
        assert fi is None

    #
    # _EH4_SCOPETABLE MemoryData items
    #

    def test_eh4_scopetable_memory_data_created(self):
        """CFGFast should create EH4ScopeTable MemoryData items for SEH prolog4 callers."""
        st_count = sum(1 for md in self.cfg.model.memory_data.values() if md.sort == MemoryDataSort.EH4ScopeTable)
        assert st_count == 52, f"Expected 52 EH4ScopeTable entries, got {st_count}"

    def test_eh4_scopetable_occupied(self):
        """EH4ScopeTable regions should be marked as occupied in _seg_list."""
        for addr, md in self.cfg.model.memory_data.items():
            if md.sort == MemoryDataSort.EH4ScopeTable:
                assert self.cfg._seg_list.is_occupied(addr), f"EH4ScopeTable at {addr:#x} should be occupied"
                sort = self.cfg._seg_list.occupied_by_sort(addr)
                assert sort == MemoryDataSort.EH4ScopeTable, (
                    f"EH4ScopeTable at {addr:#x} should be occupied as eh4-scopetable, got {sort}"
                )

    def test_specific_eh4_scopetable_single_record(self):
        """A known 1-record scope table at 0x50b4ae80 should exist with correct size."""
        assert 0x50B4AE80 in self.cfg.model.memory_data
        md = self.cfg.model.memory_data[0x50B4AE80]
        assert md.sort == MemoryDataSort.EH4ScopeTable
        assert md.size == EH4_SCOPETABLE_HEADER_SIZE + 1 * EH4_SCOPETABLE_RECORD_SIZE

    def test_specific_eh4_scopetable_multi_record(self):
        """A known 8-record scope table at 0x50b4ae10 should exist with correct size."""
        assert 0x50B4AE10 in self.cfg.model.memory_data
        md = self.cfg.model.memory_data[0x50B4AE10]
        assert md.sort == MemoryDataSort.EH4ScopeTable
        assert md.size == EH4_SCOPETABLE_HEADER_SIZE + 8 * EH4_SCOPETABLE_RECORD_SIZE

    #
    # _EH4_SCOPETABLE parsing helpers
    #

    def test_parse_eh4_scopetable_known_struct(self):
        """parse_eh4_scopetable should correctly parse the scope table at 0x50b4ae10."""
        st = parse_eh4_scopetable(self.proj.loader.memory, 0x50B4AE10, code_range=(0x50B01000, 0x50B4DCB1))
        assert st is not None
        assert st.gs_cookie_offset == -2
        assert st.eh_cookie_offset == -44
        assert len(st.records) == 8
        # First record
        assert st.records[0].enclosing_level == -2
        assert st.records[0].filter_func == 0x50B204AF
        assert st.records[0].handler_func == 0x50B204C0

    def test_parse_eh4_scopetable_finally_handler(self):
        """A __finally scope record should have filter_func == 0."""
        st = parse_eh4_scopetable(self.proj.loader.memory, 0x50B4AF80, code_range=(0x50B01000, 0x50B4DCB1))
        assert st is not None
        assert len(st.records) == 1
        assert st.records[0].filter_func == 0
        assert st.records[0].handler_func != 0

    def test_parse_eh4_scopetable_invalid_address(self):
        """parse_eh4_scopetable should return None for an address with invalid data."""
        st = parse_eh4_scopetable(self.proj.loader.memory, 0x50B01000, code_range=(0x50B01000, 0x50B4DCB1))
        assert st is None


if __name__ == "__main__":
    unittest.main()

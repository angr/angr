#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long

"""Tests for PE metadata region awareness in CFGFast."""

from __future__ import annotations

import os
import unittest

import angr

from tests.common import bin_location, is_testing


class TestCFGFastPEMetaRegions(unittest.TestCase):
    """Test that CFGFast correctly marks PE metadata regions as data."""

    @classmethod
    def setUpClass(cls):
        TEST_BINARY = os.path.join(
            bin_location, "tests", "i386", "windows", "3995b0522f1daaf8dc1341f87f34a1897ae8988e8dfa1cbe0bc98943385f4c38"
        )

        # Known layout of the test binary (PE32, ImageBase=0x76be0000):
        # .text section: RVA 0x1000..0x26d98
        # IAT (dir 12):        RVA 0x1000, size 0x4d0  -> inside .text
        # Export dir (dir 0):  RVA 0x3440, size 0x117d  -> inside .text
        # Import dir (dir 1):  RVA 0x24f90, size 0xc8   -> inside .text
        # Delay import (dir 13): RVA 0x24ef8, size 0x40 -> inside .text

        cls._image_base = 0x76BE0000
        cls.proj = angr.Project(TEST_BINARY)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True, show_progressbar=not is_testing)

    def test_iat_marked_as_data(self):
        """IAT region should be marked as pointer-array in _seg_list, not code."""
        iat_start = self._image_base + 0x1000
        iat_end = self._image_base + 0x1000 + 0x4D0
        # Check several addresses within the IAT
        for addr in [iat_start, iat_start + 0x10, iat_end - 4]:
            occupied = self.cfg._seg_list.is_occupied(addr)
            sort = self.cfg._seg_list.occupied_by_sort(addr)
            assert occupied, f"IAT address {addr:#x} should be occupied"
            assert sort == "pointer-array", f"IAT address {addr:#x} should be pointer-array instead of {sort}"

    def test_export_table_marked_as_data(self):
        """Export table region should be marked as data."""
        exp_start = self._image_base + 0x3440
        occupied = self.cfg._seg_list.is_occupied(exp_start)
        sort = self.cfg._seg_list.occupied_by_sort(exp_start)
        assert occupied, f"Export table at {exp_start:#x} should be occupied"
        assert sort == "pe-export-directory", (
            f"Export table at {exp_start:#x} should be pe-export-directory instead of {sort}"
        )

    def test_no_code_nodes_in_iat(self):
        """No CFG code nodes should overlap with the IAT region."""
        iat_start = self._image_base + 0x1000
        iat_end = self._image_base + 0x1000 + 0x4D0
        for node in self.cfg.model.nodes():
            if node.size is None or node.size == 0:
                continue
            node_end = node.addr + node.size
            # Check for overlap
            overlaps = node.addr < iat_end and node_end > iat_start
            assert overlaps is False, (
                f"Code node at {node.addr:#x} (size {node.size}) overlaps IAT region {iat_start:#x}..{iat_end:#x}"
            )

    def test_no_code_nodes_in_export_table(self):
        """No CFG code nodes should overlap with the export table region."""
        exp_start = self._image_base + 0x3440
        exp_end = self._image_base + 0x3440 + 0x117D
        for node in self.cfg.model.nodes():
            if node.size is None or node.size == 0:
                continue
            node_end = node.addr + node.size
            overlaps = node.addr < exp_end and node_end > exp_start
            assert overlaps is False, (
                f"Code node at {node.addr:#x} (size {node.size}) overlaps export table {exp_start:#x}..{exp_end:#x}"
            )

    def test_exported_functions_discovered(self):
        """Exported functions should be discovered by CFGFast."""
        known_exports = {
            "CryptCATAdminAcquireContext": self._image_base + 0xADDB,
            "CryptCATAdminCalcHashFromFileHandle": self._image_base + 0x9261,
            "AddPersonalTrustDBPages": self._image_base + 0x15146,
        }
        for name, expected_addr in known_exports.items():
            assert expected_addr in self.cfg.kb.functions, (
                f"Exported function {name} at {expected_addr:#x} should be in function list"
            )

    def test_memory_data_entries_for_metadata(self):
        """MemoryData entries should exist for metadata regions."""
        iat_start = self._image_base + 0x1000
        assert iat_start in self.cfg.model.memory_data, f"MemoryData entry should exist for IAT at {iat_start:#x}"


if __name__ == "__main__":
    unittest.main()

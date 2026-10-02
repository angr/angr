#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCfgNoExeutableRegions(unittest.TestCase):
    def test_cfg_no_exec_regions_65e25ea2(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "65e25ea21a2f873affee8034e2c3381df48ff4129d447fa288fbd92307647582"
        )
        p = angr.Project(bin_path)
        with self.assertLogs("angr.analyses.cfg.cfg_base", level=logging.WARNING) as logs:
            cfg = p.analyses.CFG()
        assert len(cfg.kb.functions) == 0
        assert cfg.regions == []
        assert any("nothing to scan" in record for record in logs.output)

    def test_cfg_empty_executable_section_is_not_a_region(self):
        # riscv-reloc-64-pic.o only carries data: its .text is SHF_EXECINSTR with sh_size 0, so it maps no bytes.
        bin_path = os.path.join(test_location, "riscv64", "riscv-reloc-64-pic.o")
        p = angr.Project(bin_path, auto_load_libs=False)
        with self.assertLogs("angr.analyses.cfg.cfg_base", level=logging.WARNING) as logs:
            cfg = p.analyses.CFGFast()
        assert len(cfg.kb.functions) == 0
        assert cfg.regions == []
        assert any("nothing to scan" in record for record in logs.output)

    def test_cfg_scoped_to_an_object_that_holds_no_code(self):
        # The extern object CLE builds holds no code, so scoping CFGFast to it gives an empty map rather
        # than every backer in the loader.
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        p = angr.Project(bin_path, auto_load_libs=False)
        main_object = p.loader.main_object
        with self.assertLogs("angr.analyses.cfg.cfg_base", level=logging.WARNING) as logs:
            cfg = p.analyses.CFGFast(binary=p.loader.extern_object)
            assert cfg.regions == []
            assert not [f for f in cfg.kb.functions.values() if main_object.min_addr <= f.addr <= main_object.max_addr]
        assert any("nothing to scan" in record for record in logs.output)

    def test_cfg_elf_no_section_headers(self):
        # Regression test for #6409: stripped ELFs with no section headers fall back to segments.
        bin_path = os.path.join(test_location, "armel", "dbus-cleanup-sockets_stripped")
        p = angr.Project(bin_path)
        # Regions come from segments here, so there are bytes to scan.
        with self.assertNoLogs("angr.analyses.cfg.cfg_base", level=logging.WARNING):
            cfg = p.analyses.CFG()
        assert len(cfg.kb.functions) > 0

    def test_warning_offers_force_segment_only_where_segments_hold_code(self):
        # Telling the caller to set force_segment is only worth doing where deriving the regions from segments
        # gives something to scan. A PE's segments are its sections, and this relocatable has no executable
        # segment either, so on both of these the knob cannot change the empty map and must not be offered.
        windows_dll = os.path.join(
            test_location, "x86_64", "windows", "65e25ea21a2f873affee8034e2c3381df48ff4129d447fa288fbd92307647582"
        )
        relocatable = os.path.join(test_location, "riscv64", "riscv-reloc-64-pic.o")
        for bin_path, auto_load_libs in ((windows_dll, True), (relocatable, False)):
            p = angr.Project(bin_path, auto_load_libs=auto_load_libs)
            with self.assertLogs("angr.analyses.cfg.cfg_base", level=logging.WARNING) as logs:
                cfg = p.analyses.CFGFast()
            assert cfg.regions == []
            said = [record for record in logs.output if "nothing to scan" in record]
            assert len(said) == 1, said
            assert '"regions"' in said[0]
            assert 'set "force_segment" to derive' not in said[0]
            assert '"force_segment" will not help here' in said[0]
            # The setting the advice used to name, on a fresh project so the first run's knowledge base is not
            # reused: it leaves the map just as empty, which is why naming it was wrong.
            fresh = angr.Project(bin_path, auto_load_libs=auto_load_libs)
            assert fresh.analyses.CFGFast(force_segment=True).regions == []


if __name__ == "__main__":
    unittest.main()

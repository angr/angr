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

    def test_cfg_elf_no_section_headers(self):
        # Regression test for #6409: stripped ELFs with no section headers fall back to segments.
        bin_path = os.path.join(test_location, "armel", "dbus-cleanup-sockets_stripped")
        p = angr.Project(bin_path)
        # Regions come from segments here, so there are bytes to scan.
        with self.assertNoLogs("angr.analyses.cfg.cfg_base", level=logging.WARNING):
            cfg = p.analyses.CFG()
        assert len(cfg.kb.functions) > 0


if __name__ == "__main__":
    unittest.main()

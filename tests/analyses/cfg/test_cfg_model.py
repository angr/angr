#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr
from angr.analyses import CFGFast
from tests.common import bin_location

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
FAUXWARE_PATH = os.path.join(bin_location, "tests", "x86_64", "fauxware")
REFLOW_FAUXWARE_PATH = os.path.join(bin_location, "tests", "x86_64", "fauxware_reflow")
LWIP_TCPECHO_PATH = os.path.join(bin_location, "tests", "armel", "lwip_tcpecho_bm.elf")


class TestCfgModel(unittest.TestCase):
    """
    Test cases for CFGModel.
    """

    def test_cfgmodel_clear_region_for_reflow(self):
        """Test CFGModel::clear_region_for_reflow."""
        proj = angr.Project(FAUXWARE_PATH, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()()
        func = cfg.functions["authenticate"]

        addr = 0x40068E
        end_addr = 0x400692
        cfg.model.clear_region_for_reflow(addr, end_addr - addr)

        for addr in func.block_addrs:
            assert cfg.model.get_any_node(addr) is None

    def test_cfgmodel_clear_region_for_reflow_multifunc(self):
        """Test CFGModel::clear_region_for_reflow across function boundaries."""
        proj = angr.Project(FAUXWARE_PATH, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()()

        expected_removed_addrs = list(cfg.functions["accepted"].block_addrs) + list(
            cfg.functions["rejected"].block_addrs
        )

        addr = 0x4006FB
        end_addr = 0x4006FE
        cfg.model.clear_region_for_reflow(addr, end_addr - addr)

        for addr in expected_removed_addrs:
            assert cfg.model.get_any_node(addr) is None

    def test_cfgmodel_find_func_for_reflow(self):
        """Test CFGModel::find_func_for_reflow in same function"""
        proj = angr.Project(REFLOW_FAUXWARE_PATH, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()()

        addr = 0x40131C
        func = cfg.model.find_function_for_reflow_into_addr(addr)
        assert func is not None
        assert func.name == "main"

    def test_cfgmodel_find_func_for_reflow_nonreturning(self):
        """Test CFGModel::find_func_for_reflow right after a non-returning function call in same function"""
        proj = angr.Project(REFLOW_FAUXWARE_PATH, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()()

        addr = 0x401371
        func = cfg.model.find_function_for_reflow_into_addr(addr)
        assert func is not None
        assert func.name == "main"

    def test_cfgmodel_find_func_for_reflow_multifunc(self):
        """Test CFGModel::find_func_for_reflow at function boundary"""
        proj = angr.Project(REFLOW_FAUXWARE_PATH, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()()

        addr = 0x4012C0
        func = cfg.model.find_function_for_reflow_into_addr(addr)
        assert func is None

    def test_cfgmodel_find_func_for_reflow_nonreturning_multifunc(self):
        """Test CFGModel::find_func_for_reflow at function boundary after a non-returning function call"""
        proj = angr.Project(REFLOW_FAUXWARE_PATH, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()()

        addr = 0x4012E6
        func = cfg.model.find_function_for_reflow_into_addr(addr)
        assert func is None

    def test_tidy_data_references_unmapped_data_addr_before_a_section(self):
        """Test CFGModel::tidy_data_references on a data address that no section or segment covers."""
        proj = angr.Project(LWIP_TCPECHO_PATH, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()()

        # this firmware image leaves a wide hole between its two loaded regions, and the pointer-array pass keeps
        # every pointer that lands in the main object's address range, the hole included
        unmapped_addr = 0x50020
        assert unmapped_addr in cfg.model.memory_data
        assert proj.loader.find_section_containing(unmapped_addr) is None
        assert proj.loader.find_segment_containing(unmapped_addr) is None
        assert proj.loader.find_section_next_to(unmapped_addr) is not None

        # tidying that address on its own, the way CFGFast tidies each batch of newly found data, leaves the next
        # section as the only bound in hand for it
        cfg.model.tidy_data_references(memory_data_addrs=[unmapped_addr])
        assert cfg.model.memory_data[unmapped_addr].max_size == 0


if __name__ == "__main__":
    unittest.main()

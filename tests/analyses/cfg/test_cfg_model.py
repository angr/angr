#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest
import logging

import angr
from angr.analyses import CFGFast

from ...common import bin_location

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
FAUXWARE_PATH = os.path.join(bin_location, "tests", "x86_64", "fauxware")


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


if __name__ == "__main__":
    unittest.main()

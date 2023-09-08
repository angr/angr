#!/usr/bin/env python3
__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ...common import bin_location

test_location = os.path.join(bin_location, "tests")
arches = {"i386", "x86_64"}


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCfgGetAnyNode(unittest.TestCase):
    def test_cfg_get_any_node(self):
        for arch in arches:
            self.run_cfg_get_any_node(arch)

    def run_cfg_get_any_node(self, arch):
        test_file = os.path.join(test_location, arch, "hello_world")
        proj = angr.Project(test_file, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for node1 in cfg.nodes():
            if node1.size == 0:
                node2 = cfg.get_any_node(addr=node1.addr, anyaddr=True)
                assert node2 is not None


if __name__ == "__main__":
    unittest.main()

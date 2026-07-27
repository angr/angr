#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.knowledge_plugins.functions.function import Function

try:
    import pysoot
except ModuleNotFoundError:
    pysoot = None

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
@unittest.skipUnless(pysoot, "pysoot not available")
class TestCfgfastSoot(unittest.TestCase):
    def test_simple1(self):
        binary_path = os.path.join(test_location, "java", "simple1.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple1.Class1.main"}, auto_load_libs=False)
        cfg = p.analyses.CFGFastSoot()
        assert cfg.graph.nodes()
        assert all(hasattr(function, slot) for function in cfg.kb.functions.values() for slot in Function.__slots__)

    def test_simple2(self):
        binary_path = os.path.join(test_location, "java", "simple2.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple2.Class1.main"}, auto_load_libs=False)
        cfg = p.analyses.CFGFastSoot()
        assert cfg.graph.nodes()


if __name__ == "__main__":
    unittest.main()

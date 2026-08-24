#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

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

    def test_simple2(self):
        binary_path = os.path.join(test_location, "java", "simple2.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple2.Class1.main"}, auto_load_libs=False)
        cfg = p.analyses.CFGFastSoot()
        assert cfg.graph.nodes()

    def test_simple2_without_entry_point(self):
        # simple2.jar has no Main-Class manifest attribute, so without an explicit entry_point the loader leaves
        # Project.entry at 0. CFGFastSoot must still analyze every method of every class.
        binary_path = os.path.join(test_location, "java", "simple2.jar")
        p = angr.Project(binary_path, auto_load_libs=False)
        assert p.entry == 0
        cfg = p.analyses.CFGFastSoot()
        assert cfg.graph.nodes()
        function_names = {f.name for f in p.kb.functions.values()}
        assert "simple2.Class1.main(java.lang.String[])" in function_names
        # methods that no entry point reaches are analyzed too
        assert "simple2.Class1.unreachable(int)" in function_names


if __name__ == "__main__":
    unittest.main()

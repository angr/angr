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

    def test_jni_library_of_another_architecture_is_not_scanned(self):
        # A JNI project's architecture is Soot and its native library's is not, so CFGFast cannot decode that
        # library and does not scan it. Skipping it must not drop the region collector into its raw-memory last
        # resort, which has nothing left to describe the program and would hand back the extern and kernel
        # objects instead.
        binary_path = os.path.join(test_location, "java", "fauxware_java_jni", "fauxware.jar")
        p = angr.Project(binary_path, main_opts={"jni_libs": ["libfauxware.so"]}, auto_load_libs=True)

        assert p.arch.name == "Soot"
        assert [obj for obj in p.loader.all_objects if obj.has_memory and obj.arch != p.arch] != []

        cfg = p.analyses.CFGFast()

        assert cfg.regions == []

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

    def test_invokespecial_on_an_interface(self):
        # Impl.greet() calls Greeter.super.greet(), so the invoke's declaring class is an interface.
        # Resolving it asks SootClassHierarchy whether that interface is a subclass of Impl;
        # get_super_classes has no chain to walk for an interface and raises, which aborted the CFG.
        binary_path = os.path.join(test_location, "java", "interface_default.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "iface.Impl.main"}, auto_load_libs=False)

        cfg = p.analyses.CFGFastSoot()

        assert cfg.graph.nodes()
        names = {f.name for f in cfg.kb.functions.values()}
        assert any("greet" in name for name in names), names


if __name__ == "__main__":
    unittest.main()

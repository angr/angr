#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.functions.soot_function import SootFunction

try:
    import pysoot
except ModuleNotFoundError:
    pysoot = None

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


@unittest.skipUnless(pysoot, "pysoot not available")
class TestSootFunction(unittest.TestCase):
    """
    SootFunction replaces Function.__init__ rather than extending it, so the two can drift apart.
    """

    functions: list[Function]

    @classmethod
    def setUpClass(cls):
        binary_path = os.path.join(test_location, "java", "simple1.jar")
        project = angr.Project(binary_path, main_opts={"entry_point": "simple1.Class1.main"}, auto_load_libs=False)
        cls.functions = list(project.analyses.CFGFastSoot().kb.functions.values())
        assert cls.functions
        assert all(isinstance(function, SootFunction) for function in cls.functions)

    def test_every_function_field_is_initialized(self):
        # SootFunction reimplements Function.__init__, so a field added to Function and forgotten there stays unset.
        uninitialized = {
            slot for function in self.functions for slot in Function.__slots__ if not hasattr(function, slot)
        }
        assert not uninitialized, f"SootFunction.__init__ leaves {sorted(uninitialized)} unset"

    def test_function_attributes_are_readable(self):
        # Each of these reads a field that SootFunction.__init__ used to leave unset, raising AttributeError.
        for function in self.functions:
            # Soot does not record where arguments live, so both argument lists stay empty.
            assert function.num_arguments == 0
            assert function.cyclomatic_complexity >= 1
            assert function.prototype is None
            assert function.is_prototype_guessed
            # The name is the method signature Soot reports, not a generated placeholder.
            assert not function.is_default_name
            assert not function.ran_cca
            assert not function.meta_only
            assert not function.evicted


if __name__ == "__main__":
    unittest.main()

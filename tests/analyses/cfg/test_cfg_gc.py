#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""Python objects CFGFast leaves behind."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import gc
import os
import unittest

import angr
from angr.analyses.cfg.indirect_jump_resolvers.constant_value_manager import ConstantValueManager
from angr.knowledge_plugins.functions.recovery import RecoveryFunction, RecoveryFunctionManager
from angr.rustylib.recovery_functions import RecoveryFunctions
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCFGFastGC(unittest.TestCase):
    def test_scan_time_functions_are_freed(self):
        # the jump-table resolver steps a state whose reg_read BP references a ConstantValueManager
        # exact types: isinstance() raises on dead weakproxies left by other tests
        scan_types = {RecoveryFunction, RecoveryFunctionManager, RecoveryFunctions, ConstantValueManager}
        before = {id(o) for o in gc.get_objects() if type(o) in scan_types}
        path = os.path.join(test_location, "x86_64", "fpijr_global_table")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        assert cfg.kb.functions
        gc.collect()
        leaked = [o for o in gc.get_objects() if type(o) in scan_types and id(o) not in before]
        assert not leaked, f"{len(leaked)} scan-time objects alive, e.g. {type(leaked[0]).__name__}"


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""CFGFast's scan-time function manager and the functions it drops are freed by refcount, without a GC pass."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import gc
import os
import pickle
import unittest
import weakref

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_plugins.functions.function import FunctionInfo
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angr.knowledge_plugins.functions.recovery import RecoveryFunctionManager
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestFunctionCycles(unittest.TestCase):
    def _cfg_without_gc(self, binary: str):
        managers: list[weakref.ref] = []
        removed: list[weakref.ref] = []
        orig_install = CFGFast._install_recovery_functions
        orig_del = FunctionManager.__delitem__

        def install(cfg):
            orig_install(cfg)
            if isinstance(cfg.kb.functions, RecoveryFunctionManager):
                managers.append(weakref.ref(cfg.kb.functions))

        def delitem(fm, addr):
            if not isinstance(fm, RecoveryFunctionManager):
                func = fm.get_by_addr(addr)
                if func is not None:
                    removed.append(weakref.ref(func))
            orig_del(fm, addr)

        CFGFast._install_recovery_functions = install
        FunctionManager.__delitem__ = delitem
        gc.disable()
        try:
            proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
            proj.analyses.CFGFast(normalize=True)
            return proj, managers, removed
        finally:
            gc.enable()
            CFGFast._install_recovery_functions = orig_install
            FunctionManager.__delitem__ = orig_del

    def test_scan_manager_freed_by_refcount(self):
        proj, managers, removed = self._cfg_without_gc("x86_64/cvs")
        assert managers and removed
        assert all(m() is None for m in managers)
        # functions removed as stubs or empty are not kept alive by their FunctionInfo
        assert all(f() is None for f in removed)
        assert not isinstance(proj.kb.functions, RecoveryFunctionManager)

    def test_no_cyclic_function_garbage(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        gc.collect()
        proj.analyses.CFGFast(normalize=True)
        gc.set_debug(gc.DEBUG_SAVEALL)
        try:
            gc.collect()
            kinds = {type(o).__name__ for o in gc.garbage}
        finally:
            gc.set_debug(0)
            gc.garbage.clear()
        assert not kinds & {"RecoveryFunctionManager", "RecoveryFunctions", "FunctionIndex", "Function", "FunctionInfo"}

    def test_function_info_back_reference(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions["main"]
        func.info["k"] = 1
        func._dirty = False
        func.info["k"] = 2
        assert func._dirty
        # pickles: the owner re-attaches itself
        loaded = pickle.loads(pickle.dumps(func, -1))
        assert dict(loaded.info) == dict(func.info) and loaded.info._func is loaded
        # states pickled with a strong back-reference
        legacy = FunctionInfo.__new__(FunctionInfo)
        legacy.__setstate__({"data": {"a": 1}, "_func": func})
        assert legacy._func is func and dict(legacy) == {"a": 1}
        # an info that outlives its function only stops marking it dirty
        fm = proj.kb.functions
        tmp = fm.function(addr=0x500000, create=True)
        assert tmp is not None
        orphan = tmp.info
        del fm[0x500000]
        del tmp
        assert orphan._func is None
        orphan["x"] = 1
        assert orphan["x"] == 1


if __name__ == "__main__":
    unittest.main()

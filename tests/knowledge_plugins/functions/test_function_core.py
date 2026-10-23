#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""FunctionCore, the Rust core of Function."""

from __future__ import annotations

import os
import pickle
import unittest

import angr
from angr.knowledge_plugins.functions import Function
from angr.rustylib.function_core import FunctionCore
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


def _core_fields(func: Function) -> dict:
    return {
        "addr": func.addr,
        "name": func.name,
        "is_default_name": func.is_default_name,
        "previous_names": list(func.previous_names),
        "binary_name": func.binary_name,
        "is_syscall": func.is_syscall,
        "is_simprocedure": func.is_simprocedure,
        "is_plt": func.is_plt,
        "is_alignment": func.is_alignment,
        "returning": func.returning,
        "prototype": func.prototype,
        "calling_convention": type(func.calling_convention),
        "prototype_libname": func.prototype_libname,
        "info": dict(func.info),
        "blocks": sorted(func.block_addrs_set),
    }


class TestFunctionCore(unittest.TestCase):
    def test_core_fields_and_dirty_tracking(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        func = Function(proj.kb.functions, 0x400580, syscall=False)
        assert isinstance(func, FunctionCore)
        func._dirty = False
        func.is_plt = func.is_plt
        assert not func.dirty
        func.is_plt = not func.is_plt
        assert func.dirty
        func._dirty = False
        func.name = "renamed"
        assert func.dirty
        assert func.previous_names == ["_start"]
        func.previous_names.append("other")  # the list is the function's own
        assert func.previous_names == ["_start", "other"]
        func.returning = False
        assert proj.kb.functions.is_func_nonreturning(0x400580)

    def test_pickle_and_legacy_state(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.kb.functions["main"]
        func.name = "main2"
        func.tags = ("x",)
        state = func.__getstate__()
        loaded = pickle.loads(pickle.dumps(func))
        assert _core_fields(loaded) | {"calling_convention": None} == _core_fields(func) | {"calling_convention": None}
        assert loaded.tags == ("x",)
        assert loaded._graph is not func._graph
        # a state pickled before the core moved to Rust (flags may be None there)
        state["_is_alignment"] = None
        old = Function.__new__(Function)
        old.__setstate__(state)
        assert old.is_alignment is False
        assert old.name == "main2" and old.previous_names == ["main"]


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""Function's lazily created Python containers (prototype maps, info, argument lists, node objects)."""

from __future__ import annotations

import os
import pickle
import unittest

import angr
from angr.enums import Flavors
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.functions.function import FunctionInfo, PrototypeSource
from angr.knowledge_plugins.functions.function_parser import FunctionParser
from angr.sim_type import SimTypeFunction, SimTypeInt
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")
LAZY = (
    "_prototypes",
    "_prototype_sources",
    "_prototypes_resolved",
    "_prototype_ref_warned",
    "_info",
    "_node_objs",
    "_argument_registers",
    "_argument_stack_variables",
)
C = Flavors.DEFAULT_FLAVOR


def _proto(n: int) -> SimTypeFunction:
    return SimTypeFunction([SimTypeInt()] * n, SimTypeInt(), arg_names=[f"p{i}" for i in range(n)])


class TestFunctionLazySlots(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(FAUXWARE, auto_load_libs=False)

    def _func(self, addr=0x400580) -> Function:
        return Function(self.proj.kb.functions, addr, syscall=False)

    def test_fresh_function_creates_nothing(self):
        func = self._func()
        for slot in LAZY:
            assert getattr(func, slot) is None, slot
        assert func.prototype is None
        assert func.prototype_source == PrototypeSource.NONE
        assert func.get_prototype("rust") is None
        assert func.get_prototype_source("rust") == PrototypeSource.NONE
        assert func.prototypes == {C: None}
        assert func.prototype_sources == {C: PrototypeSource.NONE}
        assert not func.has_prototype_for_flavor("rust")
        assert func.uses_default_prototype_for("rust")
        assert func.num_arguments == 0
        assert func.arguments == []
        assert func._info_data() == {}
        # reads leave the containers alone
        assert func._prototypes is None and func._info is None
        # setting the default source to NONE is a no-op
        func.prototype_source = PrototypeSource.NONE
        assert func._prototypes is None

    def test_prototypes_per_flavor(self):
        func = self._func()
        func.set_prototype("rust", _proto(1), PrototypeSource.USER)
        assert func.prototypes == {C: None, "rust": _proto(1)}
        assert func.get_prototype_source("rust") == PrototypeSource.USER
        assert func.prototype_source == PrototypeSource.NONE
        func.prototype = _proto(2)
        func.prototype_source = PrototypeSource.SIMPROC
        assert func.get_prototype("go") == _proto(2)
        assert func.get_prototype_source("go") == PrototypeSource.SIMPROC
        # a new flavor's source starts from C's
        func.set_prototype("go", _proto(3))
        assert func.get_prototype_source("go") == PrototypeSource.SIMPROC
        func.clear_prototype("go")
        assert not func.has_prototype_for_flavor("go")
        func.clear_prototype(C)
        assert func.prototype is None and func.prototype_source == PrototypeSource.NONE
        assert func.get_prototype("rust") == _proto(1)
        # set_prototype_source on a flavor without an entry copies C's prototype
        func2 = self._func(0x400600)
        func2.prototype = _proto(1)
        func2.set_prototype_source("rust", PrototypeSource.USER)
        assert func2.get_prototype("rust") == _proto(1)
        assert func2.get_prototype_source("rust") == PrototypeSource.USER
        assert func2.prototype_source == PrototypeSource.NONE
        # prototype_libname resets the resolved flags
        func2._prototypes_resolved = {C}
        func2.prototype_libname = "libc.so.6"
        assert func2._prototypes_resolved is None

    def test_info(self):
        fm = self.proj.kb.functions
        func = fm.function(0x400580, create=True)
        assert func is not None
        func._dirty = False
        info = func.info
        assert isinstance(info, FunctionInfo) and func.info is info
        assert not func.dirty
        info["gp"] = 1
        assert func.dirty and func._info_data() == {"gp": 1}
        func._dirty = False
        del info["gp"]
        assert func.dirty
        func.info = {"is_alloca_probe": True}
        assert 0x400580 in fm.get_key_func_addrs("alloca_probe")
        assert func.info.data == {"is_alloca_probe": True}

    def test_arguments(self):
        func = self._func()
        func._add_argument_stack_variable(8)
        func._add_argument_stack_variable(8)
        assert func._argument_stack_variables == [8]
        assert func._argument_registers is None
        assert func.num_arguments == 1

    def test_pickle_state_is_materialized(self):
        func = self._func()
        state = func.__getstate__()
        assert state["_prototypes"] == {C: None}
        assert state["_prototype_sources"] == {C: PrototypeSource.NONE}
        assert state["_prototypes_resolved"] == set() and state["_prototype_ref_warned"] == set()
        assert state["_argument_registers"] == [] and state["_argument_stack_variables"] == []
        assert isinstance(state["_info"], FunctionInfo) and not state["_info"]
        assert state["_node_objs"] == {}
        # getstate does not create the containers on the function itself
        assert func._prototypes is None and func._info is None
        func2 = pickle.loads(pickle.dumps(func))
        assert func2.prototypes == {C: None}
        assert func2.info.data == {}
        func2.prototype = _proto(1)
        assert func2.prototype == _proto(1)

        func.set_prototype("rust", _proto(2), PrototypeSource.USER)
        func.info["gp"] = 3
        func3 = pickle.loads(pickle.dumps(func))
        assert func3.prototypes == {C: None, "rust": _proto(2)}
        assert func3.get_prototype_source("rust") == PrototypeSource.USER
        assert func3.info.data == {"gp": 3}

    def test_copy(self):
        func = self._func()
        func2 = func.copy()
        for slot in ("_prototypes", "_prototype_sources", "_prototypes_resolved", "_info"):
            assert getattr(func2, slot) is None, slot
        func.set_prototype("rust", _proto(1))
        func.info["gp"] = 1
        func3 = func.copy()
        assert func3.prototypes == func.prototypes
        assert func3.info.data == {"gp": 1} and func3.info is not func.info
        assert func3.info._func is func3

    def test_protobuf_round_trip(self):
        for populate in (False, True):
            func = self._func()
            if populate:
                func.set_prototype("rust", _proto(1), PrototypeSource.USER)
                func.info["gp"] = 7
            cmsg = FunctionParser.serialize(func)
            blob = cmsg.SerializeToString()
            func2 = FunctionParser.parse_from_cmsg(cmsg, function_manager=self.proj.kb.functions, project=self.proj)
            assert FunctionParser.serialize(func2).SerializeToString() == blob
            assert func2.prototypes == func.prototypes
            assert func2._info_data() == func._info_data()
            if not populate:
                assert func2._info is None and func2._prototypes is None


if __name__ == "__main__":
    unittest.main()

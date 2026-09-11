#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.knowledge_plugins.functions.function import Function
from angr.procedures import SIM_LIBRARIES
from angr.sim_type import SimStruct, SimTypeFunction, SimTypePointer, SimTypeRef
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

DIRENT_FIELDS = ["d_ino", "d_reclen", "d_type", "d_namelen", "d_name"]


class TestFunctionParserPrototype(unittest.TestCase):
    @staticmethod
    def _function_with_prototype(proj: angr.Project, libname: str, name: str, deref: bool = False) -> Function:
        func = proj.kb.functions.function(addr=proj.entry, create=True)
        assert func is not None
        prototype = SIM_LIBRARIES[libname][0].get_prototype(name, arch=proj.arch, deref=deref)
        assert prototype is not None
        func.prototype = prototype
        func.prototype_libname = libname
        return func

    @staticmethod
    def _round_trip(proj: angr.Project, func: Function) -> SimTypeFunction:
        cmsg = func.serialize_to_cmessage()
        loaded = Function.parse_from_cmessage(cmsg, function_manager=proj.kb.functions, project=proj)
        assert isinstance(loaded.prototype, SimTypeFunction)
        return loaded.prototype

    def test_struct_that_no_type_collection_holds_survives_serialization(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        func = self._function_with_prototype(proj, "libc.so.6", "readdir")

        before = func.prototype
        assert isinstance(before, SimTypeFunction)
        assert isinstance(before.returnty, SimTypePointer)
        assert isinstance(before.returnty.pts_to, SimStruct)
        assert list(before.returnty.pts_to.fields) == DIRENT_FIELDS

        after = self._round_trip(proj, func)
        assert isinstance(after.returnty, SimTypePointer)
        assert isinstance(after.returnty.pts_to, SimStruct)
        assert list(after.returnty.pts_to.fields) == DIRENT_FIELDS

    def test_struct_that_a_type_collection_holds_becomes_a_reference(self):
        angr.procedures.definitions.load_win32api_definitions()
        proj = angr.Project(os.path.join(test_location, "x86_64", "windows", "sioctl.sys"), auto_load_libs=False)
        func = self._function_with_prototype(proj, "iphlpapi.dll", "GetInterfaceDnsSettings", deref=True)

        before = func.prototype
        assert isinstance(before, SimTypeFunction)
        assert isinstance(before.args[0], SimStruct)
        assert before.args[0].name == "Guid"

        after = self._round_trip(proj, func)
        assert isinstance(after.args[0], SimTypeRef)
        assert after.args[0].name == "Guid"


if __name__ == "__main__":
    unittest.main()

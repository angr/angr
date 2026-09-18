#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import json
import os
import unittest

import angr
from angr.knowledge_plugins.functions.function import Function
from angr.procedures import SIM_LIBRARIES
from angr.procedures.definitions import SIM_TYPE_COLLECTIONS
from angr.sim_type import SimStruct, SimType, SimTypeFunction, SimTypePointer, SimTypeRef, SimUnion
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
    def _round_trip(proj: angr.Project, func: Function) -> tuple[SimTypeFunction, SimTypeFunction]:
        """
        Serialize the function and load it back. Returns the prototype as it was stored, and the prototype the loaded
        function reads back (which Function.prototype dereferences against the loaded type collections).
        """
        cmsg = func.serialize_to_cmessage()
        stored = SimType.from_json(json.loads(cmsg.prototype.decode("utf-8")))
        assert isinstance(stored, SimTypeFunction)
        loaded = Function.parse_from_cmessage(cmsg, function_manager=proj.kb.functions, project=proj)
        assert isinstance(loaded.prototype, SimTypeFunction)
        return stored, loaded.prototype

    @staticmethod
    def _anonymous_struct(prototype: SimTypeFunction) -> SimStruct | SimTypeRef:
        # CMTranslateColors(HANDLE, COLOR*, ...): COLOR is a union whose "Anonymous" member is an inline struct that the
        # win32 generator names _Anonymous_e__Struct, like every other inline anonymous struct
        arg = prototype.args[1]
        assert isinstance(arg, SimTypePointer)
        assert isinstance(arg.pts_to, SimUnion)
        member = arg.pts_to.members["Anonymous"]
        assert isinstance(member, (SimStruct, SimTypeRef))
        return member

    def test_struct_that_no_type_collection_holds_is_stored_in_full(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        func = self._function_with_prototype(proj, "libc.so.6", "readdir")

        before = func.prototype
        assert isinstance(before, SimTypeFunction)
        assert isinstance(before.returnty, SimTypePointer)
        assert isinstance(before.returnty.pts_to, SimStruct)
        assert list(before.returnty.pts_to.fields) == DIRENT_FIELDS

        stored, after = self._round_trip(proj, func)
        for prototype in (stored, after):
            assert isinstance(prototype.returnty, SimTypePointer)
            assert isinstance(prototype.returnty.pts_to, SimStruct)
            assert list(prototype.returnty.pts_to.fields) == DIRENT_FIELDS

    def test_struct_that_a_type_collection_defines_the_same_way_is_stored_as_a_reference(self):
        angr.procedures.definitions.load_win32api_definitions()
        proj = angr.Project(os.path.join(test_location, "x86_64", "windows", "sioctl.sys"), auto_load_libs=False)
        func = self._function_with_prototype(proj, "iphlpapi.dll", "GetInterfaceDnsSettings", deref=True)

        before = func.prototype
        assert isinstance(before, SimTypeFunction)
        assert isinstance(before.args[0], SimStruct)
        assert before.args[0].name == "Guid"

        stored, after = self._round_trip(proj, func)
        assert isinstance(stored.args[0], SimTypeRef)
        assert stored.args[0].name == "Guid"
        assert isinstance(after.args[0], SimStruct)
        assert after.args[0] == before.args[0]

    def test_struct_that_only_shares_its_name_with_a_definition_is_stored_in_full(self):
        angr.procedures.definitions.load_win32api_definitions()
        proj = angr.Project(os.path.join(test_location, "x86_64", "windows", "sioctl.sys"), auto_load_libs=False)
        func = self._function_with_prototype(proj, "icm32.dll", "CMTranslateColors", deref=True)

        before = func.prototype
        assert isinstance(before, SimTypeFunction)
        inline = self._anonymous_struct(before)
        assert isinstance(inline, SimStruct)
        assert inline.name == "_Anonymous_e__Struct"
        assert list(inline.fields) == ["reserved1", "reserved2"]
        # the collection's definition of that name is a different struct
        defined = SIM_TYPE_COLLECTIONS["win32"].get("_Anonymous_e__Struct")
        assert isinstance(defined, SimStruct)
        assert list(defined.fields) != list(inline.fields)

        stored, after = self._round_trip(proj, func)
        for prototype in (stored, after):
            struct = self._anonymous_struct(prototype)
            assert isinstance(struct, SimStruct)
            assert list(struct.fields) == ["reserved1", "reserved2"]


if __name__ == "__main__":
    unittest.main()

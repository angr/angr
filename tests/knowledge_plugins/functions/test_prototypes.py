#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
import angr.calling_conventions
from angr.calling_conventions import SimRegArg
from angr.sim_type import SimTypePointer, SimTypeRef
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestPrototypes(unittest.TestCase):
    def test_function_prototype(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)

        func = angr.knowledge_plugins.Function(proj.kb.functions, 0x100000, name="strcmp")
        func.prototype = angr.SIM_LIBRARIES["libc.so.6"][0].prototypes[func.name]
        func.calling_convention = angr.calling_conventions.default_cc(proj.arch.name, platform="Linux")(proj.arch)

    def test_find_prototype(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)

        cfg = proj.analyses.CFG()

        func = cfg.kb.functions.function(name="strcmp", plt=False)
        func.calling_convention = angr.calling_conventions.default_cc(proj.arch.name, platform="Linux")(proj.arch)

        func.find_declaration()

        arg_locs = func.calling_convention.arg_locs(func.prototype)

        assert len(arg_locs) == 2
        assert arg_locs[0].reg_name == "rdi"
        assert arg_locs[1].reg_name == "rsi"

    def test_arguments_resolve_library_type_references(self):
        # RtlAnsiStringToUnicodeString's third argument is BOOLEAN, which ntdll.dll ships as a type reference with no
        # size of its own. Function.arguments must resolve it before placing it, or the one-byte argument is placed as
        # a whole machine word.
        proj = angr.Project(os.path.join(test_location, "x86_64", "netfilter_b64.sys"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=False, analyze_callsites=True)

        func = cfg.kb.functions.function(name="RtlAnsiStringToUnicodeString")
        assert func is not None
        assert func.prototype is not None
        assert func.prototype_libname == "ntdll.dll"
        assert isinstance(func.prototype.args[2], SimTypeRef)
        assert func.prototype.args[2].size is None

        arg_locs = func.arguments
        assert [loc.reg_name for loc in arg_locs if isinstance(loc, SimRegArg)] == ["rcx", "rdx", "r8"]
        assert [loc.size for loc in arg_locs] == [8, 8, 1]

    def test_cpp_void_pointer(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "void_pointer"), auto_load_libs=False)

        cfg = proj.analyses.CFG()
        proj.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)

        func = cfg.kb.functions.function(name="_ZdlPvm", plt=True)
        assert isinstance(func.prototype.args[0], SimTypePointer)


if __name__ == "__main__":
    unittest.main()

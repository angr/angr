#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Tests for functions that pass or return a C++ class the binary never defines.

A demangled C++ declaration names classes the binary does not define. Those become a
SimCppClass with a size and no members, and the calling convention has to give them a
location anyway.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.decompiler.decompiler import Decompiler
from angr.calling_conventions import SimRegArg
from angr.sim_type import SimCppClass
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestOpaqueClassLocations(unittest.TestCase):
    def test_opaque_class_return_value_has_a_location(self):
        # Concurrency::location::current() is an MSVC-mangled method returning a class msvcr120.dll
        # does not define.
        bin_path = os.path.join(test_location, "x86_64", "windows", "msvcr120.dll")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            force_smart_scan=False, normalize=True, regions=[(0x180009AF8, 0x180009AF8 + 0x200)]
        )
        proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model)

        func = proj.kb.functions[0x180009AF8]
        prototype = func.prototype
        cc = func.calling_convention
        assert prototype is not None and cc is not None
        returnty = prototype.returnty
        assert isinstance(returnty, SimCppClass)
        assert not returnty.fields and returnty.size

        ret_loc = cc.return_val(returnty)
        assert isinstance(ret_loc, SimRegArg), f"Unexpected return location: {ret_loc}"
        assert ret_loc.reg_name == "rax"
        assert ret_loc.size == returnty.size // proj.arch.byte_width

        d = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert d.codegen is not None and d.codegen.text is not None
        print_decompilation_result(d)
        # the prototype does not return void, so a bare return statement drops the returned value
        assert "return;" not in d.codegen.text

    def test_opaque_class_arguments_have_locations(self):
        # plouf(std::string, std::string) takes two classes this binary does not define
        bin_path = os.path.join(test_location, "i386", "cpp_regression_test_ch25")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model)

        func = next(
            f
            for f in cfg.functions.values()
            if f.demangled_name is not None and f.demangled_name.startswith("plouf(") and not f.is_plt
        )
        prototype = func.prototype
        cc = func.calling_convention
        assert prototype is not None and cc is not None
        assert all(isinstance(arg, SimCppClass) and not arg.fields and arg.size for arg in prototype.args)

        arg_locs = list(cc.arg_locs(prototype.with_arch(proj.arch)))
        assert len(arg_locs) == 2
        assert all(loc.size == 4 for loc in arg_locs), f"Unexpected argument locations: {arg_locs}"

        d = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert d.codegen is not None and d.codegen.text is not None
        print_decompilation_result(d)
        # both arguments are declared, so neither may be dropped from the signature
        assert "void plouf()" not in d.codegen.text


if __name__ == "__main__":
    unittest.main()

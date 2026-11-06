#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.sim_type import SimTypeFunction, SimTypeInt
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestWdkDefinitions(unittest.TestCase):
    def test_fwpkclnt_imports_get_kernel_declarations(self):
        # a kernel driver importing the WFP management functions from fwpkclnt.sys
        driver = os.path.join(
            test_location,
            "x86_64",
            "windows",
            "9c75d43ec531c76caa65de86dcac0269d6727ba4ec74fe1cac1fda0e176fd2ab",
        )
        proj = angr.Project(driver, auto_load_libs=False)

        export = proj.loader.main_object.imports["FwpmEngineOpen0"].resolvedby
        assert export is not None
        hook = proj.hooked_by(export.rebased_addr)
        assert hook is not None
        assert hook.library_name == "fwpkclnt.sys"
        assert not hook.guessed_prototype
        # NTSTATUS
        assert isinstance(hook.prototype, SimTypeFunction)
        assert isinstance(hook.prototype.returnty, SimTypeInt)
        assert hook.prototype.returnty.signed

        # user-mode callers keep the DWORD declarations of fwpuclnt.dll
        for lib in angr.SIM_LIBRARIES["fwpuclnt.dll"]:
            proto = lib.get_prototype("FwpmEngineOpen0", deref=True)
            assert proto is not None
            assert isinstance(proto.returnty, SimTypeInt)
            assert not proto.returnty.signed


if __name__ == "__main__":
    unittest.main()

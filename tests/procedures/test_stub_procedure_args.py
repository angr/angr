#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.calling_conventions import SimCCStdcall, SimStackArg
from angr.engines.successors import SimSuccessors
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeInt, SimTypePointer
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestStubProcedureArgs(unittest.TestCase):
    def test_stub_procedure_args(self):
        # stub procedures should have the right number of arguments

        angr.procedures.definitions.load_win32api_definitions()

        lib = angr.SIM_LIBRARIES["user32.dll"][0]
        lib.set_prototype(
            "____a_random_stdcall_function__",
            SimTypeFunction(
                [SimTypeInt(signed=True), SimTypeInt(signed=True), SimTypeInt(signed=False)],
                SimTypePointer(SimTypeChar(), offset=0),
                arg_names=["_random_arg_0", "_random_arg_1", "_random_arg_2"],
            ),
        )
        stub = lib.get_stub("____a_random_stdcall_function__", archinfo.ArchX86())
        stub.cc = SimCCStdcall(archinfo.ArchX86())
        lib._apply_metadata(stub, archinfo.ArchX86())
        assert len(stub.prototype.args) == 3
        assert all(isinstance(arg, SimStackArg) for arg in stub.cc.arg_locs(stub.prototype))

        proj = angr.Project(os.path.join(test_location, "i386", "all"), auto_load_libs=False)
        state = proj.factory.blank_state()

        initial_sp = state.regs.sp
        stub.state = state
        stub.successors = SimSuccessors(0, state)
        stub.ret(0)

        succ = stub.successors.all_successors[0]
        assert state.solver.eval_one(succ.regs.sp - initial_sp) == 0x10

    def test_libstdcxx_stub_wchar_t_is_32_bits(self):
        # std::ctype<wchar_t>::do_toupper(wchar_t) const
        lib = angr.SIM_LIBRARIES["libstdc++.so"][0]
        for arch, signed in (
            (archinfo.ArchAMD64(), True),
            (archinfo.ArchX86(), True),
            (archinfo.ArchARMHF(), False),
            (archinfo.ArchAArch64(), False),
        ):
            prototype = lib.get_stub("_ZNKSt5ctypeIwE10do_toupperEw", arch).prototype
            assert isinstance(prototype, SimTypeFunction)
            wchar_t = prototype.args[1]
            assert isinstance(wchar_t, SimTypeInt)
            assert wchar_t.size == 32
            assert wchar_t.signed is signed

    def test_glibc_wchar_t_follows_the_target(self):
        # wchar_t* wmemchr(const wchar_t* BLOCK, wchar_t WC, size_t SIZE)
        lib = angr.SIM_LIBRARIES["libc.so.6"][0]
        for arch, os_name, bits, signed in (
            (archinfo.ArchAMD64(), None, 32, True),
            (archinfo.ArchARMHF(), None, 32, False),
            (archinfo.ArchAMD64(), "Win32", 16, True),
        ):
            prototype = lib.get_prototype("wmemchr", arch=arch, os_name=os_name)
            assert prototype is not None
            block, found = prototype.args[0], prototype.returnty
            assert isinstance(block, SimTypePointer)
            assert isinstance(found, SimTypePointer)
            for wchar_t in (block.pts_to, prototype.args[1], found.pts_to):
                assert isinstance(wchar_t, SimTypeInt)
                assert wchar_t.size == bits
                assert wchar_t.signed is signed


if __name__ == "__main__":
    unittest.main()

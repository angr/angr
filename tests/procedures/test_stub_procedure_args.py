#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.procedures.definitions.win32_user32 import lib
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeChar
from angr.engines.successors import SimSuccessors
from angr.calling_conventions import SimCCStdcall, SimStackArg

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestStubProcedureArgs(unittest.TestCase):
    def test_stub_procedure_args(self):
        # stub procedures should have the right number of arguments

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


if __name__ == "__main__":
    unittest.main()

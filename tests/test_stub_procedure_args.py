import os

import archinfo

import angr
from angr.procedures.definitions.user32 import lib
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeChar
from angr.engines.successors import SimSuccessors
from angr.calling_conventions import SimCCStdcall, SimStackArg

binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_stub_procedure_args():
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

    proj = angr.Project(os.path.join(binaries_base, "i386", "all"), auto_load_libs=False)
    state = proj.factory.blank_state()

    initial_sp = state.regs.sp
    stub.state = state
    stub.successors = SimSuccessors(0, state)
    stub.ret(0)

    succ = stub.successors.all_successors[0]
    assert state.solver.eval_one(succ.regs.sp - initial_sp) == 0x10


if __name__ == "__main__":
    test_stub_procedure_args()

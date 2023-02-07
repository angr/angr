import angr

import logging

l = logging.getLogger("angr.tests")

import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

arches = {"mips", "mipsel", "mips64", "x86_64", "ppc", "ppc64"}


def run_test_syscalls(arch):
    # import ipdb; ipdb.set_trace()
    p = angr.Project(os.path.join(test_location, arch, "test_ioctl"), exclude_sim_procedures_list=["ioctl"])
    p.simos.syscall_library.procedures.pop("ioctl", None)

    s = p.factory.entry_state()

    simgr = p.factory.simulation_manager(thing=s)
    simgr.run()
    assert len(simgr.deadended) == 2, "for these architectures, libc checks if the bit is set. make sure it branches"


if __name__ == "__main__":
    for arch in arches:
        run_test_syscalls(arch)

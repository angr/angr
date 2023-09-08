# pylint: disable=missing-class-docstring,no-self-use,line-too-long

import os
import unittest

import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

arches = {"mips", "mipsel", "mips64", "x86_64", "ppc", "ppc64"}


class TestSyscallResult(unittest.TestCase):
    @staticmethod
    def run_test_syscalls(arch):
        p = angr.Project(os.path.join(test_location, arch, "test_ioctl"), exclude_sim_procedures_list=["ioctl"])
        p.simos.syscall_library.procedures.pop("ioctl", None)

        s = p.factory.entry_state()

        simgr = p.factory.simulation_manager(thing=s)
        simgr.run()
        assert (
            len(simgr.deadended) == 2
        ), "for these architectures, libc checks if the bit is set. make sure it branches"

    def test_syscalls(self):
        for arch in arches:
            with self.subTest(arch=arch):
                self.run_test_syscalls(arch)


if __name__ == "__main__":
    unittest.main()

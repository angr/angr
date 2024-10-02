#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.sim.exec_func"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")

arches = {"mips", "mipsel", "mips64", "x86_64", "ppc", "ppc64"}


class TestSyscallResult(unittest.TestCase):
    @staticmethod
    def run_test_syscalls(binary):
        p = angr.Project(binary, exclude_sim_procedures_list=["ioctl"])
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
                if arch == "x86_64":
                    # x86_64/libc.so.6 does not work, we use a newer version here
                    binary = os.path.join(test_location, arch, "ioctl", "test_ioctl")
                else:
                    binary = os.path.join(test_location, arch, "test_ioctl")
                self.run_test_syscalls(binary)


if __name__ == "__main__":
    unittest.main()

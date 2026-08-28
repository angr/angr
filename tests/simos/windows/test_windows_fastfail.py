#!/usr/bin/env python3
# pylint: disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.simos.windows"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.calling_conventions import (
    SimCCAArch64WindowsSyscall,
    SimCCAMD64WindowsSyscall,
    SimCCARMWindowsSyscall,
    SimCCX86WindowsSyscall,
)
from angr.simos import SimWindows
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestWindowsFastfail(unittest.TestCase):
    """
    Tests for the __fastfail handler SimWindows installs.
    """

    def test_fastfail_on_a_real_windows_arm_binary(self):
        # The convention has to be reachable from a real PE, not only from load_shellcode: cle sets os="windows"
        # for every PE, so SimWindows is selected from the file's own machine type rather than from an argument.
        for path, expected_cc in (
            (os.path.join("aarch64", "windows", "fastfail_arm64.exe"), SimCCAArch64WindowsSyscall),
            (os.path.join("armel", "windows", "fastfail_armnt.exe"), SimCCARMWindowsSyscall),
        ):
            with self.subTest(path=path):
                project = angr.Project(os.path.join(test_location, path), auto_load_libs=False)
                assert isinstance(project.simos, SimWindows)
                assert isinstance(project.simos.fastfail.cc, expected_cc)

    def test_fastfail_runs_on_a_real_windows_arm_binary(self):
        # Selecting the convention is not the same as being able to use it. Run the handler on both images, which
        # covers ARMNT end to end -- the shellcode test above only executes the AArch64 one.
        for path in (
            os.path.join("aarch64", "windows", "fastfail_arm64.exe"),
            os.path.join("armel", "windows", "fastfail_armnt.exe"),
        ):
            with self.subTest(path=path):
                project = angr.Project(os.path.join(test_location, path), auto_load_libs=False)
                assert isinstance(project.simos, SimWindows)
                simgr = project.factory.simulation_manager(project.factory.call_state(project.simos.fastfail.addr, 0))
                simgr.run()

                assert len(simgr.deadended) == 1
                state = simgr.deadended[0]
                assert state.history.jumpkind == "Ijk_Exit"
                terminations = [event for event in state.history.events if event.type == "terminate"]
                assert len(terminations) == 1
                assert state.solver.eval_one(terminations[0].objects["exit_code"]) == 0xC0000409

    def test_fastfail_uses_the_windows_syscall_convention(self):
        # Windows runs on ARM and AArch64 too, so every architecture that has __fastfail has a Windows syscall
        # convention for its handler.
        for arch, expected_cc in (
            ("x86", SimCCX86WindowsSyscall),
            ("amd64", SimCCAMD64WindowsSyscall),
            ("armel", SimCCARMWindowsSyscall),
            ("armhf", SimCCARMWindowsSyscall),
            ("aarch64", SimCCAArch64WindowsSyscall),
        ):
            with self.subTest(arch=arch):
                project = angr.load_shellcode(b"\x00" * 4, arch=arch, simos="windows")
                assert isinstance(project.simos, SimWindows)
                assert isinstance(project.simos.fastfail.cc, expected_cc)

    def test_arm_syscall_number_comes_from_r12(self):
        # A Windows ARM stub loads the service index into r12 and traps with svc #1, where Linux uses r7.
        project = angr.load_shellcode(b"\x01\x00\x00\xef", arch="armel", simos="windows")  # svc #1
        state = project.factory.blank_state()
        state.regs.ip_at_syscall = project.entry + 4
        state.regs.r7 = 0x11
        state.regs.r12 = 0x22
        assert state.solver.eval_one(SimCCARMWindowsSyscall(project.arch).syscall_num(state)) == 0x22

    def test_aarch64_syscall_number_comes_from_the_svc_immediate(self):
        # A Windows AArch64 stub carries the service index in the SVC immediate itself, so no register holds it.
        project = angr.load_shellcode(b"\xe1\x00\x00\xd4", arch="aarch64", simos="windows")  # svc #7
        state = project.factory.blank_state()
        state.regs.ip_at_syscall = project.entry + 4
        state.regs.x8 = 0x33
        assert state.solver.eval_one(SimCCAArch64WindowsSyscall(project.arch).syscall_num(state)) == 7

    def test_fastfail_terminates_state_on_aarch64(self):
        # The convention installed on AArch64 must be usable, not just present.
        project = angr.load_shellcode(b"\x00" * 4, arch="aarch64", simos="windows")
        assert isinstance(project.simos, SimWindows)
        simgr = project.factory.simulation_manager(project.factory.call_state(project.simos.fastfail.addr, 0))
        simgr.run()

        assert len(simgr.deadended) == 1
        state = simgr.deadended[0]
        assert state.history.jumpkind == "Ijk_Exit"
        terminations = [event for event in state.history.events if event.type == "terminate"]
        assert len(terminations) == 1
        assert state.solver.eval_one(terminations[0].objects["exit_code"]) == 0xC0000409


if __name__ == "__main__":
    unittest.main()

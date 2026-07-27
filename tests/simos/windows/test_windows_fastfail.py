#!/usr/bin/env python3
# pylint: disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.simos.windows"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.calling_conventions import (
    SimCCAArch64WindowsSyscall,
    SimCCAMD64WindowsSyscall,
    SimCCARMWindowsSyscall,
    SimCCRISCV64,
    SimCCX86WindowsSyscall,
)
from angr.simos import SimWindows


class TestWindowsFastfail(unittest.TestCase):
    """
    Tests for the __fastfail handler SimWindows installs.
    """

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

    def test_fastfail_falls_back_where_windows_has_no_syscall_convention(self):
        # cle labels every PE os="windows", so a machine type Windows has no syscall ABI for still reaches
        # SimWindows. RISC-V PEs are real -- UEFI ships them -- and building the project must still work.
        project = angr.load_shellcode(b"\x00" * 4, arch="riscv64", simos="windows")
        assert isinstance(project.simos, SimWindows)
        assert isinstance(project.simos.fastfail.cc, SimCCRISCV64)

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

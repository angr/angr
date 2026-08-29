#!/usr/bin/env python3
# pylint: disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.simos"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.calling_conventions import (
    SimCCAArch64,
    SimCCMicrosoftAMD64,
    SimCCMicrosoftCdecl,
    SimCCRISCV64,
    default_cc,
)
from angr.simos import SimUefi
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# angr's own CI checks out angr/binaries at master, so this fixture is absent until its pull request merges.
riscv64_uefi_image = os.path.join(test_location, "riscv64", "uefi", "HighMemDxe.efi")


class TestUefi(unittest.TestCase):
    """
    Tests for the UEFI environment.
    """

    @unittest.skipUnless(os.path.exists(riscv64_uefi_image), "needs the RISC-V UEFI fixture from angr/binaries")
    def test_riscv64_image_does_not_become_windows(self):
        # A UEFI module is a PE, and until cle told them apart every PE became a Windows binary. Windows has never
        # run on RISC-V, so SimWindows reached for a Win32 syscall convention RISCV64 has no reason to have and
        # raised KeyError: 'Win32' before the project was built.
        project = angr.Project(riscv64_uefi_image, auto_load_libs=False)
        assert project.arch.name == "RISCV64"
        assert isinstance(project.simos, SimUefi)
        assert project.simos.name == "UEFI"
        # the RISC-V binding of the UEFI specification is the architecture's ordinary convention
        assert isinstance(project.factory.cc(), SimCCRISCV64)

    def test_ia32_image_uses_the_microsoft_convention(self):
        # A Terse Executable only ever holds a UEFI module. The IA-32 binding of the UEFI specification is the C
        # calling convention as the Microsoft toolchains implement it, not the System V one.
        project = angr.Project(os.path.join(test_location, "i386", "te_sections.te"), auto_load_libs=False)
        assert isinstance(project.simos, SimUefi)
        assert isinstance(project.factory.cc(), SimCCMicrosoftCdecl)

    def test_aarch64_image_uses_the_architecture_default(self):
        # Only the x86 bindings depart from the architecture's ordinary convention; AArch64 UEFI is AAPCS64.
        project = angr.Project(os.path.join(test_location, "aarch64", "te_sections.te"), auto_load_libs=False)
        assert isinstance(project.simos, SimUefi)
        assert isinstance(project.factory.cc(), SimCCAArch64)

    def test_x64_binding_is_the_microsoft_convention(self):
        # The X64 binding is the Microsoft x64 calling convention. angr/binaries carries no X64 UEFI image, so this
        # asserts the table entry the environment reads rather than building a project.
        assert default_cc("AMD64", platform="UEFI") is SimCCMicrosoftAMD64


if __name__ == "__main__":
    unittest.main()

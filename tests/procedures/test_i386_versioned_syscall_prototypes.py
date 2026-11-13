#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import unittest

import archinfo

from angr.calling_conventions import SimCCX86LinuxSyscall
from angr.procedures.definitions import SIM_LIBRARIES, SimSyscallLibrary, linux_kernel

# Linux v5.4 arch/x86/entry/syscalls/syscall_32.tbl: number, userspace name, kernel entry point.
I386_VERSIONED_SYSCALLS = {
    22: ("umount", "oldumount"),
    52: ("umount2", "umount"),
    106: ("stat", "newstat"),
    107: ("lstat", "newlstat"),
    108: ("fstat", "newfstat"),
    122: ("uname", "newuname"),
}


class TestI386VersionedSyscallPrototypes(unittest.TestCase):
    def test_versioned_syscalls_use_their_kernel_entry_point_declarations(self):
        lib = SIM_LIBRARIES["linux"][0]
        assert isinstance(lib, SimSyscallLibrary)
        arch = archinfo.arch_from_id("x86")

        for number, (wrapper_name, declaration_name) in I386_VERSIONED_SYSCALLS.items():
            assert lib.syscall_number_mapping["i386"][number] == wrapper_name

            expected = linux_kernel._base_syscall_decls[declaration_name].with_arch(arch)

            proc = lib.get(number, arch, ["i386"])
            assert proc.display_name == wrapper_name
            assert not proc.guessed_prototype
            assert proc.prototype == expected
            assert isinstance(proc.cc, SimCCX86LinuxSyscall)
            assert lib.syscall_prototype_mapping["i386"][number] == declaration_name


if __name__ == "__main__":
    unittest.main()

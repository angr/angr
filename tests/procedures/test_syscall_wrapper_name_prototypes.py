#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import unittest

import archinfo

from angr.calling_conventions import SimCCX86LinuxSyscall
from angr.procedures.definitions import SIM_LIBRARIES, SimSyscallLibrary
from angr.sim_type import SimTypeFunction

# (userspace wrapper name, kernel declaration name, an abi that numbers the wrapper). Each pair
# is one syscall: arch/x86/entry/syscalls/syscall_32.tbl at torvalds/linux v5.4 gives
# "140 i386 _llseek sys_llseek", "149 i386 _sysctl sys_sysctl" and
# "89 i386 readdir sys_old_readdir".
WRAPPER_NAMES = [
    ("_llseek", "llseek", "i386"),
    ("_sysctl", "sysctl", "i386"),
    ("readdir", "old_readdir", "i386"),
]


class TestSyscallWrapperNamePrototypes(unittest.TestCase):
    """
    The kernel declaration tables are keyed by the kernel's own name for a syscall and the number
    tables name the userspace wrapper. Where the two spellings differ, the declaration used to be
    unreachable and the syscall arrived at the decompiler with no declaration of its own.
    """

    def _linux_syscall_library(self) -> SimSyscallLibrary:
        lib = SIM_LIBRARIES["linux"][0]
        assert isinstance(lib, SimSyscallLibrary)
        return lib

    def test_wrapper_name_carries_the_kernel_declaration(self):
        lib = self._linux_syscall_library()
        for wrapper, kernel, _ in WRAPPER_NAMES:
            for abi, mapping in lib.syscall_number_mapping.items():
                if wrapper not in mapping.values() or abi not in lib.syscall_prototypes:
                    continue
                assert lib.has_prototype(abi, wrapper), (abi, wrapper)
                under_wrapper = lib.get_prototype(abi, wrapper, deref=True)
                under_kernel = lib.get_prototype(abi, kernel, deref=True)
                assert under_wrapper is not None and under_kernel is not None, (abi, wrapper)
                assert list(under_wrapper.arg_names) == list(under_kernel.arg_names), (abi, wrapper)

    def test_kernel_names_are_still_registered(self):
        # Registering the wrapper name is additive; the kernel name keeps its declaration.
        lib = self._linux_syscall_library()
        for _, kernel, abi in WRAPPER_NAMES:
            assert lib.has_prototype(abi, kernel), (abi, kernel)
            assert lib.get_prototype(abi, kernel, deref=True) is not None, (abi, kernel)

    def test_llseek_resolves_to_the_five_argument_declaration(self):
        # i386 140 used to come back with guessed_prototype set, so a call site was laid out from
        # whatever the callsite analysis guessed instead of from this signature.
        lib = self._linux_syscall_library()
        proc = lib.get(140, archinfo.arch_from_id("x86"), ["i386"])
        assert proc.display_name == "_llseek"
        assert not proc.guessed_prototype
        assert isinstance(proc.prototype, SimTypeFunction)
        assert list(proc.prototype.arg_names) == ["fd", "offset_high", "offset_low", "result", "whence"]
        assert isinstance(proc.cc, SimCCX86LinuxSyscall)


if __name__ == "__main__":
    unittest.main()

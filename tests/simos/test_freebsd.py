#!/usr/bin/env python3
# pylint: disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.simos"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.procedures import SIM_LIBRARIES
from angr.procedures.definitions import SimSyscallLibrary
from angr.simos import SimFreeBSD, SimLinux
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# A FreeBSD/aarch64 executable: EI_OSABI is ELFOSABI_FREEBSD, so cle reports its OS
# without needing to read anything else.
freebsd_aarch64 = os.path.join(test_location, "dogbolt", "megatest-arm64-freebsd")

# A FreeBSD/i386 program that issues its syscalls the way FreeBSD takes them. angr's own CI
# checks out angr/binaries at master, so this fixture is absent until its pull request
# merges.
freebsd_i386 = os.path.join(test_location, "i386", "freebsd-syscalls-i386")


class TestFreeBSD(unittest.TestCase):
    """
    Tests for the FreeBSD environment.
    """

    def test_freebsd_elf_does_not_become_linux(self):
        # Every EI_OSABI value used to be registered for SimLinux, so a FreeBSD executable
        # was analysed with the Linux syscall table.
        project = angr.Project(freebsd_aarch64, auto_load_libs=False)
        assert project.loader.main_object.os == "UNIX - FreeBSD"
        assert isinstance(project.simos, SimFreeBSD)
        assert not isinstance(project.simos, SimLinux)
        assert project.simos.name == "FreeBSD"

    def test_native_numbering_is_not_the_linux_one(self):
        # The numbers the two tables spell the same way are the ones both systems
        # inherited from Research Unix: 3 read, 4 write, 5 open and 6 close are already in
        # V5's sysent.c, and 33 access arrives in V7. Above those the tables diverge, and
        # decoding one through the other renames the call. Numbers from sys/sys/syscall.h
        # at freebsd/freebsd-src release/14.0.0.
        arch = archinfo.arch_from_id("x86")
        freebsd = SIM_LIBRARIES["freebsd"][0]
        linux = SIM_LIBRARIES["linux"][0]
        assert isinstance(freebsd, SimSyscallLibrary)
        assert isinstance(linux, SimSyscallLibrary)
        expected = {
            3: ("read", "read"),
            4: ("write", "write"),
            5: ("open", "open"),
            6: ("close", "close"),
            33: ("access", "access"),
            59: ("execve", "oldolduname"),
            128: ("rename", "init_module"),
            272: ("getdents", "fadvise64_64"),
        }
        for number, (freebsd_name, linux_name) in expected.items():
            assert freebsd.get(number, arch, abi_list=["freebsd"]).display_name == freebsd_name
            assert linux.get(number, arch, abi_list=["i386"]).display_name == linux_name

    def test_one_abi_covers_every_architecture(self):
        # FreeBSD does not renumber its native syscalls per architecture, unlike Linux.
        library = SIM_LIBRARIES["freebsd"][0]
        assert isinstance(library, SimSyscallLibrary)
        for arch_name in ("x86", "amd64", "aarch64"):
            arch = archinfo.arch_from_id(arch_name)
            proc = library.get(59, arch, abi_list=["freebsd"])
            assert proc.display_name == "execve"
            assert proc.abi == "freebsd"

    @unittest.skipUnless(os.path.exists(freebsd_i386), "needs the FreeBSD i386 fixture from angr/binaries")
    def test_i386_syscalls_decode_with_freebsd_numbers_and_stack_arguments(self):
        # Reading this program through the Linux i386 table renames two of its calls --
        # 128 is init_module there and 272 is fadvise64_64 -- and reads every argument out
        # of ebx, ecx and edx, which FreeBSD never put anything in.
        project = angr.Project(freebsd_i386, auto_load_libs=False)
        assert isinstance(project.simos, SimFreeBSD)
        cfg = project.analyses.CFGFast(normalize=True)
        assert {f.name for f in cfg.functions.values() if f.is_syscall} == {
            "access",
            "close",
            "exit",
            "getdents",
            "open",
            "rename",
            "write",
        }

        decompilation = project.analyses.Decompiler(cfg.functions["_start"], cfg=cfg.model)
        assert decompilation.codegen is not None
        text = decompilation.codegen.text
        assert text is not None
        # The arguments the program pushed, in the order it pushed them.
        assert 'access("/COPYRIGHT", 0)' in text
        assert 'open("/", 0, 0)' in text
        assert 'write(1, "FreeBSD\\n", 8)' in text
        assert 'rename("/tmp/from", "/tmp/to")' in text
        assert "exit(0)" in text


if __name__ == "__main__":
    unittest.main()

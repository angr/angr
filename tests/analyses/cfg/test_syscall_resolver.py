#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from angr.analyses.cfg.indirect_jump_resolvers.syscall_resolver import SyscallResolver
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSyscallResolver(unittest.TestCase):
    def test_filter_accepts_syscalls_when_the_os_model_can_resolve_them(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        resolver = SyscallResolver(proj)

        assert resolver.filter(None, 0, 0, None, "Ijk_Sys_syscall") is True
        assert resolver.filter(None, 0, 0, None, "Ijk_Boring") is False

    def test_filter_rejects_syscalls_on_a_project_with_no_os_model(self):
        # A firmware blob gets the base SimOS, whose syscall() unconditionally returns None. Resolution can never
        # succeed, so the resolver must not symbolically execute the block to find that out.
        proj = angr.Project(
            os.path.join(test_location, "armel", "chall.bin"),
            main_opts={"backend": "blob", "arch": "ARMEL", "base_addr": 0},
            auto_load_libs=False,
        )
        assert proj.simos.syscall(proj.factory.blank_state()) is None

        resolver = SyscallResolver(proj)
        assert resolver.filter(None, 0, 0, None, "Ijk_Sys_syscall") is False


if __name__ == "__main__":
    unittest.main()

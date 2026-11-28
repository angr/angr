#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from angr.analyses.cfg.indirect_jump_resolvers.constant_value_manager import ConstantValueManager
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

    def test_resolves_a_syscall_number_set_in_a_predecessor_block(self):
        # 0x415990 sets x8 to 93 (exit) and branches to two blocks that end in `svc #0` without touching x8
        proj = angr.Project(os.path.join(test_location, "aarch64", "ld-linux-aarch64.so.1"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        func = cfg.kb.functions[0x415990]

        for site in (0x4159A4, 0x4159D4):
            syscall = proj.simos.syscall_from_addr(func.get_call_target(site))
            assert syscall is not None
            assert syscall.display_name == "exit"

    def test_syscall_return_register_is_unknown_after_the_syscall(self):
        # runtime.rtsigprocmask sets eax to 175 and executes `int 0x80`, which returns its result in eax
        proj = angr.Project(os.path.join(test_location, "i386", "go", "go1.27.1", "recv"), auto_load_libs=False)
        symbol = proj.loader.find_symbol("runtime.rtsigprocmask")
        assert symbol is not None
        func_addr = symbol.rebased_addr
        cfg = proj.analyses.CFGFast(
            function_starts=[func_addr],
            start_at_entry=False,
            symbols=False,
            function_prologues=False,
            force_smart_scan=False,
        )
        func = cfg.kb.functions[func_addr]
        syscall = proj.simos.syscall_from_addr(func.get_call_target(func_addr))
        assert syscall is not None
        assert syscall.display_name == "rt_sigprocmask"

        after_syscall = 0x80D5487
        entry = ConstantValueManager(proj, cfg.kb, func, after_syscall).entry_registers()
        assert proj.arch.registers["eax"][0] not in entry


if __name__ == "__main__":
    unittest.main()

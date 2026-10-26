#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os.path
import unittest
from unittest import mock

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
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

    def test_rust_fast_path_matches_symbolic_execution(self):
        # syscall numbers that are block-local constants are resolved in Rust without symbolic execution
        for binary in ("mips/ld.so.1", "x86_64/calc", "i386/rcr_test"):
            path = os.path.join(test_location, *binary.split("/"))
            cfg = angr.Project(path, auto_load_libs=False).analyses.CFGFast(normalize=True)
            assert cfg._ijr_stats.get("SyscallResolver:rust", 0) > 0, binary
            with mock.patch.object(SyscallResolver, "rust_fast_path", return_value=None):
                cfg_py = angr.Project(path, auto_load_libs=False).analyses.CFGFast(normalize=True)
            assert cfg_py._ijr_stats.get("SyscallResolver:rust", 0) == 0

            def syscall_edges(c):
                return sorted(
                    (src.addr, dst.addr, data["jumpkind"])
                    for src, dst, data in c.graph.edges(data=True)
                    if data["jumpkind"].startswith("Ijk_Sys")
                )

            edges = syscall_edges(cfg)
            assert edges, binary
            assert edges == syscall_edges(cfg_py), binary

    def test_rust_fast_path_shadow(self):
        path = os.path.join(test_location, "x86_64", "calc")
        with mock.patch.object(CFGFast, "_rust_ijr_shadow", True):
            cfg = angr.Project(path, auto_load_libs=False).analyses.CFGFast(normalize=True)
        assert cfg._ijr_stats.get("SyscallResolver:shadow_same", 0) > 0
        assert not [m for m in cfg._ijr_shadow_mismatches if m["kind"] == "SyscallResolver"]


if __name__ == "__main__":
    unittest.main()

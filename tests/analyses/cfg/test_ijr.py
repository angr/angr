#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.analyses.cfg.indirect_jump_resolvers import MemoryLoadResolver
from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import default_indirect_jump_resolvers
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _digest(cfg: CFGFast):
    nodes = sorted((n.addr, n.size, n.function_address) for n in cfg.graph.nodes())
    edges = sorted(
        (a.addr, a.size, b.addr, b.size, d.get("jumpkind"), d.get("stmt_idx"), d.get("ins_addr"))
        for a, b, d in cfg.graph.edges(data=True)
    )
    funcs = sorted((f.addr, f.name, tuple(sorted(f.block_addrs_set))) for f in cfg.kb.functions.values())
    ijs = sorted(
        (ij.addr, ij.ins_addr, ij.func_addr, ij.jumpkind, tuple(ij.resolved_targets or ()))
        for ij in cfg.kb.indirect_jumps.values()
    )
    return nodes, edges, funcs, ijs


def _cfg(proj: angr.Project, **kwargs) -> CFGFast:
    return proj.analyses.CFGFast(normalize=True, **kwargs)


class TestResolverChain(unittest.TestCase):
    def _compare(self, name: str):
        with mock.patch.object(CFGFast, "_rust_ijr", False):
            base = _digest(_cfg(angr.Project(os.path.join(test_location, name), auto_load_libs=False)))
        cfg = _cfg(angr.Project(os.path.join(test_location, name), auto_load_libs=False))
        assert cfg._ijr_stats.get("precheck:rust", 0) > 0
        assert _digest(cfg) == base

    def test_amd64(self):
        self._compare("x86_64/fauxware")

    def test_mips(self):
        self._compare("mips/fauxware")

    def test_armel(self):
        self._compare("armel/fauxware")

    def test_x86_pe(self):
        self._compare("x86_64/windows/1817a5bf9c01035bcf8a975c9f1d94b0ce7f6a200339485d8f93859f8f6d730c.exe")

    def test_shadow(self):
        for name in ("x86_64/fauxware", "mips/fauxware", "i386/fauxware"):
            with mock.patch.object(CFGFast, "_rust_ijr_shadow", True):
                cfg = _cfg(angr.Project(os.path.join(test_location, name), auto_load_libs=False))
            assert cfg._ijr_shadow_mismatches == []
            assert cfg._ijr_stats.get("MemoryLoadResolver:shadow_same", 0) > 0

    def test_memload_in_rust(self):
        cfg = _cfg(angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False))
        assert cfg._ijr_stats.get("MemoryLoadResolver:rust", 0) > 0

    def test_kinds_and_master_switch(self):
        proj = angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False)
        with mock.patch.object(CFGFast, "_rust_ijr_kinds", frozenset({"precheck"})):
            cfg = _cfg(proj)
        assert "MemoryLoadResolver:rust" not in cfg._ijr_stats
        assert cfg._ijr_stats.get("precheck:rust", 0) > 0
        with mock.patch.object(CFGFast, "_rust_ijr", False):
            cfg = _cfg(proj)
        assert cfg._ijr_stats == {}

    def test_python_resolvers_keep_working(self):
        """
        Subclasses, opted-out instances and user resolvers run in Python, in their list positions.
        """
        calls: list[tuple[str, int]] = []

        class MyMemoryLoad(MemoryLoadResolver):
            def resolve(self, cfg, addr, func_addr, block, jumpkind, func_graph_complete=True, **kwargs):
                calls.append(("sub", addr))
                return super().resolve(cfg, addr, func_addr, block, jumpkind, **kwargs)

        class Spy(MemoryLoadResolver):
            def filter(self, cfg, addr, func_addr, block, jumpkind):
                calls.append(("spy", addr))
                assert block.statements is not None
                return False

        name = os.path.join(test_location, "x86_64/fauxware")
        with mock.patch.object(CFGFast, "_rust_ijr", False):
            base = _digest(_cfg(angr.Project(name, auto_load_libs=False)))

        proj = angr.Project(name, auto_load_libs=False)
        cfg = _cfg(proj, indirect_jump_resolvers=[Spy(proj), MyMemoryLoad(proj)])
        assert "MemoryLoadResolver:rust" not in cfg._ijr_stats
        assert {k for k, _ in calls} == {"spy", "sub"}
        # the subclass resolves exactly what the Rust MemoryLoadResolver would
        assert _digest(cfg)[3] == base[3]

        proj = angr.Project(name, auto_load_libs=False)
        resolvers = default_indirect_jump_resolvers(proj.loader.main_object, proj)
        for r in resolvers:
            if isinstance(r, MemoryLoadResolver):
                r.use_rust = False
        cfg = _cfg(proj, indirect_jump_resolvers=resolvers)
        assert "MemoryLoadResolver:rust" not in cfg._ijr_stats
        assert _digest(cfg) == base


if __name__ == "__main__":
    unittest.main()

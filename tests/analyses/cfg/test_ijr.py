#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import pickle
import unittest
from unittest import mock

import pyvex

import angr
from angr.analyses.cfg.cfg_base import CFGBase
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.analyses.cfg.indirect_jump_resolvers import ConstantResolver, MemoryLoadResolver
from angr.analyses.cfg.indirect_jump_resolvers.constant_value_manager import ConstantValueManager, fcp_rows
from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import default_indirect_jump_resolvers
from angr.analyses.cfg.indirect_jump_resolvers.propagator_utils import PropagatorLoadCallback
from angr.analyses.propagator.vex_vars import VEXTmp
from angr.blade import Blade
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


def _py_rows(replacements) -> list:
    """Python FCP replacements in the row format of ResolverChain.debug_fcp."""
    rows = []
    for loc, d in replacements.items():
        row = [((("tmp", k.tmp, 0) if isinstance(k, VEXTmp) else ("reg", k.offset, k.size)), v) for k, v in d.items()]
        rows.append(((loc.block_addr, loc.stmt_idx, loc.ins_addr), row))
    return rows


class _Compare:
    """
    Wraps CFGBase._process_unresolved_indirect_jumps: before each batch of deferred jumps, compares the Rust FCP,
    Blade and ConstantValueManager (outside the chain's dispatch) with the Python ones for every jump.
    """

    def __init__(self):
        self.fcp: list[tuple] = []
        self.blade: list[tuple] = []
        self.cvm: list[tuple] = []
        self.orig = CFGBase._process_unresolved_indirect_jumps

    def __call__(self, cfg):
        for jump in sorted(cfg._indirect_jumps_to_resolve, key=lambda j: j.addr):
            self.compare(cfg, jump)
        return self.orig(cfg)

    def compare(self, cfg, jump):
        chain = cfg._ijr_chain
        project = cfg.project
        if chain is not None and cfg.functions.contains_addr(jump.func_addr):
            func = cfg.functions.get_by_addr(jump.func_addr)
            prop = project.analyses.FastConstantPropagation(
                func,
                vex_cross_insn_opt=False,
                load_callback=PropagatorLoadCallback(project).propagator_load_callback,
            )
            self.fcp.append((jump.func_addr, chain.debug_fcp(cfg, jump.func_addr), _py_rows(prop.replacements)))
            if func.get_node(jump.addr) is not None:
                cvm = ConstantValueManager(project, cfg.kb, func, jump.addr)
                cvm._build_mapping()
                rust = cfg._ijr_fcp.cvm_mapping(cfg, jump.func_addr, jump.addr)
                self.cvm.append((jump.addr, rust.rows(), fcp_rows(cvm.mapping)))
            if isinstance(cfg._lift(jump.addr).vex.next, pyvex.IRExpr.RdTmp):
                b = Blade(
                    cfg.graph,
                    jump.addr,
                    -1,
                    cfg=cfg,
                    project=project,
                    ignore_bp=False,
                    ignore_sp=False,
                    max_level=3,
                    stop_at_calls=True,
                    cross_insn_opt=True,
                    control_dependence=False,
                )
                nodes, edges = chain.debug_blade(jump.addr)
                self.blade.append(
                    (jump.addr, (list(nodes), list(edges)), (list(b.slice.nodes()), list(b.slice.edges())))
                )

    def method(self):
        def _process_unresolved_indirect_jumps(cfg):
            return self(cfg)

        return _process_unresolved_indirect_jumps


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
        for name in ("x86_64/fauxware", "mips/fauxware", "i386/fauxware", "armel/fauxware"):
            with mock.patch.object(CFGFast, "_rust_ijr_shadow", True):
                cfg = _cfg(angr.Project(os.path.join(test_location, name), auto_load_libs=False))
            assert cfg._ijr_shadow_mismatches == []
            assert cfg._ijr_stats.get("MemoryLoadResolver:shadow_same", 0) > 0

    def test_memload_in_rust(self):
        cfg = _cfg(angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False))
        assert cfg._ijr_stats.get("MemoryLoadResolver:rust", 0) > 0

    def test_fcp_and_blade_match_python(self):
        for name in ("x86_64/fauxware", "mips/fauxware", "armel/fauxware", "i386/fauxware"):
            cmp = _Compare()
            with mock.patch.object(CFGBase, "_process_unresolved_indirect_jumps", cmp.method()):
                _cfg(angr.Project(os.path.join(test_location, name), auto_load_libs=False))
            assert cmp.fcp, name
            for func_addr, rust, python in cmp.fcp:
                assert list(rust) == python, (name, hex(func_addr))
            assert any(python for _, _, python in cmp.fcp)
            assert cmp.blade, name
            for addr, rust, python in cmp.blade:
                assert rust == python, (name, hex(addr))
            assert cmp.cvm, name
            for addr, rust, python in cmp.cvm:
                assert list(rust) == python, (name, hex(addr))

    def test_constant_resolver_publishes_propagations(self):
        name = os.path.join(
            test_location, "x86_64/windows/1817a5bf9c01035bcf8a975c9f1d94b0ce7f6a200339485d8f93859f8f6d730c.exe"
        )
        with mock.patch.object(CFGFast, "_rust_ijr", False):
            proj = angr.Project(name, auto_load_libs=False)
            _cfg(proj)
            base = {
                k: (m.function_block_count, dict(m.replacements)) for k, m in proj.kb.propagations._propagations.items()
            }
        proj = angr.Project(name, auto_load_libs=False)
        cfg = _cfg(proj)
        assert cfg._ijr_stats.get("ConstantResolver:resolved", 0) > 0
        props = proj.kb.propagations._propagations
        assert {k: (m.function_block_count, dict(m.replacements)) for k, m in props.items()} == base
        model = next(iter(props.values()))
        assert pickle.loads(pickle.dumps(model.replacements)) == dict(model.replacements)

        # a second run on the same KB reuses those FCP results, so ConstantResolver stays in Python
        cfg = _cfg(proj)
        assert "ConstantResolver:rust" not in cfg._ijr_stats

    def test_cvm_kind(self):
        name = os.path.join(
            test_location, "x86_64/windows/1817a5bf9c01035bcf8a975c9f1d94b0ce7f6a200339485d8f93859f8f6d730c.exe"
        )
        kinds = CFGFast._rust_ijr_kinds - {"ConstantValueManager"}
        with mock.patch.object(CFGFast, "_rust_ijr_kinds", kinds):
            base = _digest(_cfg(angr.Project(name, auto_load_libs=False)))
        cfg = _cfg(angr.Project(name, auto_load_libs=False))
        assert cfg._ijr_stats.get("ConstantValueManager:rust", 0) > 0
        assert _digest(cfg) == base

    def test_scan_path(self):
        """
        The block scan resolves indirect exits through the chain; the result equals the _create_jobs path's.
        """
        name = os.path.join(test_location, "x86_64/fauxware")
        with mock.patch.object(CFGFast, "_rust_ijr_scan", False):
            base = _digest(_cfg(angr.Project(name, auto_load_libs=False)))
        cfg = _cfg(angr.Project(name, auto_load_libs=False))
        stats = cfg._block_scan_stats
        assert stats.get("ijr:resolved", 0) > 0
        assert stats.get("ijr:unresolved", 0) > 0
        assert _digest(cfg) == base

    def test_arch_resolvers(self):
        """
        The architecture-specific timeless resolvers in Rust give the CFG their Python twins give.
        """
        cases = {
            "armel/fauxware": "ArmElfFastResolver",
            "mips/fauxware": "MipsElfFastResolver",
            "i386/fauxware": "X86ElfPicPltResolver",
            "x86_64/windows/1817a5bf9c01035bcf8a975c9f1d94b0ce7f6a200339485d8f93859f8f6d730c.exe": "AMD64PeIatResolver",
        }
        for name, kind in cases.items():
            path = os.path.join(test_location, name)
            with mock.patch.object(CFGFast, "_rust_ijr_kinds", CFGFast._rust_ijr_kinds - {kind}):
                base = _digest(_cfg(angr.Project(path, auto_load_libs=False)))
            cfg = _cfg(angr.Project(path, auto_load_libs=False))
            assert cfg._ijr_stats.get(f"{kind}:rust", 0) + cfg._ijr_stats.get(f"{kind}:decline:symbolic", 0) > 0, name
            assert _digest(cfg) == base, name

    def test_kinds_and_master_switch(self):
        proj = angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False)
        with mock.patch.object(CFGFast, "_rust_ijr_kinds", frozenset({"precheck"})):
            cfg = _cfg(proj)
        assert "MemoryLoadResolver:rust" not in cfg._ijr_stats
        assert "ConstantResolver:rust" not in cfg._ijr_stats
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
            if isinstance(r, (MemoryLoadResolver, ConstantResolver)):
                r.use_rust = False
        cfg = _cfg(proj, indirect_jump_resolvers=resolvers)
        assert "MemoryLoadResolver:rust" not in cfg._ijr_stats
        assert "ConstantResolver:rust" not in cfg._ijr_stats
        assert _digest(cfg) == base


if __name__ == "__main__":
    unittest.main()

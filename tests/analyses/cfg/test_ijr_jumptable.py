#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import json
import os
import unittest
from unittest import mock

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.analyses.cfg.indirect_jump_resolvers import JumpTableResolver
from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import default_indirect_jump_resolvers
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

JT = "JumpTableResolver"
NO_RUST_JT = CFGFast._rust_ijr_kinds - {JT}


def _tables(cfg: CFGFast) -> dict:
    return {
        addr: (
            bool(ij.jumptable),
            sorted(ij.resolved_targets),
            [(t.addr, t.size, t.entry_size, list(t.entries)) for t in ij.jumptables],
            ij.type,
        )
        for addr, ij in cfg.indirect_jumps.items()
    }


def _cfg(name: str, **kwargs) -> CFGFast:
    proj = angr.Project(os.path.join(test_location, name), auto_load_libs=False)
    return proj.analyses.CFGFast(normalize=True, **kwargs)


class TestRustJumpTableResolver(unittest.TestCase):
    def _same_as_python(self, name: str, **kwargs) -> CFGFast:
        with mock.patch.object(CFGFast, "_rust_ijr_kinds", NO_RUST_JT):
            base = _cfg(name, **kwargs)
        assert JT + ":cls:resolved" not in base._ijr_stats
        cfg = _cfg(name, **kwargs)
        assert cfg._ijr_stats.get(JT + ":cls:resolved", 0) > 0
        assert _tables(cfg) == _tables(base)
        assert sorted(cfg.model.jump_tables) == sorted(base.model.jump_tables)
        return cfg

    def test_amd64_switches(self):
        self._same_as_python("x86_64/cfg_switches")

    def test_i386_switches(self):
        self._same_as_python("i386/cfg_switches_O2")

    def test_two_level_table(self):
        # a byte index table in front of the jump table: the index table is the primary record
        cfg = self._same_as_python(
            "x86_64/windows/9c75d43ec531c76caa65de86dcac0269d6727ba4ec74fe1cac1fda0e176fd2ab",
            regions=[(0x140051B40, 0x140051CD6)],
            function_starts=[0x140051B40],
            start_at_entry=False,
        )
        jt = cfg.model.jump_tables[0x140051BBB]
        assert [(t.addr, t.entry_size) for t in jt.jumptables] == [(0x140051CA0, 1), (0x140051C84, 4)]

    def test_unbounded_tables_are_deferred(self):
        # rustc tables without a bounds check: deferred until the final pass, then sized from the next data reference
        cfg = self._same_as_python(
            "x86_64/rust/jql", regions=[(0x4E63B0, 0x4E6D80)], function_starts=[0x4E63B0], start_at_entry=False
        )
        assert cfg._ijr_stats.get(JT + ":cls:deferred", 0) > 0
        assert len(cfg.model.jump_tables[0x4E63D8].jumptable_entries) == 6

    def test_lower_bound_from_a_deeper_guard(self):
        # ACLSetUserStringError: `cmp eax, 1; jle` above `cmp eax, 0x16; ja`; Rust always looks one block deeper
        for deeper in (True, False):
            with mock.patch.object(CFGFast, "_jt_deeper_lower_bound", deeper):
                cfg = _cfg(
                    "x86_64/decompiler/redis_server_O2",
                    regions=[(0xA05380, 0xA05440)],
                    function_starts=[0xA05380],
                    start_at_entry=False,
                )
            assert cfg._ijr_stats.get(JT + ":cls:resolved", 0) > 0
            jt = cfg.model.jump_tables[0xA0539A]
            assert (jt.jumptable_addr, jt.jumptable_size) == (0xC171F8, 21 * 8)

    def test_arm_conditional_loads(self):
        # `ldrls pc, [pc, r3, lsl #2]`: the load happens only when the guard holds
        self._same_as_python("armel/cfg_switches")

    def test_aarch64_byte_tables(self):
        self._same_as_python("aarch64/langdetect_go")

    def test_mips_gp_tables(self):
        with mock.patch.object(CFGFast, "_rust_ijr_kinds", NO_RUST_JT):
            base = _cfg("mipsel/jumptable_0")
        cfg = _cfg("mipsel/jumptable_0")
        assert cfg._ijr_stats.get(JT + ":cls:resolved", 0) > 0
        base_tables, tables = _tables(base), _tables(cfg)
        # Rust also resolves tables Python does not; the ones Python resolves are the same
        for addr, rec in base_tables.items():
            if rec[2]:
                assert tables[addr] == rec, hex(addr)
        assert sum(1 for rec in tables.values() if rec[2]) > sum(1 for rec in base_tables.values() if rec[2])

    def test_i386_pic_table(self):
        # iconv: `call __x86.get_pc_thunk.bx; add ebx, imm` makes ebx the GOT, which bases the table and its targets
        name = "i386/libc.so.6"
        kwargs = {
            "regions": [(0x41A860, 0x41AA00), (0x52694B, 0x52694F)],
            "function_starts": [0x52694B, 0x41A860],
            "start_at_entry": False,
        }
        with mock.patch.object(CFGFast, "_rust_ijr_kinds", NO_RUST_JT):
            base = _cfg(name, **kwargs)
        assert not base.indirect_jumps[0x41A8E7].jumptable
        cfg = _cfg(name, **kwargs)
        ij = cfg.indirect_jumps[0x41A8E7]
        assert [(t.addr, len(t.entries)) for t in ij.jumptables] == [(0x549D00, 9)]
        assert sorted(set(ij.resolved_targets)) == [0x41A8F8, 0x41A920, 0x41A930, 0x41A958, 0x41A980, 0x41A9A8]

    def test_python_deeper_lower_bound_default(self):
        # off behind the Rust resolver, on without it; an explicit setting wins
        def deeper(**kwargs) -> bool:
            cfg = _cfg("x86_64/fauxware", **kwargs)
            return next(r for r in cfg.indirect_jump_resolvers if isinstance(r, JumpTableResolver)).deeper_lower_bound

        assert deeper() is False
        with mock.patch.object(CFGFast, "_rust_ijr_kinds", NO_RUST_JT):
            assert deeper() is True
        with mock.patch.object(CFGFast, "_rust_jt_arches", frozenset()):
            assert deeper() is True
        with mock.patch.object(CFGFast, "_jt_deeper_lower_bound", True):
            assert deeper() is True
        proj = angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False)
        resolvers = default_indirect_jump_resolvers(proj.loader.main_object, proj)
        for r in resolvers:
            if isinstance(r, JumpTableResolver):
                r.deeper_lower_bound = True
        proj.analyses.CFGFast(normalize=True, indirect_jump_resolvers=resolvers)
        assert all(r.deeper_lower_bound for r in resolvers if isinstance(r, JumpTableResolver))

    def test_shadow_classification(self):
        with mock.patch.object(CFGFast, "_rust_ijr_shadow", True):
            cfg = _cfg("x86_64/cfg_switches")
        assert cfg._ijr_shadow_mismatches == []
        records = cfg._ijr_jt_records
        resolved = [r for r in records if json.loads(r["rust"])["cls"] == "resolved"]
        assert resolved
        for r in resolved:
            assert r["python"]["resolved"]
            assert json.loads(r["rust"])["targets"] == r["python"]["targets"], hex(r["addr"])

    def test_python_shadow_of_rust_answers(self):
        with mock.patch.object(CFGFast, "_rust_jt_py_shadow", True):
            cfg = _cfg("x86_64/cfg_switches")
        rust_first = [r for r in cfg._ijr_jt_records if not r["python_authoritative"]]
        assert rust_first
        for r in rust_first:
            assert json.loads(r["rust"])["targets"] == r["python"]["targets"], hex(r["addr"])

    def test_skip_classes(self):
        # jumps that are not table-shaped are answered in Rust on every architecture; Python fails them too, so the
        # CFG does not change
        for name in ("mips/fauxware", "mipsel/fauxware", "ppc/fauxware"):
            with mock.patch.object(CFGFast, "_rust_jt_skip", False):
                base = _cfg(name)
            cfg = _cfg(name)
            assert any(k.startswith(JT + ":cls:skip:") for k in cfg._ijr_stats), name
            assert _tables(cfg) == _tables(base), name
            assert sorted((n.addr, n.size) for n in cfg.graph.nodes()) == sorted(
                (n.addr, n.size) for n in base.graph.nodes()
            ), name

    def test_disabled_by_kind_or_arch(self):
        with (
            mock.patch.object(CFGFast, "_rust_jt_arches", frozenset()),
            mock.patch.object(CFGFast, "_rust_jt_skip", False),
        ):
            cfg = _cfg("x86_64/cfg_switches")
        assert cfg._ijr_stats.get(JT + ":decline:arch", 0) > 0
        assert JT + ":cls:resolved" not in cfg._ijr_stats


if __name__ == "__main__":
    unittest.main()

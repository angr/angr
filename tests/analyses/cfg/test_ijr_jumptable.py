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


def _rust_records(name: str, lo: int, hi: int) -> dict:
    """Shadow records of a one-function region: jump -> (Rust answer, Python targets)."""
    with mock.patch.object(CFGFast, "_rust_ijr_shadow", True):
        cfg = _cfg(name, regions=[(lo, hi)], function_starts=[lo], start_at_entry=False)
    return {r["addr"]: (json.loads(r["rust"]), r["python"]["targets"]) for r in cfg._ijr_jt_records}


class TestRustJumpTableResolver(unittest.TestCase):
    def _agrees(self, records: dict, addr: int, table: int, n: int) -> None:
        rust, py_targets = records[addr]
        assert rust["cls"] == "resolved", hex(addr)
        assert (rust["table"], rust["n"]) == (table, n), hex(addr)
        assert rust["targets"] == py_targets, hex(addr)

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

    def test_signed_bounds_across_zero(self):
        # memmove-ssse3 tails: `cmp rdx, -0x40; jl` with `rdx + 0x40` as the index
        with mock.patch.object(CFGFast, "_rust_ijr_shadow", True):
            cfg = _cfg(
                "x86_64/ioctl/libc.so.6",
                regions=[(0x57AC10, 0x57E000)],
                function_starts=[0x57AC10],
                start_at_entry=False,
            )
        records = {r["addr"]: r for r in cfg._ijr_jt_records}
        for addr in (0x57ADE5, 0x57B011, 0x57D4AE, 0x57D58C, 0x57D7C5, 0x57D9F1):
            rust = json.loads(records[addr]["rust"])
            assert rust["cls"] == "resolved", hex(addr)
            assert rust["targets"] == records[addr]["python"]["targets"], hex(addr)
        assert (json.loads(records[0x57D58C]["rust"])["table"], json.loads(records[0x57D58C]["rust"])["n"]) == (
            0x5E2F50,
            64,
        )

    def test_skip_unbounded_tables(self):
        # off by default; on, tables whose index no path bounds are unresolved without the Python resolver
        kwargs = {"regions": [(0x4BFEC0, 0x4C0EC4)], "function_starts": [0x4BFEC0], "start_at_entry": False}
        base = _cfg("x86_64/ioctl/libc.so.6", **kwargs)
        declined = base._ijr_stats.get(JT + ":cls:unbounded:table", 0)
        assert declined > 0
        with mock.patch.object(CFGFast, "_rust_jt_skip_unbounded", True):
            cfg = _cfg("x86_64/ioctl/libc.so.6", **kwargs)
        assert cfg._ijr_stats.get(JT + ":cls:skip:unbounded_table", 0) == declined
        assert JT + ":cls:unbounded:table" not in cfg._ijr_stats
        assert set(cfg.model.jump_tables) <= set(base.model.jump_tables)

    def test_add_flag_conditions(self):
        # strncmp-sse42: `add r8, 0x20; jl` then `add r8, 0x10; jl` bound the index to [0, 15]
        records = _rust_records("x86_64/ioctl/libc.so.6", 0x4BFEC0, 0x4C0EC4)
        self._agrees(records, 0x4C0D92, 0x5D31B0, 16)

    def test_deeper_paths_for_unbounded_tables(self):
        # strncmp-sse42: the index's lower bound (`test rdx, rdx; je` at entry) is five blocks up; index 0 is excluded
        records = _rust_records("x86_64/ioctl/libc.so.6", 0x4BFEC0, 0x4C0EC4)
        rust, py_targets = records[0x4C0435]
        assert (rust["cls"], rust["table"], rust["n"]) == ("resolved", 0x5D3124, 17)
        assert rust["targets"] == py_targets[1:]

    def test_bit_counts_and_relations(self):
        libc = "x86_64/ioctl/libc.so.6"
        # strncmp-sse42: `bsf rdx, rdx; cmp rdx, r8; jb` bounds r8 by the mask's 16 bits; `cmp r8, r10; jbe` with
        # r10 = 0x11 - (rsi & 0xf)
        records = _rust_records(libc, 0x4BFEC0, 0x4C0EC4)
        self._agrees(records, 0x4C0323, 0x5D3120, 16)
        self._agrees(records, 0x4C0409, 0x5D3120, 18)
        # strcpy-ssse3: (eax + 15) - ecx with eax < ecx, both below 16; Python reads 29 entries into the next table
        rust, py_targets = _rust_records(libc, 0x4B1920, 0x4B3000)[0x4B19A3]
        assert (rust["table"], rust["n"]) == (0x5D2E20, 16)
        assert rust["targets"] == py_targets[:16]
        # strcmp-sse2: bsf + 16 - (rsi & 0xf) is in [1, 31]; the table at 0x5d3020 has 32 entries. Python counts only
        # the 16 bits the mask can set
        records = _rust_records(libc, 0x4BF890, 0x4BFEB3)
        self._agrees(records, 0x4BFB50, 0x5D3024, 31)
        # bsf of the mask shifted right by rsi & 0xf: Rust declines, Python reads the 16 entries 0x4bfb38 reads
        rust, py_targets = records[0x4BFB10]
        assert rust["cls"] == "decline"
        assert py_targets == records[0x4BFB38][0]["targets"]

    def test_unsigned_ranges_through_wrapping_sums(self):
        # memmove-ssse3 tails: rdx <u 0x80 and (rdx - 0x40) >=u 0x20 above an index of rdx - 0x60
        records = _rust_records("x86_64/ioctl/libc.so.6", 0x57D5F0, 0x580166)
        self._agrees(records, 0x57D8F6, 0x5E3110, 32)
        self._agrees(records, 0x57DB16, 0x5E3110, 32)

    def test_index_table_of_a_truncated_sum(self):
        # vfprintf: the byte index table is read at (int)(signed char)c - 0x20, bounded by (c - 0x20) & 0xff <= 0x5a
        records = _rust_records("x86_64/ioctl/libc.so.6", 0x472B40, 0x47502F)
        self._agrees(records, 0x4735D8, 0x5D16E0, 91)
        assert json.dumps(records[0x4735D8][0]["table2"][:3]) == json.dumps([0x5D1360, 31 * 4, 4])

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

    def test_python_check_tables_default(self):
        # on behind the Rust resolver, off without it; an explicit setting wins
        def check(**kwargs) -> bool:
            cfg = _cfg("x86_64/fauxware", **kwargs)
            return next(r for r in cfg.indirect_jump_resolvers if isinstance(r, JumpTableResolver)).check_tables

        assert check() is True
        with mock.patch.object(CFGFast, "_rust_ijr_kinds", NO_RUST_JT):
            assert check() is False
        with (
            mock.patch.object(CFGFast, "_rust_ijr_kinds", NO_RUST_JT),
            mock.patch.object(CFGFast, "_jt_check_tables", True),
        ):
            assert check() is True

    def test_python_tables_checked(self):
        # libc: an unbounded index read 65535 entries; strlen-sse2 read 29 entries into the next table at 0x5d2f20
        # (the Python resolver alone: the Rust one answers the second jump itself)
        def tables(check: bool, regions, starts) -> dict:
            with (
                mock.patch.object(CFGFast, "_rust_ijr_kinds", NO_RUST_JT),
                mock.patch.object(CFGFast, "_jt_check_tables", check),
            ):
                cfg = _cfg("x86_64/ioctl/libc.so.6", regions=regions, function_starts=starts, start_at_entry=False)
            return {a: [(t.addr, len(t.entries)) for t in ij.jumptables] for a, ij in cfg.indirect_jumps.items()}

        too_many = ([(0x4BFEC0, 0x4C0EC0)], [0x4BFEC0])
        assert tables(False, *too_many)[0x4C0EA9] == [(0x5D3124, 65535)]
        assert tables(True, *too_many)[0x4C0EA9] == []
        over_read = ([(0x579470, 0x57B000), (0x4B5980, 0x4B7980)], [0x579470, 0x4B5980])
        assert tables(False, *over_read)[0x579513] == [(0x5D2EE0, 29)]
        assert tables(True, *over_read)[0x579513] == [(0x5D2EE0, 16)]

    def test_rust_write_back(self):
        # the jobs of resolved jumps queued in Rust give the CFG the Python write-back gives
        def summary(cfg: CFGFast) -> tuple:
            return (
                sorted((n.addr, n.size) for n in cfg.graph.nodes()),
                sorted((u.addr, v.addr, d.get("jumpkind")) for u, v, d in cfg.graph.edges(data=True)),
                sorted((f.addr, tuple(sorted(f.block_addrs_set)), f.returning) for f in cfg.kb.functions.values()),
                _tables(cfg),
                sorted((m.addr, m.size, str(m.sort)) for m in cfg.memory_data.values()),
            )

        for name in ("x86_64/cfg_switches", "armel/cfg_switches", "x86_64/decompiler/redis_server_O2"):
            kwargs = (
                {"regions": [(0xA05380, 0xA05440)], "function_starts": [0xA05380], "start_at_entry": False}
                if "redis" in name
                else {}
            )
            with mock.patch.object(CFGFast, "_rust_ijr_write_back", False):
                base = _cfg(name, **kwargs)
            cfg = _cfg(name, **kwargs)
            assert cfg._ijr_stats.get("write_back:rust", 0) > 0, name
            assert "write_back:rust" not in base._ijr_stats, name
            assert summary(cfg) == summary(base), name

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

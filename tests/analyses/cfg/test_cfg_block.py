#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""CFGFast's Rust per-block scan (angr.rustylib.cfg_block) against the Python per-block code."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import json
import os
import unittest
from unittest import mock

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _scan_time_functions(cfg) -> list:
    """Every scan-time function with its transition graph edges and info, in graph order."""
    out = []
    for func in cfg.kb.functions.values():
        edges = [
            (type(s).__name__, s.addr, s.size, type(d).__name__, d.addr, d.size, sorted(data.items(), key=str))
            for s, d, data in func.transition_graph.edges(data=True)
        ]
        out.append(
            (
                func.addr,
                func.name,
                func.returning,
                func.is_plt,
                json.dumps(dict(func.info), sort_keys=True, default=str),
                sorted(func.block_addrs_set),
                edges,
            )
        )
    return out


def _digest(cfg) -> tuple:
    nodes = [
        (n.addr, n.size, n.function_address, tuple(n.instruction_addrs), n.thumb, n.byte_string)
        for n in cfg.model.graph
    ]
    edges = [
        (s.addr, d.addr, data["jumpkind"], data.get("ins_addr"), str(data.get("stmt_idx")))
        for s, d, data in cfg.model.graph.edges(data=True)
    ]
    funcs = sorted(
        (f.addr, f.name, f.returning, sorted(f.block_addrs_set), sorted(map(str, f.graph.edges())))
        for f in cfg.kb.functions.values()
    )
    memory_data = [(a, m.size, str(m.sort)) for a, m in cfg.model.memory_data.items()]
    insn_to_md = sorted((k, v.addr) for k, v in cfg.model.insn_addr_to_memory_data.items())
    xrefs = sorted(
        (x.ins_addr, x.block_addr, str(x.stmt_idx), x.dst) for xs in cfg.kb.xrefs.xrefs_by_ins_addr.values() for x in xs
    )
    return nodes, edges, funcs, memory_data, insn_to_md, xrefs


class TestCFGFastBlockScan(unittest.TestCase):
    def _run(self, binary: str, rust: bool, **kwargs):
        snapshots = []
        make_functions = CFGFast.make_functions

        def recording_make_functions(cfg):
            snapshots.append(_scan_time_functions(cfg))
            return make_functions(cfg)

        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
        with (
            mock.patch.object(CFGFast, "_rust_block_scan", rust),
            mock.patch.object(CFGFast, "make_functions", recording_make_functions),
        ):
            cfg = proj.analyses.CFGFast(show_progressbar=False, **kwargs)
        assert cfg._block_scanner is None
        return cfg, _digest(cfg), snapshots

    def _check(self, binary: str, **kwargs) -> dict[str, int]:
        cfg_rust, digest_rust, scan_rust = self._run(binary, True, **kwargs)
        _, digest_py, scan_py = self._run(binary, False, **kwargs)
        assert scan_rust == scan_py
        assert digest_rust == digest_py
        stats = cfg_rust._block_scan_stats
        assert stats["rust"] > 0
        return stats

    def test_x86_64(self):
        stats = self._check("x86_64/fauxware", normalize=True, data_references=True, cross_references=True)
        assert stats.get("callback:indirect", 0) > 0
        assert stats.get("escape:outside_regions", 0) > 0

    def test_x86_64_complete_scan(self):
        self._check("x86_64/fauxware", force_complete_scan=True, data_references=True)

    def test_x86_64_pe(self):
        self._check(
            "x86_64/windows/1817a5bf9c01035bcf8a975c9f1d94b0ce7f6a200339485d8f93859f8f6d730c.exe",
            data_references=True,
        )

    def test_i386(self):
        self._check("i386/fauxware", normalize=True, data_references=True)

    def test_mips(self):
        stats = self._check("mips/fauxware", data_references=True)
        assert stats.get("mips_gp:rust", 0) > 0
        assert stats.get("callback:mips_gp", 0) > 0

    def test_mipsel(self):
        stats = self._check("mipsel/fauxware", data_references=True, normalize=True)
        assert stats.get("mips_gp:rust", 0) > 0

    def test_ppc64(self):
        self._check("ppc64/fauxware", data_references=True)

    def test_armel(self):
        stats = self._check("armel/fauxware", data_references=True)
        assert stats.get("callback:arm_arch_specific", 0) > 0

    def test_armhf(self):
        self._check("armhf/fauxware", data_references=True, normalize=True)

    def test_cortex_m(self):
        stats = self._check(
            "armel/Nucleo_read_hyperterminal.elf",
            data_references=True,
            regions=[(0x8000000, 0x8001000)],
            start_at_entry=False,
            function_prologues=True,
        )
        assert stats.get("callback:thumb_filter", 0) > 0

    def test_disabled(self):
        cfg, _, _ = self._run("x86_64/fauxware", False)
        assert cfg._block_scan_stats == {}


if __name__ == "__main__":
    unittest.main()

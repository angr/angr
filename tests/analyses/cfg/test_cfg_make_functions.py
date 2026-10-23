#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""CFGFast post-analysis in Rust (angr.rustylib.cfg_funcs, cfg_normalize, cfg_post) against the Python code."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import io
import json
import os
import unittest
from unittest import mock

import angr
from angr.analyses.cfg.cfg_base import CFGBase
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.analyses.cfg.loader_snapshot import build_loader_snapshot
from angr.rustylib.cfg_post import x86_alignment_verdicts
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _snapshot(proj, cfg) -> dict:
    """Functions, function graphs, callgraph, function index and CFG nodes, all in iteration order."""
    fm = proj.kb.functions
    funcs = []
    for addr in fm:
        f = fm.get_by_addr(addr)
        g = f._graph
        funcs.append(
            (
                addr,
                f.name,
                f.is_default_name,
                f.is_plt,
                f.is_syscall,
                f.is_simprocedure,
                f.is_alignment,
                f.returning,
                f.binary_name,
                f.normalized,
                json.dumps(dict(f.info), default=str),
                g.to_bytes(),
                str(f.prototype),
                str(f.calling_convention),
            )
        )
    cg = fm.callgraph
    return {
        "funcs": funcs,
        "cg_nodes": list(cg.nodes()),
        "cg_edges": list(cg.edges(keys=True, data=True)),
        "cg_pred": [(n, list(cg.pred[n])) for n in cg.nodes()],
        "block_counts": list(fm._func_block_counts.items()),
        "key_funcs": {k: list(v) for k, v in fm.get_key_func_type_and_addrs().items()},
        "nodes": [(n.addr, n.size, n.function_address, n.name) for n in cfg.model.graph.nodes()],
        "edges": [
            (s.addr, s.size, d.addr, d.size, sorted(data.items())) for s, d, data in cfg.model.graph.edges(data=True)
        ],
        "updated_nonreturning": sorted(cfg._updated_nonreturning_functions or []),
    }


def _graph_snapshot(cfg) -> dict:
    """The CFG node records, edges and side tables that normalize() changes, in order."""
    model = cfg.model
    return {
        "node_fields": [
            (
                n.addr,
                n.size,
                list(n.instruction_addrs),
                n.function_address,
                n.thumb,
                n.is_syscall,
                n.no_ret,
                n.byte_string,
                n.simprocedure_name,
            )
            for n in model.graph.nodes()
        ],
        "edge_data": [
            (s.addr, s.size, d.addr, d.size, list(data.items())) for s, d, data in model.graph.edges(data=True)
        ],
        "blockid_to_blockkey": list(model._blockid_to_blockkey.items()),
        "block_addrs_with_return": sorted(model._block_addrs_with_return),
        "jump_tables": [(a, j.addr) for a, j in model.jump_tables.items()],
        "indirect_jumps": [(a, j.addr) for a, j in cfg.indirect_jumps.items()],
    }


def _run(path, rust: bool, flag: str = "_rust_make_functions", **kwargs) -> dict:
    with mock.patch.object(CFGFast, flag, rust):
        if isinstance(path, bytes):
            proj = angr.Project(
                io.BytesIO(path),
                main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x400000, "entry_point": 0x400000},
                auto_load_libs=False,
            )
        else:
            proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(**kwargs)
        return {**_snapshot(proj, cfg), **_graph_snapshot(cfg)}


class _Compare(unittest.TestCase):
    flag = "_rust_make_functions"

    def _check(self, path, **kwargs):
        expected = _run(path, False, self.flag, **kwargs)
        actual = _run(path, True, self.flag, **kwargs)
        assert expected.keys() == actual.keys()
        for k, v in expected.items():
            assert actual[k] == v, k


class TestRustMakeFunctions(_Compare):
    def test_x86_64(self):
        self._check(os.path.join(test_location, "x86_64", "fauxware"), normalize=True)

    def test_x86_64_not_normalized(self):
        self._check(os.path.join(test_location, "x86_64", "fauxware"), normalize=False)

    def test_armel(self):
        self._check(os.path.join(test_location, "armel", "fauxware"), normalize=True)

    def test_mips(self):
        self._check(os.path.join(test_location, "mips", "fauxware"), normalize=True)

    def test_x86_64_pe(self):
        self._check(
            os.path.join(
                test_location,
                "x86_64",
                "windows",
                "1817a5bf9c01035bcf8a975c9f1d94b0ce7f6a200339485d8f93859f8f6d730c.exe",
            ),
            normalize=True,
        )

    def test_python_path_for_tail_call_detection(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        with mock.patch(
            "angr.analyses.cfg.cfg_base.CFGBase._make_functions_in_rust", side_effect=AssertionError
        ) as rust:
            proj.analyses.CFGFast(normalize=True, detect_tail_calls=True)
        rust.assert_not_called()


class TestRustNormalize(_Compare):
    flag = "_rust_normalize"

    # 0x400000: call 0x400010; call 0x400011; ret. The blocks at 0x400010 (nop; nop; ret) and 0x400011 (nop; ret)
    # end at the same address.
    OVERLAP = bytes.fromhex("e80b000000e807000000c3cccccccccc9090c3")

    def test_overlapping_blocks(self):
        self._check(self.OVERLAP, normalize=True)
        snap = _run(self.OVERLAP, True, self.flag, normalize=True)
        assert sorted((a, s) for a, s, *_ in snap["node_fields"]) == [
            (0x400000, 5),
            (0x400005, 5),
            (0x40000A, 1),
            (0x400010, 1),
            (0x400011, 2),
        ]
        assert (0x400010, 1, 0x400011, 2, [("jumpkind", "Ijk_Boring"), ("ins_addr", 0x400010)]) in snap["edge_data"]

    def test_x86_64_pe(self):
        self._check(
            os.path.join(
                test_location,
                "x86_64",
                "windows",
                "1817a5bf9c01035bcf8a975c9f1d94b0ce7f6a200339485d8f93859f8f6d730c.exe",
            ),
            normalize=True,
        )

    def test_armel(self):
        self._check(os.path.join(test_location, "armel", "fauxware"), normalize=True)


class TestRustAlignments(_Compare):
    flag = "_rust_alignments"

    PE = os.path.join(
        test_location, "x86_64", "windows", "1817a5bf9c01035bcf8a975c9f1d94b0ce7f6a200339485d8f93859f8f6d730c.exe"
    )

    def test_x86_64(self):
        self._check(os.path.join(test_location, "x86_64", "fauxware"), normalize=True)

    def test_verdicts_match_the_python_checks(self):
        proj = angr.Project(self.PE, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        fm = proj.kb.functions
        candidates = [
            a
            for a in fm
            if fm.get_func_block_count(a) == 1 and not (fm[a].is_simprocedure or fm[a].is_syscall or fm[a].is_plt)
        ]
        snapshot = build_loader_snapshot(proj.loader, proj.arch, [proj.loader.main_object])
        verdicts = x86_alignment_verdicts(snapshot, cfg.model.graph._graph, [fm[a]._graph for a in candidates], True)
        decided = 0
        for addr, verdict in zip(candidates, verdicts):
            if verdict is None:
                continue
            decided += 1
            func = fm[addr]
            block = next(func.blocks)
            expected = CFGBase._is_noop_block(proj.arch, block) or all(
                CFGBase._is_noop_insn(insn) for insn in block.capstone.insns
            )
            if not expected:
                node = func.get_node(block.addr)
                successors = list(func.graph.successors(node))
                expected = len(successors) == 1 and successors[0].addr == node.addr
            assert verdict == expected, hex(addr)
        assert decided > 150


if __name__ == "__main__":
    unittest.main()

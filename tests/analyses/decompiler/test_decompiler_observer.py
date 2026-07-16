from __future__ import annotations

import json
import os
import tempfile
import unittest

import networkx

import angr
from angr.ailment import Block
from angr.analyses.decompiler import Decompiler, DecompilerObserver, ObserverFormat
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _make_test_graph() -> networkx.DiGraph:
    b0 = Block(0x1000, 4, statements=[], idx=None)
    b1 = Block(0x1010, 4, statements=[], idx=1)
    g = networkx.DiGraph()
    g.add_edge(b0, b1)
    return g


class RaisingObserver(DecompilerObserver):
    def on_clinic_stage(self, func_addr, stage_name, ail_graph):
        raise RuntimeError("observer failure")

    def on_decompiler_stage(self, func_addr, stage_name, ail_graph):
        raise RuntimeError("observer failure")


class TestDecompilerObserver(unittest.TestCase):
    def test_observer_dump_formats(self):
        g = _make_test_graph()
        with tempfile.TemporaryDirectory() as tmpdir:
            obs = DecompilerObserver(tmpdir, formats=(ObserverFormat.JSON, ObserverFormat.DOT, ObserverFormat.TEXT))
            obs.on_clinic_stage(0x1000, "TEST_STAGE", g)

            basename = "000_0x1000_clinic_TEST_STAGE"
            files = os.listdir(tmpdir)
            assert sorted(files) == [
                basename + ".dot",
                basename + ".json",
                basename + ".txt",
                basename + "_blocks.txt",
            ]

            # JSON
            with open(os.path.join(tmpdir, basename + ".json"), encoding="utf-8") as f:
                data = json.load(f)
            assert data["function"] == "0x1000"
            assert data["sequence"] == 0
            assert data["phase"] == "clinic"
            assert data["stage"] == "TEST_STAGE"
            assert data["graph"]["nodes"] == [{"addr": 0x1000, "idx": None}, {"addr": 0x1010, "idx": 1}]
            assert data["graph"]["edges"] == [[{"addr": 0x1000, "idx": None}, {"addr": 0x1010, "idx": 1}]]
            assert len(data["blocks"]) == 2
            assert all(isinstance(blk["dbg_repr"], str) for blk in data["blocks"])

            # DOT
            with open(os.path.join(tmpdir, basename + ".dot"), encoding="utf-8") as f:
                dot = f.read()
            assert dot.startswith("digraph")
            assert "n_0x1000_None" in dot
            assert "n_0x1010_1" in dot
            assert "n_0x1000_None -> n_0x1010_1;" in dot

            # TEXT
            with open(os.path.join(tmpdir, basename + ".txt"), encoding="utf-8") as f:
                text = f.read()
            assert "== Graph ==" in text
            assert "== Blocks ==" in text
            assert "0x1000:None -> 0x1010:1" in text

    def test_observer_isolated_nodes_in_text_dump(self):
        g = networkx.DiGraph()
        g.add_node(Block(0x2000, 4, statements=[], idx=None))
        with tempfile.TemporaryDirectory() as tmpdir:
            obs = DecompilerObserver(tmpdir, formats=ObserverFormat.TEXT)
            obs.on_decompiler_stage(0x2000, "TEST_STAGE", g)
            with open(os.path.join(tmpdir, "000_0x2000_decompiler_TEST_STAGE.txt"), encoding="utf-8") as f:
                text = f.read()
            assert "0x2000:None (isolated)" in text

    def test_observer_unknown_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValueError):
                DecompilerObserver(tmpdir, formats=("yaml",))
            with self.assertRaises(ValueError):
                DecompilerObserver(tmpdir, formats=())

    def test_observer_full_decompilation(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        f = proj.kb.functions["main"]

        with tempfile.TemporaryDirectory() as tmpdir:
            obs = DecompilerObserver(tmpdir, formats=(ObserverFormat.JSON,))
            dec = proj.analyses[Decompiler].prep(fail_fast=True)(f, cfg=cfg.model, observer=obs)

            # the observer must not break decompilation
            assert dec.codegen is not None and dec.codegen.text

            files = sorted(os.listdir(tmpdir))
            clinic_files = [fn for fn in files if "_clinic_" in fn]
            decompiler_files = [fn for fn in files if "_decompiler_" in fn]
            # stage sets shift over time; use loose lower bounds
            assert len(clinic_files) >= 12
            assert len(decompiler_files) >= 8

            for stage in ("SSA_LEVEL0_TRANSFORMATION", "RECOVER_VARIABLES", "REMOVE_EMPTY_NODES"):
                assert any(stage in fn for fn in clinic_files), f"missing clinic stage dump {stage}"
            for stage in ("CLINIC", "REGION_IDENTIFICATION", "STRUCTURING", "CODEGEN"):
                assert any(stage in fn for fn in decompiler_files), f"missing decompiler stage dump {stage}"

            # all dumps must be valid JSON following the schema
            for fn in files:
                with open(os.path.join(tmpdir, fn), encoding="utf-8") as fp:
                    data = json.load(fp)
                assert set(data) == {"function", "sequence", "phase", "stage", "graph", "blocks"}
                assert data["function"] == hex(f.addr)
                assert len(data["blocks"]) == len(data["graph"]["nodes"]) >= 1
                assert all(blk["dbg_repr"] for blk in data["blocks"])
                node_keys = {(n["addr"], n["idx"]) for n in data["graph"]["nodes"]}
                for src, dst in data["graph"]["edges"]:
                    assert (src["addr"], src["idx"]) in node_keys
                    assert (dst["addr"], dst["idx"]) in node_keys

            # sequence numbers are strictly increasing in listing order, and clinic dumps come first
            seqs = [int(fn.split("_", 1)[0]) for fn in files]
            assert seqs == sorted(set(seqs))
            max_clinic_seq = max(int(fn.split("_", 1)[0]) for fn in clinic_files)
            min_decompiler_seq = min(int(fn.split("_", 1)[0]) for fn in decompiler_files)
            assert max_clinic_seq < min_decompiler_seq

    def test_observer_failure_does_not_break_decompilation(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        f = proj.kb.functions["main"]

        with tempfile.TemporaryDirectory() as tmpdir:
            obs = RaisingObserver(tmpdir, formats=(ObserverFormat.JSON,))
            dec = proj.analyses[Decompiler].prep(fail_fast=True)(f, cfg=cfg.model, observer=obs)
            assert dec.codegen is not None and dec.codegen.text
            assert not os.listdir(tmpdir)


if __name__ == "__main__":
    unittest.main()

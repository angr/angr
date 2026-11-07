#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest

import networkx
import pyvex

import angr
from angr.analyses.vm_deobfuscation.deobf_reader import _Reader
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation
from angr.knowledge_plugins.cfg.block_id import BlockID


class _Node:
    def __init__(self, addr, irsb=None):
        self.addr, self.irsb = addr, irsb


def _deob(project):
    deob = types.SimpleNamespace(project=project)
    for name in ("_ambiguous_successor_marker", "_mark_ambiguous_successors"):
        setattr(deob, name, types.MethodType(getattr(VMDeobfuscation, name), deob))
    return deob


class TestAmbiguousSuccessorMarker(unittest.TestCase):
    """CNICdriver sub_239a0: 0x23a82 jumps once but kept two successors (one per VM region tag)."""

    def test_a_jump_with_two_successors_branches_on_the_marker(self):
        project = angr.load_shellcode(b"\xe9\x0b\x00\x00\x00" + b"\x90" * 0x20, arch="amd64", load_address=0x1000)
        src = _Node(0x1000, project.factory.block(0x1000).vex)
        succ_a, succ_b = _Node(0x2000), _Node(0x3000)
        graph = networkx.DiGraph()
        graph.add_edge(src, succ_a, type="transition")
        graph.add_edge(src, succ_b, type="transition")
        deob = _deob(project)

        assert deob._mark_ambiguous_successors(graph) == [src]
        marker = project.vm_ambiguous_successor_marker
        assert project.loader.find_symbol(marker).name == "__ambiguous_successor"
        exits = [st for st in src.irsb.statements if isinstance(st, pyvex.stmt.Exit)]
        # one successor on the marker's value, the other as the jump: both stay reachable and visible
        assert [st.dst.value for st in exits] == [0x2000]
        assert src.irsb.next.con.value == 0x3000
        loads = [st.data for st in src.irsb.statements
                 if isinstance(st, pyvex.stmt.WrTmp) and isinstance(st.data, pyvex.expr.Load)]
        assert any(isinstance(ld.addr, pyvex.expr.Const) and ld.addr.con.value == marker for ld in loads)
        src.irsb.typecheck()

    def test_a_single_successor_or_a_branch_is_left_alone(self):
        project = angr.load_shellcode(b"\xe9\x0b\x00\x00\x00" + b"\x90" * 0x20, arch="amd64", load_address=0x1000)
        src = _Node(0x1000, project.factory.block(0x1000).vex)
        graph = networkx.DiGraph()
        graph.add_edge(src, _Node(0x2000), type="transition")
        graph.add_edge(src, _Node(0x3000), type="call")
        assert _deob(project)._mark_ambiguous_successors(graph) == []
        assert getattr(project, "vm_ambiguous_successor_marker", None) is None

    def test_one_address_under_two_region_tags_is_two_targets(self):
        # sub_239a0: 0x23a82 -> 0x629b1 under region tags ...985 and ...986. The final graph places each (VPC, address)
        # at its own synthetic address, so each exit names one of the two successors
        project = angr.load_shellcode(b"\xe9\x0b\x00\x00\x00" + b"\x90" * 0x20, arch="amd64", load_address=0x1000)
        project.enc_stmt_addr_to_original = {}
        deob = _deob(project)
        deob._synthetic_addrs = {}
        deob.SYNTHETIC_ADDR_BASE, deob.SYNTHETIC_BLOCK_STRIDE = VMDeobfuscation.SYNTHETIC_ADDR_BASE, 0x1_0000
        enc = lambda addr, vpc: VMDeobfuscation.convert_addr_to_int(  # noqa: E731
            deob, addr, BlockID.new(addr, (), "normal", vpc))
        src = _Node(enc(0x23A82, None), project.factory.block(0x1000).vex)
        tag_a, tag_b = _Node(enc(0x629B1, 0x7E000000000003D9)), _Node(enc(0x629B1, 0x7E000000000003DA))
        assert tag_a.addr != tag_b.addr
        graph = networkx.DiGraph()
        graph.add_edge(src, tag_a, type="transition")
        graph.add_edge(src, tag_b, type="transition")
        assert deob._mark_ambiguous_successors(graph) == [src]
        targets = [st.dst.value for st in src.irsb.statements if isinstance(st, pyvex.stmt.Exit)]
        assert sorted(targets + [src.irsb.next.con.value]) == sorted([tag_a.addr, tag_b.addr])
        assert {project.enc_stmt_addr_to_original[t][2].vm_vpc for t in (tag_a.addr, tag_b.addr)} == {
            0x7E000000000003D9, 0x7E000000000003DA}

    def test_successors_at_one_address_are_not_marked(self):
        # two block ids at one address (e.g. 0x629b1 under region tags ...985 and ...986, had they shared a
        # synthetic address): an exit names its successor by address, so the marker could not tell them apart
        project = angr.load_shellcode(b"\xe9\x0b\x00\x00\x00" + b"\x90" * 0x20, arch="amd64", load_address=0x1000)
        src = _Node(0x1000, project.factory.block(0x1000).vex)
        before = src.irsb
        graph = networkx.DiGraph()
        graph.add_edge(src, _Node(0x2000), type="transition")
        graph.add_edge(src, _Node(0x2000), type="transition")
        with self.assertLogs("angr.analyses.vm_deobfuscation.vm_deobfuscation", "WARNING") as logs:
            assert _deob(project)._mark_ambiguous_successors(graph) == []
        assert any("not marked" in m for m in logs.output)
        assert src.irsb is before

    def test_a_replay_reads_the_marker_at_its_own_address(self):
        # the dump names the producer's marker address; the replaying project's extern object put it elsewhere
        project = types.SimpleNamespace(_vm_marker_remap=(0x201048, 0x100018))
        reader = types.SimpleNamespace(project=project, _addr=lambda a: a)
        for name in ("_expr", "_const"):
            setattr(reader, name, types.MethodType(getattr(_Reader, name), reader))
        load = {"e": "Load", "end": "Iend_LE", "ty": "Ity_I8",
                "addr": {"e": "Const", "con": {"ty": "Ity_I64", "value": str(0x201048)}}}
        assert reader._expr(load).addr.con.value == 0x100018
        load["addr"]["con"]["value"] = str(0x201050)
        assert reader._expr(load).addr.con.value == 0x201050


if __name__ == "__main__":
    unittest.main()

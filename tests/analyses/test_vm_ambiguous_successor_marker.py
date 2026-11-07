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

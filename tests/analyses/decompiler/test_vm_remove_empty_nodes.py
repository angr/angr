#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import Const, Register
from angr.ailment.statement import Assignment, Jump, Label
from angr.analyses.decompiler.vm_deobfuscation_simplifier import VMDeobfuscationSimplifierMixin


def _goto_shell(addr, target):
    """A block reduced to nothing but a label and a jump -- what remove_all_empty_nodes hunts."""
    return Block(addr, 1, statements=[Label(addr, f"L{addr:x}"), Jump(addr + 1, Const(addr + 2, target, 64))])


def _real_block(addr):
    return Block(
        addr,
        1,
        statements=[Assignment(addr, Register(addr + 1, 16, 64), Const(addr + 2, 1, 64))],
    )


def _run(graph, entry_node_addr):
    # remove_all_empty_nodes only reads entry_node_addr off self, so a stub stands in for Clinic.
    return VMDeobfuscationSimplifierMixin.remove_all_empty_nodes(
        SimpleNamespace(entry_node_addr=entry_node_addr), graph
    )


class TestRemoveAllEmptyNodes(unittest.TestCase):
    def test_the_entry_is_never_removed(self):
        # The entry has no predecessors by definition, which the "not preds" branch would
        # otherwise read as an orphan.
        entry = _goto_shell(0x1000, 0x2000)
        body = _real_block(0x2000)
        graph = networkx.DiGraph()
        graph.add_edge(entry, body)

        out = _run(graph, (entry.addr, entry.idx))
        assert entry in out.nodes(), "the entry block was deleted as an orphan"

    def test_a_genuine_orphan_is_still_removed(self):
        # The guard must not disable the case the branch exists for.
        entry = _real_block(0x1000)
        orphan = _goto_shell(0x3000, 0x4000)
        graph = networkx.DiGraph()
        graph.add_node(entry)
        graph.add_node(orphan)

        out = _run(graph, (entry.addr, entry.idx))
        assert entry in out.nodes()
        assert orphan not in out.nodes(), "an unreachable goto shell should still be removed"


if __name__ == "__main__":
    unittest.main()

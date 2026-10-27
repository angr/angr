#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import Const, Phi, Register, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label
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


def _vvar(varid):
    return VirtualVariable(varid, varid, 64, VirtualVariableCategory.REGISTER, oident=16)


def _phi_block(addr, sources):
    phi = Phi(addr + 1, 64, [((a, 0), _vvar(v)) for a, v in sources])
    return Block(addr, 1, statements=[Assignment(addr, _vvar(100), phi)])


def _phi_sources(block):
    return sorted((src[0], vvar.varid) for src, vvar in block.statements[0].src.src_and_vvars)


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

    def test_phi_sources_follow_a_removed_node(self):
        # entry -> shell -> join: join's phi named the shell, so it must name the entry afterwards
        entry = Block(0x1000, 1, statements=[Jump(0x1001, Const(0x1002, 0x2000, 64))])
        shell = _goto_shell(0x2000, 0x3000)
        join = _phi_block(0x3000, [(0x2000, 1)])
        graph = networkx.DiGraph()
        graph.add_edge(entry, shell)
        graph.add_edge(shell, join)

        out = _run(graph, (entry.addr, entry.idx))
        assert shell not in out.nodes()
        assert _phi_sources(join) == [(0x1000, 1)]

    def test_a_shell_separating_two_phi_values_is_kept(self):
        # branch -> shell -> join and branch -> join carry different values into join's phi; merging the
        # two edges would lose one of them
        branch = Block(
            0x1000,
            1,
            statements=[
                ConditionalJump(0x1001, Const(0x1002, 1, 1), Const(0x1003, 0x2000, 64), Const(0x1004, 0x3000, 64))
            ],
        )
        shell = _goto_shell(0x2000, 0x3000)
        join = _phi_block(0x3000, [(0x2000, 1), (0x1000, 2)])
        graph = networkx.DiGraph()
        graph.add_edge(branch, shell)
        graph.add_edge(shell, join)
        graph.add_edge(branch, join)

        out = _run(graph, (branch.addr, branch.idx))
        assert shell in out.nodes()
        assert _phi_sources(join) == [(0x1000, 2), (0x2000, 1)]


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import networkx

from angr import claripy
from angr.ailment import Block
from angr.ailment.expression import Const
from angr.ailment.manager import Manager
from angr.ailment.statement import ConditionalJump, Jump, Return
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.optimization_passes.deadblock_remover import DeadblockRemover
from tests.common import bin_location, load_project_with_scoped_cfg

# sub_4029f0's entry block ends in a conditional jump whose condition is the constant 1, so the
# other out-edge carries the condition False and the two blocks behind it are unreachable. Its
# entry block is the graph's only source, which is the case the pass is able to judge.
FFS_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "ffs")
FFS_FUNC = 0x4029F0
FFS_DEAD = (0x402A03, 0x402A0F)
FFS_SURVIVING = (0x4029F0, 0x402A18)


class TestDeadblockRemover(unittest.TestCase):
    def test_blocks_behind_a_folded_condition_are_removed(self):
        """
        The pass still does its job where the entry block is the head of the graph: the two blocks
        behind the False edge go, and the entry block stays.
        """
        proj, cfg = load_project_with_scoped_cfg(FFS_BIN, FFS_FUNC)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[FFS_FUNC], cfg=cfg.model)

        assert dec.clinic is not None and dec.clinic.graph is not None
        addrs = {block.addr for block in dec.clinic.graph}
        for addr in FFS_DEAD:
            assert addr not in addrs
        assert addrs == set(FFS_SURVIVING)

    def test_the_pass_leaves_a_graph_it_cannot_judge_alone(self):
        """
        A function whose entry block has a predecessor: the graph's head is then another block, so
        the reaching conditions are reachability from that block and the entry's own comes out
        False. Removing it on that basis leaves the function with no entry block, and
        RegionIdentifier cannot structure it.
        """
        proj, cfg = load_project_with_scoped_cfg(FFS_BIN, FFS_FUNC)
        func = cfg.functions[FFS_FUNC]
        manager = Manager()

        head_addr, sink_addr = func.addr, func.addr + 0x40
        gate_addr, entry_addr = func.addr + 0x80, func.addr + 0xC0

        # the condition is the constant 1, as the simplifier leaves it on the public fixture above,
        # so the edge to gate_addr carries False and everything behind it is unreachable from head
        head = Block(
            head_addr,
            4,
            statements=[
                ConditionalJump(
                    manager.next_atom(),
                    Const(manager.next_atom(), 1, 1),
                    Const(manager.next_atom(), sink_addr, proj.arch.bits),
                    Const(manager.next_atom(), gate_addr, proj.arch.bits),
                    ins_addr=head_addr,
                )
            ],
        )
        gate = Block(
            gate_addr,
            4,
            statements=[
                Jump(manager.next_atom(), Const(manager.next_atom(), entry_addr, proj.arch.bits), ins_addr=gate_addr)
            ],
        )
        entry = Block(
            entry_addr,
            4,
            statements=[
                Jump(manager.next_atom(), Const(manager.next_atom(), sink_addr, proj.arch.bits), ins_addr=entry_addr)
            ],
        )
        sink = Block(sink_addr, 4, statements=[Return(manager.next_atom(), [], ins_addr=sink_addr)])

        graph = networkx.DiGraph()
        graph.add_edges_from([(head, sink), (head, gate), (gate, entry), (entry, sink)])

        # the shape the docstring claims, and the condition that makes the pass act at all
        assert networkx.is_directed_acyclic_graph(graph)
        assert [node for node in graph if graph.in_degree(node) == 0] == [head]
        assert graph.in_degree(entry) == 1
        cond_proc = ConditionProcessor(proj.arch, manager)
        cond_proc.recover_reaching_conditions(region=None, graph=graph, simplify_conditions=False)
        assert claripy.is_false(cond_proc.reaching_conditions[entry])

        pass_ = DeadblockRemover(func, manager, graph=graph, entry_node_addr=(entry_addr, None))

        assert pass_.out_graph is None
        assert {block.addr for block in graph} == {head_addr, gate_addr, entry_addr, sink_addr}


if __name__ == "__main__":
    unittest.main()

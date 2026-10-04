#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import networkx

import angr
from angr.ailment import Block
from angr.ailment.constant import UNDETERMINED_SIZE
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Load,
    Register,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Return, Store, WeakAssignment
from angr.analyses.decompiler.optimization_passes import (
    DetermineLoadSizes,
    FlipBooleanCmp,
    ITERegionConverter,
    ReturnDeduplicator,
)
from angr.analyses.decompiler.structurer_nodes import ConditionNode, SequenceNode
from tests.common import bin_location

log = logging.getLogger(__name__)
# log.setLevel(logging.DEBUG)


def c(v):
    """Simple AIL Const shorthand"""
    return Const(0, v, 32)


def r(o):
    """Simple AIL Register shorthand"""
    return Register(0, o, 32)


class TestFlipBooleanCmp(unittest.TestCase):
    """
    Test FlipBooleanCmp optimization pass.
    """

    def test_type2_store_not_moved(self):
        """
        Ensure that:

            v0 = 123;
            if (v0 <= 1000)
                v0 = 456;
            g_deadbeef = v0;
            return;

        is not mistakenly transformed to:

            v0 = 123;
            if (v0 > 1000) {
                g_deadbeef = v0;
                return;
            }
            v0 = 456;
        """
        flip_size = 1

        block_0 = Block(
            0x400000,
            1,
            statements=[
                Assignment(0, r(0), c(0x123)),
                ConditionalJump(
                    1, BinaryOp(2, "CmpLE", [r(0), c(0x1000)], False), c(0x400023), c(0x400037), ins_addr=0x400001
                ),
            ],
        )
        block_1 = Block(0x400023, 1, statements=[Assignment(3, r(0), c(0x456)) for _ in range(flip_size)])
        block_2 = Block(
            0x400037,
            1,
            statements=[
                Store(4, c(0xDEADBEEF), r(0), 4, "Iend_LE"),  # Must not be moved
                Return(5, []),
            ],
        )

        graph = networkx.DiGraph()
        graph.add_edges_from([(block_0, block_1), (block_0, block_2), (block_1, block_2)])

        func = None
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        ri = proj.analyses.RegionIdentifier(func, graph=graph)
        rs = proj.analyses.RecursiveStructurer(ri.region, ail_manager=Manager())
        seq = rs.result

        assert isinstance(seq, SequenceNode)
        assert len(seq.nodes) == 3
        assert isinstance(seq.nodes[0], Block)
        assert isinstance(seq.nodes[1], ConditionNode)
        assert isinstance(seq.nodes[2], Block)
        assert isinstance(seq.nodes[2].statements[0], Store)
        assert isinstance(seq.nodes[2].statements[1], Return)

        pre_transform_seq_repr = seq.dbg_repr()
        log.debug("Before:\n%s", pre_transform_seq_repr)

        manager = Manager()
        FlipBooleanCmp(func, manager, flip_size=flip_size, seq=seq, graph=graph)

        post_transform_seq_repr = seq.dbg_repr()
        log.debug("After:\n%s", post_transform_seq_repr)

        assert pre_transform_seq_repr == post_transform_seq_repr

    def test_type2_call_not_moved(self):
        """
        Ensure that:

            v0 = 123;
            if (v0 <= 1000)
                v0 = 456;
            always_called(v0);
            return;

        is not mistakenly transformed to:

            v0 = 123;
            if (v0 > 1000) {
                always_called(v0);
                return;
            }
            v0 = 456;
        """
        flip_size = 1

        block_0 = Block(
            0x400000,
            1,
            statements=[
                Assignment(0, r(0), c(0x123)),
                ConditionalJump(
                    1, BinaryOp(2, "CmpLE", [r(0), c(0x1000)], False), c(0x400023), c(0x400037), ins_addr=0x400001
                ),
            ],
        )
        block_1 = Block(0x400023, 1, [Assignment(3, r(0), c(0x456)) for _ in range(flip_size)])
        block_2 = Block(
            0x400037,
            1,
            statements=[
                Call(4, "always_called", [r(0)]),  # Must not be moved
                Return(5, []),
            ],
        )

        graph = networkx.DiGraph()
        graph.add_edges_from([(block_0, block_1), (block_0, block_2), (block_1, block_2)])

        func = None
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        ri = proj.analyses.RegionIdentifier(func, graph=graph)
        rs = proj.analyses.RecursiveStructurer(ri.region, ail_manager=Manager())
        seq = rs.result

        assert isinstance(seq, SequenceNode)
        assert len(seq.nodes) == 3
        assert isinstance(seq.nodes[0], Block)
        assert isinstance(seq.nodes[1], ConditionNode)
        assert isinstance(seq.nodes[2], Block)
        assert isinstance(seq.nodes[2].statements[0], Call)
        assert isinstance(seq.nodes[2].statements[1], Return)

        pre_transform_seq_repr = seq.dbg_repr()
        log.debug("Before:\n%s", pre_transform_seq_repr)

        manager = Manager()
        FlipBooleanCmp(func, manager, flip_size=flip_size, seq=seq, graph=graph)

        post_transform_seq_repr = seq.dbg_repr()
        log.debug("After:\n%s", post_transform_seq_repr)

        assert pre_transform_seq_repr == post_transform_seq_repr


class TestDetermineLoadSizes(unittest.TestCase):
    """
    Test DetermineLoadSizes optimization pass.
    """

    STRING_ADDR = 0x400000

    def _make_project_and_func(self):
        proj = angr.load_shellcode(b"hello\x00", "AMD64", load_address=self.STRING_ADDR)
        return proj, proj.kb.functions.function(addr=self.STRING_ADDR, create=True)

    @staticmethod
    def _run(func, graph) -> Block:
        DetermineLoadSizes(func, Manager(), graph=graph)
        return next(iter(graph.nodes))

    def test_string_load_size_is_determined(self):
        # v0 =w *(0x400000) with an undetermined size is the string at 0x400000
        proj, func = self._make_project_and_func()
        vvar = VirtualVariable(0, 0, 64, VirtualVariableCategory.REGISTER, oident=16)
        load = Load(1, Const(2, self.STRING_ADDR, 64), UNDETERMINED_SIZE, "Iend_LE")
        graph = networkx.DiGraph()
        graph.add_node(
            Block(self.STRING_ADDR, 1, statements=[WeakAssignment(0, vvar, load, ins_addr=self.STRING_ADDR)])
        )

        stmt = self._run(func, graph).statements[0]
        assert isinstance(stmt, WeakAssignment)
        assert isinstance(stmt.src, Load)
        assert stmt.src.size == len(proj.loader.memory.load_null_terminated_bytes(self.STRING_ADDR))

    def test_string_load_size_is_determined_in_addition(self):
        # the C++ operator+ rewrite puts the load inside an addition
        proj, func = self._make_project_and_func()
        vvar = VirtualVariable(0, 0, 64, VirtualVariableCategory.REGISTER, oident=16)
        load = Load(1, Const(2, self.STRING_ADDR, 64), UNDETERMINED_SIZE, "Iend_LE")
        addition = BinaryOp(3, "Add", [vvar, load], False)
        graph = networkx.DiGraph()
        graph.add_node(
            Block(self.STRING_ADDR, 1, statements=[WeakAssignment(0, vvar, addition, ins_addr=self.STRING_ADDR)])
        )

        stmt = self._run(func, graph).statements[0]
        assert isinstance(stmt, WeakAssignment)
        assert isinstance(stmt.src, BinaryOp)
        assert isinstance(stmt.src.operands[1], Load)
        assert stmt.src.operands[1].size == len(proj.loader.memory.load_null_terminated_bytes(self.STRING_ADDR))

    def test_load_from_unmapped_address_is_left_alone(self):
        _, func = self._make_project_and_func()
        vvar = VirtualVariable(0, 0, 64, VirtualVariableCategory.REGISTER, oident=16)
        load = Load(1, Const(2, 0x800000, 64), UNDETERMINED_SIZE, "Iend_LE")
        graph = networkx.DiGraph()
        graph.add_node(
            Block(self.STRING_ADDR, 1, statements=[WeakAssignment(0, vvar, load, ins_addr=self.STRING_ADDR)])
        )

        stmt = self._run(func, graph).statements[0]
        assert isinstance(stmt, WeakAssignment)
        assert isinstance(stmt.src, Load)
        assert stmt.src.size == UNDETERMINED_SIZE


class TestConditionalJumpWithNonConstTarget(unittest.TestCase):
    """
    Test that a ConditionalJump whose target is not a Const does not abort the two region-matching
    passes that read those targets.
    """

    # ARMEL, so this is an architecture both passes declare. The project only hosts the analyses;
    # the hand-built graph below is the subject.
    HOST = os.path.join(bin_location, "tests", "armel", "fauxware")

    HEAD = 0x412248
    THEN = 0x412300
    TAIL = 0x412400
    TABLE = 0x412340

    def _dispatch_graph(self):
        """
        The graph ARM's conditional jump-table dispatch produces:

            cmp     r3, #6
            ldrls   pc, [pc, r3, lsl #2]

        One instruction both bounds the index and writes pc, so the taken target is not an address
        but a choice between the table entry and what pc already held. Lifted, that is a
        ConditionalJump whose true_target is an ITE: present, and not a Const.
        """
        index = VirtualVariable(0, 1, 32, VirtualVariableCategory.REGISTER, oident=12)
        fallthrough = VirtualVariable(1, 2, 32, VirtualVariableCategory.REGISTER, oident=68)
        cond = BinaryOp(2, "CmpLE", [index, c(6)], False)
        table_entry = Load(
            3,
            BinaryOp(4, "Add", [c(self.TABLE), BinaryOp(5, "Mul", [index, c(4)], False)], False),
            4,
            "Iend_LE",
        )
        head = Block(
            self.HEAD,
            12,
            statements=[
                ConditionalJump(7, cond, ITE(6, cond, table_entry, fallthrough), c(self.TAIL), ins_addr=self.HEAD + 0xC)
            ],
        )
        then_block = Block(
            self.THEN,
            8,
            statements=[Assignment(8, r(0), c(1)), Jump(9, c(self.TAIL), ins_addr=self.THEN + 4)],
        )
        tail = Block(self.TAIL, 4, statements=[Return(10, [])])
        graph = networkx.DiGraph()
        graph.add_edges_from([(head, then_block), (head, tail), (then_block, tail)])
        return graph, head

    def _run_pass(self, pass_cls):
        proj = angr.Project(self.HOST, auto_load_libs=False)
        func = proj.kb.functions.function(addr=proj.entry, create=True)
        graph, head = self._dispatch_graph()
        nodes_before = set(graph.nodes())
        opt = pass_cls(func, Manager(), graph=graph, entry_node_addr=(self.HEAD, None))
        # no region can match a target that is not an address, so the pass leaves the graph alone
        assert opt.out_graph is None
        assert set(graph.nodes()) == nodes_before
        last_stmt = head.statements[-1]
        assert isinstance(last_stmt, ConditionalJump)
        assert not isinstance(last_stmt.true_target, Const)
        assert isinstance(last_stmt.false_target, Const)

    def test_ite_region_converter_skips_non_const_target(self):
        self._run_pass(ITERegionConverter)

    def test_return_deduplicator_skips_non_const_target(self):
        self._run_pass(ReturnDeduplicator)


if __name__ == "__main__":
    unittest.main()

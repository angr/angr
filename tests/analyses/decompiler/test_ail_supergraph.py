# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest

import networkx

from angr.ailment import Block
from angr.ailment.expression import Call, Const
from angr.ailment.statement import Jump, Label, Return, SideEffectStatement
from angr.analyses.decompiler.utils import to_ail_supergraph


def _label(addr):
    return Label(0, f"LABEL_{addr:x}", ins_addr=addr, block_idx=None)


def _call(addr, name):
    return SideEffectStatement(0, Call(0, name, args=[], bits=64), ins_addr=addr)


class TestAILSupergraph(unittest.TestCase):
    def test_a_pair_joined_backwards_keeps_control_flow_order(self):
        # The KnownPatternOutliner numbers the blocks it splits off in the order
        # it creates them, so a block split *twice* ends up as a chain whose
        # later links carry lower addresses than earlier ones:
        #
        #     head(0x400100) -> length(0x400208) -> load(0x400209) -> empty(0x400200) -> if(0x400201)
        #
        # Merging the chain by address instead of by edge used to put `if` in
        # the middle of the merged block and DuplicationReverter then crashed on
        # the block's last statement (189 corpus functions). The predecessor's
        # statements come first, whatever the addresses say.
        head = Block(0x400100, 4, statements=[_label(0x400100), _call(0x400100, "head")])
        length = Block(0x400208, 0, statements=[_call(0x400208, "std::string::length")])
        load = Block(0x400209, 0, statements=[_call(0x400209, "load")])
        empty = Block(0x400200, 0, statements=[_call(0x400200, "std::string::empty")])
        tail = Block(0x400201, 0, statements=[Return(0, [], ins_addr=0x400201)])
        graph = networkx.DiGraph()
        for a, b in ((head, length), (length, load), (load, empty), (empty, tail)):
            graph.add_edge(a, b)

        merged = to_ail_supergraph(graph, allow_fake=True)
        assert len(merged.nodes) == 1
        (node,) = merged.nodes
        names = [stmt.expr.target for stmt in node.statements if isinstance(stmt, SideEffectStatement)]
        assert names == ["head", "std::string::length", "load", "std::string::empty"]
        assert isinstance(node.statements[-1], Return)
        # the merged block is entered where the chain was entered
        assert node.addr == 0x400100

    def test_a_fall_through_pair_is_unchanged(self):
        a = Block(0x400100, 4, statements=[_label(0x400100), Jump(0, Const(1, 0x400104, 64), ins_addr=0x400100)])
        b = Block(0x400104, 1, statements=[_label(0x400104), Return(0, [], ins_addr=0x400104)])
        graph = networkx.DiGraph()
        graph.add_edge(a, b)
        merged = to_ail_supergraph(graph)
        (node,) = merged.nodes
        assert node.addr == 0x400100
        # the jump in the middle goes, the return stays last
        assert not any(isinstance(s, Jump) for s in node.statements)
        assert isinstance(node.statements[-1], Return)


if __name__ == "__main__":
    unittest.main()

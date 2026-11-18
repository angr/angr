#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from collections import OrderedDict

from angr import ailment
from angr.analyses.decompiler.structurer_nodes import (
    CodeNode,
    IncompleteSwitchCaseNode,
    LoopNode,
    SequenceNode,
    SwitchCaseNode,
)
from angr.analyses.decompiler.utils import holds_incomplete_switch_case


class TestHoldsIncompleteSwitchCase(unittest.TestCase):
    """PhoenixStructurer cannot rebuild a jump table switch out of the graph while the dispatch is still folded
    into an IncompleteSwitchCaseNode, and that node reaches the schema wrapped in whatever the enclosing region
    produced. holds_incomplete_switch_case() is what lets the schema see through those wrappers."""

    @staticmethod
    def _block(addr):
        return ailment.Block(addr, 4, statements=[])

    def _incomplete(self, addr=0x400000):
        return IncompleteSwitchCaseNode(addr, self._block(addr), [self._block(addr + 0x10)])

    def test_the_node_itself(self):
        assert holds_incomplete_switch_case(self._incomplete()) is True

    def test_wrapped_in_a_loop_over_a_sequence(self):
        # the shape a nested switch produces: the dispatch address is a do-while loop whose body sequence holds
        # the incomplete switch-case, and every node carries the jump table address
        incomplete = self._incomplete()
        loop = LoopNode("do-while", None, SequenceNode(0x400000, nodes=[incomplete]), addr=0x400000)
        assert holds_incomplete_switch_case(loop) is True

    def test_wrapped_in_a_code_node(self):
        assert holds_incomplete_switch_case(CodeNode(self._incomplete(), None)) is True

    def test_not_a_bare_block(self):
        assert holds_incomplete_switch_case(self._block(0x400000)) is False

    def test_not_a_sequence_of_blocks(self):
        seq = SequenceNode(0x400000, nodes=[self._block(0x400000), self._block(0x400010)])
        assert holds_incomplete_switch_case(seq) is False

    def test_not_an_already_structured_switch_case(self):
        # the sibling guard in _match_acyclic_switch_cases_address_loaded_from_memory covers this shape, and
        # this predicate must not also claim it
        cases: OrderedDict[int | tuple[int, ...], SequenceNode] = OrderedDict(
            {0: SequenceNode(0x400010, nodes=[self._block(0x400010)])}
        )
        switch = SwitchCaseNode(None, cases, None, addr=0x400000)
        assert holds_incomplete_switch_case(switch) is False

    def test_a_cycle_terminates(self):
        seq = SequenceNode(0x400000, nodes=[self._block(0x400000)])
        seq.nodes.append(seq)
        assert holds_incomplete_switch_case(seq) is False

    def test_none(self):
        assert holds_incomplete_switch_case(None) is False


if __name__ == "__main__":
    unittest.main()

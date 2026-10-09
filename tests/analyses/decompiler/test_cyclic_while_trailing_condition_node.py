#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const, Register
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.structurer_nodes import ConditionNode, MultiNode, SequenceNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from angr.analyses.decompiler.structuring.structurer_base import StructurerBase


class TestCyclicWhileTrailingConditionNode(unittest.TestCase):
    """
    _match_cyclic_while() asks _find_node_going_to_dst() which node holds the jump to the loop body, calls
    _remove_last_statement_if_jump() to take that jump out, and asserts it got a statement back. The two disagreed
    about a SequenceNode ending in a ConditionNode: the search accepted one whose branches end in a
    ConditionalJump, which the removal can do nothing with because dropping that ConditionNode would drop real
    code. It returned None and the assertion fired with no message.
    """

    DST = 0x401A20
    HEAD = 0x401A00
    TRUE_BRANCH = 0x401A10
    FALSE_BRANCH = 0x401A18

    def _dst_block(self, m: Manager) -> Block:
        return Block(
            self.DST,
            1,
            statements=[Jump(m.next_atom(), Const(m.next_atom(), self.DST + 1, 32), ins_addr=self.DST)],
        )

    def _branch(self, m: Manager, addr: int, terminal: str) -> Block:
        if terminal == "jump":
            # the goto pair cyclic refinement creates: dropping the ConditionNode drops this jump
            last = Jump(m.next_atom(), Const(m.next_atom(), self.DST, 32), ins_addr=addr)
        else:
            # a structured if-else branch that ends by branching; nothing here can be dropped on its own
            last = ConditionalJump(
                m.next_atom(),
                Register(m.next_atom(), 16, 32),
                Const(m.next_atom(), self.DST, 32),
                Const(m.next_atom(), self.DST + 0x10, 32),
                ins_addr=addr,
            )
        return Block(addr, 1, statements=[last])

    def _sequence(self, m: Manager, terminal: str) -> tuple[SequenceNode, ConditionNode]:
        head = Block(
            self.HEAD,
            1,
            statements=[Jump(m.next_atom(), Const(m.next_atom(), self.TRUE_BRANCH, 32), ins_addr=self.HEAD)],
        )
        cond_node = ConditionNode(
            self.TRUE_BRANCH,
            None,
            Register(m.next_atom(), 16, 32),
            self._branch(m, self.TRUE_BRANCH, terminal),
            false_node=self._branch(m, self.FALSE_BRANCH, terminal),
        )
        return SequenceNode(self.HEAD, nodes=[head, cond_node]), cond_node

    @staticmethod
    def _jump_comes_out(found) -> bool:
        """Whether _match_cyclic_while() could take the jump out of what the search returned."""
        assert isinstance(found, (Block, MultiNode, SequenceNode)), (
            f"_find_node_going_to_dst() returned a {type(found).__name__}, which "
            "_remove_last_statement_if_jump() does not take"
        )
        return StructurerBase._remove_last_statement_if_jump(found) is not None

    def test_sequence_ending_in_a_goto_pair_is_claimed_and_the_jump_comes_out(self):
        m = Manager()
        seq, cond_node = self._sequence(m, "jump")

        _, _, found = PhoenixStructurer._find_node_going_to_dst(seq, self._dst_block(m), condjump_only=True)

        assert found is seq
        assert self._jump_comes_out(found)
        assert cond_node not in seq.nodes

    def test_sequence_ending_in_a_conditional_jump_pair_is_never_handed_over_unstrippable(self):
        m = Manager()
        seq, _ = self._sequence(m, "condjump")

        _, _, found = PhoenixStructurer._find_node_going_to_dst(seq, self._dst_block(m), condjump_only=True)

        assert found is None or self._jump_comes_out(found), (
            "_find_node_going_to_dst() returned a node whose jump _remove_last_statement_if_jump() cannot take "
            "out; _match_cyclic_while() asserts on exactly that"
        )

    def test_trailing_condition_node_jump_tells_the_two_shapes_apart(self):
        m = Manager()
        goto_pair, _ = self._sequence(m, "jump")
        real_code, _ = self._sequence(m, "condjump")

        assert StructurerBase._trailing_condition_node_jump(goto_pair) is not None
        assert StructurerBase._trailing_condition_node_jump(real_code) is None


if __name__ == "__main__":
    unittest.main()

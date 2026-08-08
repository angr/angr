#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.structurer_nodes import ContinueNode, LoopNode, SequenceNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

LATCH_ADDR = 0x200


def _loop_body_with(stmt, arch=None):
    """A do-while whose latch at LATCH_ADDR was folded into its condition, with stmt somewhere in its body.

    The statement is kept off the body's tail on purpose: a continue at the very end of a do-while body is redundant
    and gets dropped again, which would hide what we are testing.
    """
    m = Manager(arch=arch)
    block = Block(0x110, 1, statements=[stmt])
    inner = SequenceNode(0x110, nodes=[block])
    loop_seq = SequenceNode(0x100, nodes=[inner, Block(0x180, 1, statements=[])])
    loop_node = LoopNode("do-while", Const(m.next_atom(), 1, 8), loop_seq, addr=0x100, continue_addr=LATCH_ADDR)
    return block, inner, loop_seq, loop_node


def _continue_nodes(node, out=None):
    if out is None:
        out = []
    if isinstance(node, ContinueNode):
        out.append(node)
    for attr in ("nodes", "node", "sequence_node", "true_node", "false_node"):
        child = getattr(node, attr, None)
        if isinstance(child, list):
            for c in child:
                _continue_nodes(c, out)
        elif child is not None:
            _continue_nodes(child, out)
    return out


def _loop_nodes(node, out=None):
    """Collect every LoopNode in a structured tree."""
    if out is None:
        out = []
    if isinstance(node, LoopNode):
        out.append(node)
    for attr in ("nodes", "node", "sequence_node", "true_node", "false_node", "else_node", "default_node", "head"):
        child = getattr(node, attr, None)
        if isinstance(child, list):
            for c in child:
                _loop_nodes(c, out)
        elif child is not None:
            _loop_nodes(child, out)
    cases = getattr(node, "cases", None)
    if isinstance(cases, dict):
        for c in cases.values():
            _loop_nodes(c, out)
    elif isinstance(cases, list):
        for c in cases:
            _loop_nodes(c, out)
    for _, c in getattr(node, "condition_and_nodes", None) or ():
        _loop_nodes(c, out)
    return out


class TestDoWhileLatchContinue(unittest.TestCase):
    def test_jump_to_folded_latch_becomes_continue(self):
        """
        A do-while's latch stops being a node of its own once Phoenix folds its condition into the loop condition, so
        jumps to it have to become continues. Anything left behind is emitted as a goto to a label that no longer
        exists anywhere in the function.
        """
        m = Manager(arch=None)
        jump = Jump(m.next_atom(), Const(m.next_atom(), LATCH_ADDR, 64), ins_addr=0x110)
        block, inner, loop_seq, loop_node = _loop_body_with(jump)

        # this path of _rewrite_jumps_to_continues() reads no instance state, so a bare structurer can drive it
        structurer = object.__new__(PhoenixStructurer)
        structurer._rewrite_jumps_to_continues(loop_seq, loop_node=loop_node)

        continues = _continue_nodes(inner)
        assert len(continues) == 1
        assert continues[0].target == LATCH_ADDR
        # the jump must be consumed, not left behind next to the continue
        assert not block.statements

    def test_conditional_jump_to_folded_latch_becomes_continue(self):
        """
        The shape this actually broke on: one branch of a conditional jump goes to the folded latch. It has to split
        into a condition guarding the other target plus a continue.
        """
        arch = archinfo.arch_from_id("amd64")
        m = Manager(arch=arch)
        condition = BinaryOp(
            m.next_atom(), "CmpEQ", [Register(m.next_atom(), 16, 64), Const(m.next_atom(), 0, 64)], False
        )
        condjump = ConditionalJump(
            m.next_atom(),
            condition,
            Const(m.next_atom(), LATCH_ADDR, 64),
            Const(m.next_atom(), 0x300, 64),
            ins_addr=0x110,
        )
        block, inner, loop_seq, loop_node = _loop_body_with(condjump, arch=arch)

        structurer = object.__new__(PhoenixStructurer)
        structurer.cond_proc = ConditionProcessor(arch, m)
        structurer._rewrite_jumps_to_continues(loop_seq, loop_node=loop_node)

        continues = _continue_nodes(inner)
        assert len(continues) == 1
        assert continues[0].target == LATCH_ADDR
        assert not block.statements

    def test_folded_latch_address_is_recorded(self):
        """
        The other half: Phoenix has to record the latch address on the loop node in the first place. sub_4012eb holds a
        do-while at 0x40165c whose latch at 0x4016bb is folded into the loop condition.
        """
        bin_path = os.path.join(test_location, "x86_64", "1after909")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x4012EB, expand_call_tree=False, run_ccc=False)
        dec = proj.analyses.Decompiler(0x4012EB, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        loops = {(loop.addr, loop.continue_addr) for loop in _loop_nodes(dec.seq_node) if loop.sort == "do-while"}
        assert (0x40165C, 0x4016BB) in loops


if __name__ == "__main__":
    unittest.main()

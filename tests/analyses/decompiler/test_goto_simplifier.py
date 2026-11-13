#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import Const
from angr.ailment.statement import Jump
from angr.analyses.decompiler.region_simplifiers.goto import GotoSimplifier
from angr.analyses.decompiler.structurer_nodes import SequenceNode


class TestGotoSimplifier(unittest.TestCase):
    def test_goto_to_a_block_outside_the_function_is_kept(self):
        # test eax, eax; je 0x400005; nop; ret
        project = angr.load_shellcode(b"\x85\xc0\x74\x01\x90\xc3", arch="amd64", load_address=0x400000)
        project.analyses.CFGFast(normalize=True)
        func = project.kb.functions[0x400000]
        assert 0x400005 in func.block_addrs_set
        manager = Manager()

        def goto_block(addr: int, target: int) -> Block:
            return Block(
                addr, 2, statements=[Jump(manager.next_atom(), Const(manager.next_atom(), target, 64), ins_addr=addr)]
            )

        # the target of the first goto is a block of the function that is no longer in the structured output; the
        # target of the second one is a block owned by another function (a shared tail)
        to_removed_block = goto_block(0x400000, 0x400005)
        to_foreign_block = goto_block(0x400002, 0x500000)
        seq = SequenceNode(0x400000, nodes=[to_removed_block, to_foreign_block])

        simp = GotoSimplifier(seq, function=func, kb=project.kb)

        assert to_removed_block.statements == []
        assert len(to_foreign_block.statements) == 1
        assert isinstance(to_foreign_block.statements[0], Jump)
        assert {goto.dst_addr for goto in simp.irreducible_gotos} == {0x500000}


if __name__ == "__main__":
    unittest.main()

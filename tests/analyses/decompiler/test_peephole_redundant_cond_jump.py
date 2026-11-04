#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Call, Const, Register
from angr.ailment.manager import Manager
from angr.ailment.statement import ConditionalJump, Jump, SideEffectStatement
from angr.analyses.decompiler.peephole_optimizations import (
    RemoveRedunCondJump,
    RemoveRedunCondJumpKeepCalls,
    vm_peephole_optimizations,
)
from angr.analyses.decompiler.utils import peephole_optimize_multistmts, peephole_optimize_stmts

TARGET = 0x401000


class TestRedundantCondJump(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.manager = Manager()

    def _block(self, cond, true_idx=0, false_idx=0):
        m = self.manager
        jmp = ConditionalJump(
            m.next_atom(),
            cond,
            Const(m.next_atom(), TARGET, 64),
            Const(m.next_atom(), TARGET, 64),
            true_target_idx=true_idx,
            false_target_idx=false_idx,
            ins_addr=0x400000,
        )
        return Block(0x400000, 4, statements=[jmp])

    def _call_cond(self):
        m = self.manager
        call = Call(m.next_atom(), Const(m.next_atom(), 0x500000, 64), args=[], bits=64, ins_addr=0x400000)
        return BinaryOp(m.next_atom(), "CmpEQ", [call, Const(m.next_atom(), 0, 64)], ins_addr=0x400000)

    def test_vm_only(self):
        assert RemoveRedunCondJumpKeepCalls in vm_peephole_optimizations()

    def test_plain_condition_becomes_jump(self):
        m = self.manager
        cond = BinaryOp(m.next_atom(), "CmpEQ", [Register(m.next_atom(), 16, 64), Const(m.next_atom(), 0, 64)])
        block = self._block(cond)
        stmts, _ = peephole_optimize_stmts(block, [RemoveRedunCondJump(self.proj, self.proj.kb, m)])
        assert len(stmts) == 1 and isinstance(stmts[0], Jump)

    def test_copies_at_one_address_are_different_targets(self):
        # e.g. a return duplicated into .3 and .4: the branch still decides between them
        m = self.manager
        cond = BinaryOp(m.next_atom(), "CmpEQ", [Register(m.next_atom(), 16, 64), Const(m.next_atom(), 0, 64)])
        for opt in (RemoveRedunCondJump, RemoveRedunCondJumpKeepCalls):
            block = self._block(cond if opt is RemoveRedunCondJump else self._call_cond(), 3, 4)
            run = peephole_optimize_stmts if opt is RemoveRedunCondJump else peephole_optimize_multistmts
            stmts, updated = run(block, [opt(self.proj, self.proj.kb, m)])
            assert not updated and isinstance(stmts[-1], ConditionalJump)

    def test_call_in_condition_is_kept(self):
        m = self.manager
        block = self._block(self._call_cond())
        # the single-statement form must not drop the call
        stmts, updated = peephole_optimize_stmts(block, [RemoveRedunCondJump(self.proj, self.proj.kb, m)])
        assert not updated and isinstance(stmts[0], ConditionalJump)
        stmts, updated = peephole_optimize_multistmts(block, [RemoveRedunCondJumpKeepCalls(self.proj, self.proj.kb, m)])
        assert updated
        assert len(stmts) == 2 and isinstance(stmts[0], SideEffectStatement) and isinstance(stmts[1], Jump)
        assert isinstance(stmts[0].expr, Call) and stmts[0].expr.target.value == 0x500000
        assert stmts[1].target.value == TARGET


if __name__ == "__main__":
    unittest.main()

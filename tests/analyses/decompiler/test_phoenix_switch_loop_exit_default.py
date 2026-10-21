#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Return
from angr.analyses.decompiler.structurer_nodes import IncompleteSwitchCaseHeadStatement
from angr.analyses.decompiler.structuring import SAILRStructurer
from angr.analyses.decompiler.utils import sequence_to_blocks


class TestPhoenixSwitchLoopExitDefault(unittest.TestCase):
    def setUp(self):
        self.project = angr.load_shellcode(b"\xc3", arch="AMD64", load_address=0x400000)
        self.cfg = self.project.analyses.CFGFast()
        self.func = self.cfg.functions[0x400000]
        self.manager = Manager()

    def _const(self, value, bits=32):
        return Const(self.manager.next_atom(), value, bits)

    def _reg(self, offset):
        return Register(self.manager.next_atom(), offset, 32)

    def _cmp(self, op, reg, value):
        return BinaryOp(self.manager.next_atom(), op, [self._reg(reg), self._const(value)], False, bits=1)

    def _cond_block(self, addr, cond, true_addr, false_addr, *, before=()):
        jump = ConditionalJump(
            self.manager.next_atom(), cond, self._const(true_addr, 64), self._const(false_addr, 64), ins_addr=addr
        )
        return Block(addr, 4, statements=[*before, jump])

    def _assign(self, addr, reg, value):
        return Assignment(self.manager.next_atom(), self._reg(reg), self._const(value), ins_addr=addr)

    def _ret(self, addr, value):
        return Block(addr, 4, statements=[Return(self.manager.next_atom(), [self._const(value)], ins_addr=addr)])

    def _structure(self, graph, head, structurer_cls=SAILRStructurer):
        ri = self.project.analyses.RegionIdentifier(
            self.func,
            graph=graph,
            entry_node_addr=(head.addr, head.idx),
            ail_manager=self.manager,
            force_loop_single_exit=False,
            expose_loop_head_backedges=True,
        )
        rs = self.project.analyses.RecursiveStructurer(
            ri.region, cond_proc=ri.cond_proc, ail_manager=self.manager, func=self.func, structurer_cls=structurer_cls
        )
        assert rs.result is not None
        assert not rs.result_incomplete, rs.structuring_failures
        return rs

    def test_switch_in_loop_body_with_the_loop_exit_as_default(self):
        # while (getline() != -1) { r = check(); switch (r) { case -46: continue; case 0: return 0; default: goto
        # X; } } X: ... the head of the loop exits to X as well. the switch schema took the loop head for a case
        # entry (its "continue" case targets it) and absorbed X as the default node, dropping the head's exit;
        # and the head's edge to the loop head, now a goto-case, kept the body from forming a loop with the switch.
        head = self._cond_block(
            0x400000, self._cmp("CmpEQ", 8, 0xFFFFFFFF), 0x400040, 0x400010, before=[self._assign(0x400000, 8, 1)]
        )
        body_cmp = self._assign(0x400010, 16, 2)
        switch_head = Block(0x400010, 4, statements=[body_cmp])
        switch_stmt = IncompleteSwitchCaseHeadStatement(
            self.manager.next_atom(),
            self._reg(16),
            [
                (switch_head, 0xFFFFFFD2, 0x400000, 0, 0x400020),
                (switch_head, 0, 0x400030, 0, 0x400040),
                (switch_head, "default", 0x400040, 0, None),
            ],
            ins_addr=0x400010,
        )
        switch_head.statements.append(switch_stmt)
        ret0 = self._ret(0x400030, 0)
        exit_check = self._cond_block(
            0x400040, self._cmp("CmpNE", 24, 0), 0x400050, 0x400060, before=[self._assign(0x400040, 24, 3)]
        )
        ret_err = self._ret(0x400050, 1)
        ret_val = self._ret(0x400060, 2)
        graph = networkx.DiGraph(
            [
                (head, exit_check),
                (head, switch_head),
                (switch_head, head),
                (switch_head, ret0),
                (switch_head, exit_check),
                (exit_check, ret_err),
                (exit_check, ret_val),
            ]
        )
        rs = self._structure(graph, head)
        blocks = sequence_to_blocks(rs.result)
        missing = [hex(b.addr) for b in graph.nodes if b not in blocks]
        assert not missing, missing
        # the exit code is emitted once, reached through the loop condition and the switch's default goto
        assert blocks.count(exit_check) == 1
        gotos = [
            s
            for block in blocks
            for s in block.statements
            if isinstance(s, Jump) and isinstance(s.target, Const) and s.target.value == exit_check.addr
        ]
        assert len(gotos) == 1


if __name__ == "__main__":
    unittest.main()

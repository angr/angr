#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.statement import Assignment, ConditionalJump, Return
from angr.analyses.decompiler.structuring import SAILRStructurer
from angr.analyses.decompiler.utils import sequence_to_blocks


class TestPhoenixShortCircuitSuccessor(unittest.TestCase):
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

    def test_short_circuit_does_not_absorb_a_region_successor(self):
        # while (1) { while ((r0 = read()) && r0 <= 0xfffe) { r1 = f(); if (r1) continue; <C> if (r2 > 100) break; } }
        # the body { r0 <= 0xfffe; r1 ... } is an acyclic region inside the loop whose successor C holds the second
        # test. The short-circuit schema folded C into "if (!r1 || r2 <= 100) continue; else break;" although C
        # was not a member: the loop region lost its only entry into C and could not be structured.
        head = self._cond_block(
            0x400000, self._cmp("CmpEQ", 8, 0), 0x400050, 0x400010, before=[self._assign(0x400000, 8, 1)]
        )
        bound = self._cond_block(0x400010, self._cmp("CmpGT", 8, 0xFFFE), 0x400050, 0x400020)
        body = self._cond_block(
            0x400020, self._cmp("CmpNE", 16, 0), 0x400000, 0x400030, before=[self._assign(0x400020, 16, 2)]
        )
        tail = self._cond_block(0x400030, self._cmp("CmpGT", 24, 100), 0x400050, 0x400000)
        exit_block = self._ret(0x400050, 0)
        graph = networkx.DiGraph(
            [
                (head, exit_block),
                (head, bound),
                (bound, exit_block),
                (bound, body),
                (body, head),
                (body, tail),
                (tail, exit_block),
                (tail, head),
            ]
        )
        rs = self._structure(graph, head)
        blocks = sequence_to_blocks(rs.result)
        # the bound and tail blocks are folded into conditions; the body, which assigns, must survive as a block
        assert body.addr in {b.addr for b in blocks}, [hex(b.addr) for b in blocks]


if __name__ == "__main__":
    unittest.main()

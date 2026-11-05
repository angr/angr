#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Const, Convert, Register, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.peephole_optimizations import FlagsWordBitThroughVVar
from angr.utils.ail import BlockDefs, GraphVVarDefs

from .ail_equivalence import equivalent


class TestFlagsWordBitThroughVVar(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = FlagsWordBitThroughVVar(self.proj, self.proj.kb, self.m)

    def _c(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _bin(self, op, a, b, bits=None, signed=False):
        return BinaryOp(self.m.next_atom(), op, [a, b], signed, bits=bits or a.bits)

    def _v(self, varid, off):
        return VirtualVariable(self.m.next_atom(), varid, 64, VirtualVariableCategory.REGISTER, oident=off)

    def _flag(self, cond, value):
        conv = Convert(self.m.next_atom(), 1, 64, False, cond)
        return conv if value == 1 else self._bin("Mul", conv, self._c(value))

    def _word(self, a, b, extra=None):
        """~(CF | PF-ish * 4 | ZF * 64 | SF * 128) of a + ~b, the way a VM spells it"""
        s = self._bin("Add", a, UnaryOp(self.m.next_atom(), "BitwiseNeg", b, bits=64))
        cf = self._flag(self._bin("CmpLT", s, a, 1), 1)
        pf = self._bin("Mul", self._bin("And", self._bin("Shr", self._c(38505), self._bin("And", s, self._c(15))), self._c(1)), self._c(4))
        zf = self._flag(self._bin("CmpEQ", s, self._c(0), 1), 64)
        sf = self._flag(self._bin("CmpLT", s, self._c(0), 1, signed=True), 128)
        word = self._bin("Or", self._bin("Or", self._bin("Or", cf, pf), zf), sf)
        if extra is not None:
            word = self._bin("Or", word, extra)
        return UnaryOp(self.m.next_atom(), "BitwiseNeg", word, bits=64)

    def _defs(self, word):
        a, b = self._v(1, 16), self._v(2, 24)
        flags = self._v(3, 32)
        blk = Block(0x10, 1, statements=[Assignment(self.m.next_atom(), flags, word)])
        graph = networkx.DiGraph()
        graph.add_node(blk)
        return BlockDefs((), all_defs=GraphVVarDefs(graph)), flags

    def test_carry_bit_of_a_complemented_word(self):
        a, b = self._v(1, 16), self._v(2, 24)
        word = self._word(a, b)
        bd, flags = self._defs(word)
        # (~flags & 1): bit 0 of the original word, i.e. the carry a + ~b < a
        expr = self._bin("And", UnaryOp(self.m.next_atom(), "BitwiseNeg", flags, bits=64), self._c(1))
        out = self.opt.optimize(expr, block_defs=bd)
        assert isinstance(out, Convert) and out.operand.op == "CmpLT"
        # same value once flags is replaced by its definition
        inlined = self._bin("And", UnaryOp(self.m.next_atom(), "BitwiseNeg", word, bits=64), self._c(1))
        assert equivalent(inlined, out)

    def test_zero_flag_bit_of_the_variable(self):
        a, b = self._v(1, 16), self._v(2, 24)
        word = self._word(a, b)
        bd, flags = self._defs(word)
        expr = self._bin("And", flags, self._c(64))
        out = self.opt.optimize(expr, block_defs=bd)
        assert out is not None and out.op == "Mul"
        assert equivalent(self._bin("And", word, self._c(64)), out)
        assert out.depth < word.depth

    def test_term_that_may_set_the_bit_stays(self):
        a, b = self._v(1, 16), self._v(2, 24)
        word = self._word(a, b, extra=Register(self.m.next_atom(), 40, 64))
        bd, flags = self._defs(word)
        expr = self._bin("And", flags, self._c(64))
        assert self.opt.optimize(expr, block_defs=bd) is None


if __name__ == "__main__":
    unittest.main()

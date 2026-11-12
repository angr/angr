#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr.ailment import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    ITE,
    Convert,
    Register,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, SideEffectStatement
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

    def _chain(self, *exprs):
        """v10 = exprs[0], v11 = exprs[1], ...; returns (block defs, the variables)"""
        vs = [self._v(10 + i, 48 + 8 * i) for i in range(len(exprs))]
        stmts = [Assignment(self.m.next_atom(), v, e) for v, e in zip(vs, exprs)]
        graph = networkx.DiGraph()
        graph.add_node(Block(0x10, 1, statements=stmts))
        return BlockDefs((), all_defs=GraphVVarDefs(graph)), vs

    def _neg(self, e):
        return UnaryOp(self.m.next_atom(), "BitwiseNeg", e, bits=e.bits)

    def _check(self, expr, inlined, bd):
        out = self.opt.optimize(expr, block_defs=bd)
        assert out is not None
        assert equivalent(inlined, out)
        return out

    def test_bit_through_masked_copies(self):
        a, b = self._v(1, 16), self._v(2, 24)
        word = self._word(a, b)
        v0, v1, v2 = self._v(10, 48), self._v(11, 56), self._v(12, 64)
        bd, _ = self._chain(word, self._bin("And", v0, self._c(0x8D5)), self._bin("And", self._c(0x8D5), v1))
        for k in (0, 6, 7):
            self._check(self._bin("And", v2, self._c(1 << k)), self._bin("And", word, self._c(1 << k)), bd)
        # a bit the copies mask out is a constant
        out = self._check(self._bin("And", v2, self._c(1 << 8)), self._c(0), bd)
        assert isinstance(out, Convert) or out.op == "Mul"

    def test_bit_of_a_merged_word(self):
        a, b, c = self._v(1, 16), self._v(2, 24), self._v(4, 40)
        w1, w2 = self._word(a, b), self._word(c, a)
        v0, v1, v2 = self._v(10, 48), self._v(11, 56), self._v(12, 64)
        keep = 0x815

        def merged(x, y):
            return self._bin(
                "Or", self._bin("And", self._c(keep), self._neg(x)), self._bin("And", y, self._c(~keep & (2**64 - 1)))
            )

        bd, _ = self._chain(w1, w2, merged(v0, v1))
        for k in (0, 6, 7):
            for neg in (False, True):
                read, ref = (self._neg(v2), self._neg(merged(w1, w2))) if neg else (v2, merged(w1, w2))
                self._check(self._bin("And", read, self._c(1 << k)), self._bin("And", ref, self._c(1 << k)), bd)

    def test_less_or_equal_form(self):
        a, b = self._v(1, 16), self._v(2, 24)
        word = self._word(a, b)
        v0, v1 = self._v(10, 48), self._v(11, 56)
        bd, _ = self._chain(word, self._bin("And", v0, self._c(0x8D5)))

        def le(x):
            sh = [self._bin("Shr", x, self._c(n, 8)) for n in (7, 11, 6)]
            return self._bin("And", self._bin("Or", self._bin("Xor", sh[0], sh[1]), sh[2]), self._c(1))

        out = self._check(le(v1), le(self._bin("And", word, self._c(0x8D5))), bd)
        assert out.depth < word.depth

    def test_sum_of_disjoint_words(self):
        a, b, c = self._v(1, 16), self._v(2, 24), self._v(4, 40)
        w1, w2 = self._word(a, b), self._word(c, a)
        v0, v1, v2 = self._v(10, 48), self._v(11, 56), self._v(12, 64)

        def total(x, y, m):
            return self._bin("Add", self._bin("And", x, self._c(0x15)), self._bin("And", y, self._c(m)))

        bd, _ = self._chain(w1, w2, total(v0, v1, 0xC0))
        self._check(self._bin("And", v2, self._c(128)), self._bin("And", total(w1, w2, 0xC0), self._c(128)), bd)
        self._check(self._bin("And", v2, self._c(1)), self._bin("And", total(w1, w2, 0xC0), self._c(1)), bd)
        # overlapping words carry
        bd, _ = self._chain(w1, w2, total(v0, v1, 0xC4))
        assert self.opt.optimize(self._bin("And", v2, self._c(128)), block_defs=bd) is None

    def test_two_flags_tested_at_once(self):
        a, b = self._v(1, 16), self._v(2, 24)
        word = self._word(a, b)
        bd, flags = self._defs(word)
        nflags = UnaryOp(self.m.next_atom(), "BitwiseNeg", flags, bits=64)
        nword = UnaryOp(self.m.next_atom(), "BitwiseNeg", word, bits=64)
        for op in ("CmpEQ", "CmpNE"):
            # (~flags & 0x41) ==/!= 0: neither/either of CF and ZF
            expr = self._bin(op, self._bin("And", nflags, self._c(0x41)), self._c(0), 1)
            out = self.opt.optimize(expr, block_defs=bd)
            assert out is not None and out.bits == 1
            assert equivalent(self._bin(op, self._bin("And", nword, self._c(0x41)), self._c(0), 1), out)
            assert out.depth < word.depth
        # the parity bit cannot be read as a boolean: the test stays
        expr = self._bin("CmpEQ", self._bin("And", nflags, self._c(0x45)), self._c(0), 1)
        assert self.opt.optimize(expr, block_defs=bd) is None
        # an undefined variable, and a word with no variable hop
        expr = self._bin("CmpEQ", self._bin("And", a, self._c(0x41)), self._c(0), 1)
        assert self.opt.optimize(expr, block_defs=bd) is None
        expr = self._bin("CmpEQ", self._bin("And", nword, self._c(0x41)), self._c(0), 1)
        assert self.opt.optimize(expr, block_defs=bd) is None
        # compared with a nonzero constant
        expr = self._bin("CmpEQ", self._bin("And", nflags, self._c(0x41)), self._c(0x41), 1)
        assert self.opt.optimize(expr, block_defs=bd) is None
        # one flag behind the mask (the other bit is a known zero): left to the single-bit case
        expr = self._bin("CmpEQ", self._bin("And", nflags, self._c(0x48)), self._c(0), 1)
        assert self.opt.optimize(expr, block_defs=bd) is None

    def test_refusals(self):
        a, b = self._v(1, 16), self._v(2, 24)
        word = self._word(a, b)
        v0, v1 = self._v(10, 48), self._v(11, 56)
        # shift by a variable, an undefined variable, and a word with no variable hop
        bd, _ = self._chain(word, self._bin("Shr", v0, Convert(self.m.next_atom(), 64, 8, False, a)))
        assert self.opt.optimize(self._bin("And", v1, self._c(1)), block_defs=bd) is None
        assert self.opt.optimize(self._bin("And", a, self._c(64)), block_defs=bd) is None
        assert self.opt.optimize(self._bin("And", word, self._c(64)), block_defs=bd) is None

    def test_flag_of_a_flag_stays(self):
        a, b = self._v(1, 16), self._v(2, 24)
        v0 = self._v(10, 48)
        # adc: the carry out reads the carry in
        cin = Convert(self.m.next_atom(), 1, 64, False, self._bin("CmpLT", a, b, 1))
        cout = Convert(self.m.next_atom(), 1, 64, False, self._bin("CmpLT", self._bin("Add", a, cin), b, 1))
        bd, _ = self._chain(self._bin("Or", cout, self._bin("Shl", a, self._c(1, 8))))
        assert self.opt.optimize(self._bin("And", v0, self._c(1)), block_defs=bd) is None
        bd, _ = self._chain(self._bin("Or", cin, self._bin("Shl", a, self._c(1, 8))))
        assert self.opt.optimize(self._bin("And", v0, self._c(1)), block_defs=bd) is not None

    def test_bit_of_another_word_is_not_copied(self):
        a, b = self._v(1, 16), self._v(2, 24)
        v0, w = self._v(10, 48), self._v(30, 56)
        # popfd: df = ((w >> 10) & 1) ? -1 : 1 with w unknown; reading df & 0x400 must not become a read of w
        from_w = Convert(self.m.next_atom(), 64, 1, False, self._bin("Shr", w, self._c(10, 8)))
        df = ITE(self.m.next_atom(), from_w, self._c(1), self._c(0xFFFFFFFFFFFFFFFF), bits=64)
        bd, _ = self._chain(df)
        assert self.opt.optimize(self._bin("And", v0, self._c(0x400)), block_defs=bd) is None
        bd, _ = self._chain(self._flag(self._bin("CmpNE", self._bin("And", w, self._c(0x80)), self._c(0), 1), 64))
        assert self.opt.optimize(self._bin("And", v0, self._c(64)), block_defs=bd) is None

        # ... and is read where the word is known: no variable is left in the flag
        word = UnaryOp(self.m.next_atom(), "BitwiseNeg", self._word(a, b), bits=64)
        sf_clear = self._bin("CmpEQ", self._bin("And", word, self._c(0x80)), self._c(0), 1)
        bd, _ = self._chain(self._flag(sf_clear, 64))
        out = self.opt.optimize(self._bin("And", v0, self._c(64)), block_defs=bd)
        assert out is not None
        assert equivalent(self._flag(sf_clear, 64), out)
        trunc = Convert(self.m.next_atom(), 64, 1, False, self._bin("Shr", word, self._c(7, 8)))
        bd, _ = self._chain(ITE(self.m.next_atom(), trunc, self._c(0), self._c(64), bits=64))
        out = self.opt.optimize(self._bin("And", v0, self._c(64)), block_defs=bd)
        assert out is not None
        assert equivalent(self._flag(sf_clear, 64), out)

    def test_escaped_stack_slot(self):
        a = self._v(1, 16)

        def stack(varid, off):
            return VirtualVariable(self.m.next_atom(), varid, 64, VirtualVariableCategory.STACK, oident=off)

        def read_after(escaped_off):
            # v20 = a | 1; f(&v21); v22 = v20 & 1
            ref = UnaryOp(self.m.next_atom(), "Reference", stack(21, escaped_off), bits=64)
            read = self._bin("And", stack(20, -0x20), self._c(1))
            call = Call(self.m.next_atom(), "f", args=[ref], bits=64)
            stmts = [
                Assignment(self.m.next_atom(), stack(20, -0x20), self._bin("Or", a, self._c(1))),
                SideEffectStatement(self.m.next_atom(), call),
                Assignment(self.m.next_atom(), self._v(22, 48), read),
            ]
            blk = Block(0x10, 1, statements=stmts)
            graph = networkx.DiGraph()
            graph.add_node(blk)
            bd = BlockDefs((), all_defs=GraphVVarDefs(graph))
            return [self.opt.optimize(read, block_defs=bd, block=blk, stmt_idx=i) for i in (1, 2)]

        # the callee may write everything from the address it was given up to the frame base
        before, after = read_after(-0x28)
        assert before is not None and after is None
        assert None not in read_after(-0x18)


if __name__ == "__main__":
    unittest.main()

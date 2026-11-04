#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Convert, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Return, Store
from angr.analyses.decompiler.ail_simplifier import _possible_bits
from angr.knowledge_plugins.functions import Function


class TestFlagBitsIntoConditions(unittest.TestCase):
    """AILSimplifier tests a materialized flags value's bits in a branch through the terms that may set them."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\xc3", "AMD64")
        self.idx = iter(range(100, 1_000_000))
        self.x = VirtualVariable(next(self.idx), 1, 32, VirtualVariableCategory.STACK, oident=-24)

    def _c(self, v, bits):
        return Const(next(self.idx), v, bits)

    def _op(self, op, a, b, bits):
        return BinaryOp(next(self.idx), op, [a, b], False, bits=bits)

    def _flag(self, cond, shift):
        b = Convert(next(self.idx), 1, 64, False, cond)
        return b if shift == 0 else self._op("Mul", b, self._c(1 << shift, 64), 64)

    def _flags(self):
        # rflags of `cmp x, 5` as the ccall rewriter lowers it
        diff = self._op("Sub", self.x, self._c(5, 32), 32)
        low = self._op("Xor", Convert(next(self.idx), 32, 8, False, diff), self._c(0, 8), 8)
        lookup = self._op("Shr", self._c(38505, 64), self._op("And", low, self._c(15, 8), 8), 64)
        pf = self._op("Mul", self._op("And", lookup, self._c(1, 64), 64), self._c(4, 64), 64)
        af = self._op("And", self._op("Xor", diff, self.x, 32), self._c(16, 32), 32)
        af = Convert(next(self.idx), 32, 64, False, af)
        terms = [
            self._flag(self._op("CmpLT", self.x, self._c(5, 32), 1), 0),
            pf,
            af,
            self._flag(self._op("CmpEQ", self.x, self._c(5, 32), 1), 6),
            self._flag(self._op("CmpLT", diff, self._c(0, 32), 1), 7),
        ]
        value = terms[0]
        for t in terms[1:]:
            value = self._op("Or", value, t, 64)
        return value

    def _cond(self, mask):
        flags = VirtualVariable(next(self.idx), 2, 64, VirtualVariableCategory.TMP, oident=2)
        use = lambda: VirtualVariable(next(self.idx), 2, 64, VirtualVariableCategory.TMP, oident=2)  # noqa: E731
        test = self._op(
            "CmpEQ",
            self._op("And", Convert(next(self.idx), 64, 32, False, use()), self._c(mask, 32), 32),
            self._c(0, 32),
            1,
        )
        head = Block(
            0x401000,
            0x10,
            statements=[
                Assignment(0, flags, self._flags(), ins_addr=0x401000),
                # the VM saves the flags in its context: a second use keeps the definition a variable
                Store(1, self._c(0x500000, 64), use(), 8, "Iend_LE", ins_addr=0x401004),
                ConditionalJump(2, test, self._c(0x402000, 64), self._c(0x403000, 64), ins_addr=0x401008),
            ],
            idx=0,
        )
        graph = networkx.DiGraph()
        for addr in (0x402000, 0x403000):
            graph.add_edge(head, Block(addr, 1, statements=[Return(0, [], ins_addr=addr)], idx=0))
        simp = self.proj.analyses.AILSimplifier(
            Function(self.proj.kb.functions, 0x401000),
            func_graph=graph,
            ail_manager=ailment.Manager(),
            remove_dead_memdefs=False,
        )
        return next(b for b in simp.func_graph if b.addr == 0x401000).statements[-1]

    def test_possible_bits_of_mul_by_zero(self):
        # a Mul by 0 is not a shift (bit_length() - 1 == -1)
        bits = _possible_bits(self._op("Mul", self.x, self._c(0, 32), 32))
        assert bits == 0xFFFFFFFF

    def test_zero_flag_test_reads_its_term(self):
        cond = str(self._cond(64).condition)
        assert "vvar_2" not in cond
        assert "CmpEQ 5" in cond and "CmpLT" not in cond and "38505" not in cond

    def test_sign_flag_test_reads_its_term(self):
        cond = str(self._cond(128).condition)
        assert "vvar_2" not in cond and "CmpLT 0" in cond and "CmpEQ 5" not in cond

    def test_parity_flag_test_reads_its_term(self):
        # PF's lookup shifts by a variable amount; its "& 1" still confines it to one bit
        cond = str(self._cond(4).condition)
        assert "vvar_2" not in cond and "38505" in cond and "CmpEQ 5" not in cond


if __name__ == "__main__":
    unittest.main()

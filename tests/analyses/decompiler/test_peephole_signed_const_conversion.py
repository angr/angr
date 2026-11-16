#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import Const, Convert
from angr.ailment.statement import Store
from angr.analyses.decompiler.block_simplifier import BlockSimplifier
from angr.analyses.decompiler.peephole_optimizations import EagerEvaluation, EvaluateConstConversions

# (from bits, to bits, value, sign-extended value)
CASES = [
    (16, 64, 0xFEFF, 0xFFFFFFFFFFFFFEFF),
    (32, 64, 0xFD9D8F39, 0xFFFFFFFFFD9D8F39),
    (8, 32, 0x80, 0xFFFFFF80),
    (8, 16, 0x7F, 0x7F),
    (16, 64, 0x7EFF, 0x7EFF),
    (1, 8, 1, 0xFF),
]


class TestSignedConstConversion(unittest.TestCase):
    """A signed widening of a constant takes its sign from the source width."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\xc3", "AMD64")

    @staticmethod
    def _conv(from_bits, to_bits, value, signed=True):
        return Convert(1, from_bits, to_bits, signed, Const(2, value, from_bits))

    def test_each_evaluator(self):
        for cls in (EagerEvaluation, EvaluateConstConversions):
            opt = cls(self.proj, self.proj.kb, ailment.Manager(), 0)
            for from_bits, to_bits, value, expected in CASES:
                out = opt.optimize(self._conv(from_bits, to_bits, value))
                assert isinstance(out, Const) and out.bits == to_bits, (cls.__name__, from_bits, to_bits)
                assert out.value == expected, (cls.__name__, hex(value), hex(out.value))

    def test_unsigned_widening_and_narrowing_keep_the_low_bits(self):
        for cls in (EagerEvaluation, EvaluateConstConversions):
            opt = cls(self.proj, self.proj.kb, ailment.Manager(), 0)
            assert opt.optimize(self._conv(16, 64, 0xFEFF, signed=False)).value == 0xFEFF
            assert opt.optimize(self._conv(64, 16, 0x1234FEFF)).value == 0xFEFF

    def test_block_simplifier(self):
        stmts = [
            Store(10 + i, Const(None, 0x600000 + 8 * i, 64), self._conv(f, t, v), t // 8, "Iend_LE", ins_addr=i)
            for i, (f, t, v, _) in enumerate(CASES)
        ]
        block = Block(0, len(stmts), statements=stmts, idx=0)
        out = BlockSimplifier(self.proj, block, ailment.Manager(), func_addr=0).result_block
        assert [s.data.value for s in out.statements] == [e for _, _, _, e in CASES]


if __name__ == "__main__":
    unittest.main()

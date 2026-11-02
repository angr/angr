# pylint:disable=missing-class-docstring,no-self-use
"""AIL Neg is two's complement negation: constant folding and the p-code mapping agree with it."""

from __future__ import annotations

import random
import unittest

import angr
from angr import ailment, claripy
from angr.ailment import Manager
from angr.ailment.expression import BinaryOp, Const, Register, UnaryOp
from angr.analyses.decompiler.peephole_optimizations import EagerEvaluation


class TestNegConstFolding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proj = angr.load_shellcode(b"\x90", "X86")

    def setUp(self):
        self.m = Manager()
        self.opt = EagerEvaluation(self.proj, self.proj.kb, self.m)

    def _fold(self, op: str, value: int, bits: int):
        r = self.opt.optimize(UnaryOp(self.m.next_atom(), op, Const(self.m.next_atom(), value, bits), bits=bits))
        assert isinstance(r, Const) and r.bits == bits
        return r.value_int

    def test_neg_exhaustive_8bit(self):
        for c in range(256):
            want = claripy.simplify(-claripy.BVV(c, 8)).concrete_value
            assert self._fold("Neg", c, 8) == want == (-c) & 0xFF, c

    def test_neg_wide(self):
        rng = random.Random(7)
        for bits in (16, 32, 64):
            for c in [0, 1, (1 << (bits - 1)), (1 << bits) - 1, *(rng.getrandbits(bits) for _ in range(64))]:
                assert self._fold("Neg", c, bits) == claripy.simplify(-claripy.BVV(c, bits)).concrete_value

    def test_neg_matches_zero_minus(self):
        # EagerEvaluation rewrites 0 - x into Neg(x); folding x = C afterwards must give 0 - C
        x = Register(self.m.next_atom(), 8, 8)
        sub = self.opt.optimize(BinaryOp(self.m.next_atom(), "Sub", [Const(self.m.next_atom(), 0, 8), x], False))
        assert isinstance(sub, UnaryOp) and sub.op == "Neg"
        for c in range(256):
            assert self._fold("Neg", c, 8) == (0 - c) & 0xFF

    def test_vmp_key_byte(self):
        # VMProtect handler 'neg dl' on 0xee; folding it as ~0xee (0x11) mis-decrypted a VM register index
        assert self._fold("Neg", 0xEE, 8) == 0x12

    def test_bitwise_neg_is_not_neg(self):
        for c in (0, 1, 0x7F, 0xEE, 0xFF):
            r = self.opt.optimize(UnaryOp(self.m.next_atom(), "BitwiseNeg", Const(self.m.next_atom(), c, 8), bits=8))
            assert r is None or (isinstance(r, Const) and r.value_int == (~c) & 0xFF)


class TestPcodeNegations(unittest.TestCase):
    def _ops(self, code: bytes) -> set[str]:
        p = angr.load_shellcode(code, "AMD64", 0x1000, 0x1000, engine=angr.engines.UberEnginePcode)
        block = ailment.IRSBConverter.convert(p.factory.block(0x1000).vex, ailment.Manager())
        ops = set()

        def walk(e):
            if isinstance(e, UnaryOp):
                ops.add(e.op)
                walk(e.operand)
            elif isinstance(e, BinaryOp):
                for o in e.operands:
                    walk(o)

        for stmt in block.statements:
            for attr in ("src", "data"):
                if hasattr(stmt, attr):
                    walk(getattr(stmt, attr))
        return ops

    def test_int_negate_is_bitwise(self):
        # not eax: INT_NEGATE
        ops = self._ops(b"\xf7\xd0")
        assert "BitwiseNeg" in ops and "Neg" not in ops

    def test_int_2comp_is_neg(self):
        # neg eax: INT_2COMP
        ops = self._ops(b"\xf7\xd8")
        assert "Neg" in ops


if __name__ == "__main__":
    unittest.main()

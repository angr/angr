#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import random
import unittest

import angr
from angr.ailment.expression import ITE, BinaryOp, Call, Const, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import (
    ConstBitwiseNeg,
    ConstBswap,
    ConstFlagHelper,
    ConstRotate,
    ExpCmpNEToCmpNE,
)

from .ail_equivalence import equivalent


class TestConstBswap(unittest.TestCase):
    def test_bswap_of_constants(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        m = Manager()
        opt = ConstBswap(proj, proj.kb, m)
        rng = random.Random(0)
        for bits in (16, 32, 64):
            for v in [0, 1, (1 << bits) - 1, 0x0102030405060708 & ((1 << bits) - 1)] + [rng.getrandbits(bits) for _ in range(20)]:
                expr = Call(m.next_atom(), f"__builtin_bswap{bits}", args=[Const(m.next_atom(), v, bits)], bits=bits)
                out = opt.optimize(expr)
                assert isinstance(out, Const)
                assert equivalent(expr, out)
            cond = BinaryOp(m.next_atom(), "CmpEQ", [Register(m.next_atom(), 16, bits), Const(m.next_atom(), 3, bits)], False, bits=1)
            sel = ITE(m.next_atom(), cond, Const(m.next_atom(), 0x1234 % (1 << bits), bits), Const(m.next_atom(), 7, bits))
            expr = Call(m.next_atom(), f"__builtin_bswap{bits}", args=[sel], bits=bits)
            out = opt.optimize(expr)
            assert isinstance(out, ITE) and equivalent(expr, out)
        assert opt.optimize(Call(m.next_atom(), "__builtin_bswap32", args=[Register(m.next_atom(), 16, 32)], bits=32)) is None

    def test_rotate_of_constants(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        m = Manager()
        opt = ConstRotate(proj, proj.kb, m)
        rng = random.Random(1)
        for bits in (8, 16, 32, 64):
            for op in ("Rol", "Ror"):
                for n in (0, 1, 3, bits - 1, bits, bits + 5):
                    v = rng.getrandbits(bits)
                    expr = BinaryOp(m.next_atom(), op, [Const(m.next_atom(), v, bits), Const(m.next_atom(), n, 8)], False, bits=bits)
                    out = opt.optimize(expr)
                    assert isinstance(out, Const) and equivalent(expr, out), (op, bits, n)

    def test_expcmpne(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        m = Manager()
        a = BinaryOp(m.next_atom(), "And", [Register(m.next_atom(), 16, 64), Const(m.next_atom(), 0xFFFF, 64)], False, bits=64)
        expr = BinaryOp(m.next_atom(), "ExpCmpNE", [a, Const(m.next_atom(), 0, 64)], False, bits=1)
        out = ExpCmpNEToCmpNE(proj, proj.kb, m).optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "CmpNE" and out.operands[0].likes(a)

    def test_complement_of_constant(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        m = Manager()
        opt = ConstBitwiseNeg(proj, proj.kb, m)
        for bits, v in ((8, 0), (8, 0xFF), (32, 203), (64, 0x8000000000000001)):
            expr = UnaryOp(m.next_atom(), "BitwiseNeg", Const(m.next_atom(), v, bits), bits=bits)
            out = opt.optimize(expr)
            assert isinstance(out, Const) and equivalent(expr, out)


class TestConstFlagHelper(unittest.TestCase):
    @staticmethod
    def _ref(name, x, y, bits):
        # carry out of the top bit / operands' signs against the result's sign
        top = bits - 1
        if name == "__CFADD__":
            return ((x + y) >> bits) & 1
        if name == "__OFADD__":
            r = x + y
            return ((~(x ^ y) & (x ^ r)) >> top) & 1
        r = x - y
        return (((x ^ y) & (x ^ r)) >> top) & 1

    def test_flag_helpers_of_constants(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        m = Manager()
        opt = ConstFlagHelper(proj, proj.kb, m)
        rng = random.Random(2)

        def check(name, x, y, bits):
            expr = Call(m.next_atom(), name, args=[Const(m.next_atom(), x, bits), Const(m.next_atom(), y, bits)], bits=64)
            out = opt.optimize(expr)
            assert isinstance(out, Const) and out.bits == 64
            assert out.value_int == self._ref(name, x, y, bits), (name, x, y, bits)

        for name in ("__CFADD__", "__OFADD__", "__OFSUB__"):
            for x in range(256):
                for y in (0, 1, 17, 127, 128, 239, 255, rng.getrandbits(8)):
                    check(name, x, y, 8)
            for bits in (16, 32, 64):
                top = 1 << (bits - 1)
                edge = [0, 1, top - 1, top, top + 1, 2 * top - 1]
                for x in edge + [rng.getrandbits(bits) for _ in range(10)]:
                    for y in edge + [rng.getrandbits(bits) for _ in range(10)]:
                        check(name, x, y, bits)

    def test_flag_helpers_left_alone(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")
        m = Manager()
        opt = ConstFlagHelper(proj, proj.kb, m)

        def c(v, bits):
            return Const(m.next_atom(), v, bits)

        reg = Register(m.next_atom(), 16, 8)
        assert opt.optimize(Call(m.next_atom(), "__CFADD__", args=[reg, c(239, 8)], bits=64)) is None
        assert opt.optimize(Call(m.next_atom(), "__CFADD__", args=[c(1, 8), c(239, 16)], bits=64)) is None
        assert opt.optimize(Call(m.next_atom(), "__CFADD__", args=[c(1, 1), c(1, 1)], bits=64)) is None
        assert opt.optimize(Call(m.next_atom(), "__OFUMUL__", args=[c(1, 8), c(2, 8)], bits=64)) is None
        assert opt.optimize(Call(m.next_atom(), "__CFADD__", args=[c(1, 8)], bits=64)) is None


if __name__ == "__main__":
    unittest.main()

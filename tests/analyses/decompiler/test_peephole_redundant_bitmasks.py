#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import BinaryOp, Const, Convert, Register
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import RemoveRedundantBitmasks

from .test_peephole_vm_bool_select import _equivalent


def _eval(expr, r: int) -> int:
    """Concrete value of ``expr`` with every register holding ``r``."""
    mask = (1 << expr.bits) - 1
    if isinstance(expr, Const):
        return expr.value_int & mask
    if isinstance(expr, Register):
        return r & mask
    if isinstance(expr, Convert):
        v = _eval(expr.operand, r)
        if expr.is_signed and expr.to_bits > expr.from_bits and v >> (expr.from_bits - 1):
            v -= 1 << expr.from_bits
        return v & mask
    a, b = (_eval(op, r) for op in expr.operands)
    return {"And": lambda: a & b, "CmpNE": lambda: int(a != b), "CmpEQ": lambda: int(a == b)}[expr.op]()


class TestRemoveRedundantBitmasksBool(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = RemoveRedundantBitmasks(self.proj, self.proj.kb, self.m)

    def _masked(self, bits, mask, signed=False):
        cond = BinaryOp(
            self.m.next_atom(),
            "CmpNE",
            [Register(self.m.next_atom(), 16, 8), Const(self.m.next_atom(), 0, 8)],
            False,
            bits=1,
        )
        conv = Convert(self.m.next_atom(), 1, bits, signed, cond)
        return BinaryOp(self.m.next_atom(), "And", [conv, Const(self.m.next_atom(), mask, bits)], False, bits=bits)

    def test_masks_exhaustively(self):
        for bits in (8, 16, 32, 64):
            full = (1 << bits) - 1
            masks = range(256) if bits == 8 else (0, 1, 2, 3, 0x40, 0xFE, 0xFF, 0x8000, full - 1)
            for mask in masks:
                expr = self._masked(bits, mask)
                out = self.opt.optimize(expr)
                assert out is not None, (bits, mask)
                for r in (0, 1, 0x80):
                    assert _eval(out, r) == _eval(expr, r), (bits, mask, r, out)
                if mask & 1:
                    assert isinstance(out, Convert)
                else:
                    assert isinstance(out, Const) and out.value_int == 0

    def test_z3(self):
        for mask in (1, 2, 0x41, 0x40):
            expr = self._masked(32, mask)
            assert _equivalent(expr, self.opt.optimize(expr))

    def test_sign_extended_bool_is_kept(self):
        # 0 or -1: masking with anything short of all ones changes it
        for mask in (1, 2, 0xFF):
            assert self.opt.optimize(self._masked(32, mask, signed=True)) is None


if __name__ == "__main__":
    unittest.main()

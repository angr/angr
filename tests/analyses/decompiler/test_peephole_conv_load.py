#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import Convert, Load, Register
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, ConvLoad, vm_peephole_optimizations


class TestConvLoad(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.manager = Manager()
        self.opt = ConvLoad(self.proj, self.proj.kb, self.manager)

    def _conv(self, from_type, to_type, endness="Iend_LE"):
        addr = Register(self.manager.next_atom(), 16, 64)
        load = Load(self.manager.next_atom(), addr, 8, endness)
        return Convert(self.manager.next_atom(), 64, 32, False, load, from_type=from_type, to_type=to_type)

    def test_vm_only(self):
        assert ConvLoad not in EXPR_OPTS
        assert ConvLoad in vm_peephole_optimizations()

    def test_integer_truncation(self):
        out = self.opt.optimize(self._conv(Convert.TYPE_INT, Convert.TYPE_INT))
        assert isinstance(out, Load) and out.size == 4

    def test_keeps_fp_and_big_endian(self):
        assert self.opt.optimize(self._conv(Convert.TYPE_FP, Convert.TYPE_FP)) is None
        assert self.opt.optimize(self._conv(Convert.TYPE_INT, Convert.TYPE_FP)) is None
        assert self.opt.optimize(self._conv(Convert.TYPE_INT, Convert.TYPE_INT, "Iend_BE")) is None


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import ailment
from angr.ailment.expression import Const, Extract
from angr.analyses.decompiler.peephole_optimizations import EvaluateConstConversions


class TestConstExtract(unittest.TestCase):
    """Extract of any byte-aligned slice of an integer constant is evaluated."""

    def setUp(self):
        proj = angr.load_shellcode(b"\xc3", "AMD64")
        self.opt = EvaluateConstConversions(proj, proj.kb, ailment.Manager(), 0)

    def _extract(self, value, offset, bits, endness="Iend_LE"):
        return Extract(1, bits, Const(2, value, 64), Const(3, offset, 64), endness)

    def test_little_endian_slices(self):
        out = self.opt.optimize(self._extract(0x7EF4, 1, 8))
        assert isinstance(out, Const) and out.value == 0x7E and out.bits == 8
        out = self.opt.optimize(self._extract(0x1122334455667788, 4, 16))
        assert out.value == 0x3344 and out.bits == 16
        assert self.opt.optimize(self._extract(0x7EF4, 0, 8)).value == 0xF4

    def test_big_endian_slice(self):
        out = self.opt.optimize(self._extract(0x1122334455667788, 1, 8, "Iend_BE"))
        assert out.value == 0x22

    def test_out_of_range_slice_is_kept(self):
        assert self.opt.optimize(self._extract(0x7EF4, 7, 16)) is None


if __name__ == "__main__":
    unittest.main()

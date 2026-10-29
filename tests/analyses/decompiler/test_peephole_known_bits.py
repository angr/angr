#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr import claripy
from angr.ailment import Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    Register,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.peephole_optimizations import KnownBitsAndMask
from angr.analyses.decompiler.peephole_optimizations.known_bits import known_bits
from angr.utils.ail import BlockDefs, GraphVVarDefs

from .ail_equivalence import to_claripy


class TestKnownBits(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "X86")
        self.m = Manager()

    def _c(self, v, bits=32):
        return Const(self.m.next_atom(), v, bits)

    def _r(self, off, bits=32):
        return Register(self.m.next_atom(), off, bits)

    def _bin(self, op, a, b, bits=None):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=bits or a.bits)

    def _flag(self, cond, value):
        return self._bin("Mul", Convert(self.m.next_atom(), 1, 32, False, cond), self._c(value))

    def _vvar(self, varid):
        return VirtualVariable(self.m.next_atom(), varid, 32, VirtualVariableCategory.REGISTER, oident=8)

    def _flags_word(self, x):
        # PF | ZF | SF of a LOGIC result, the way the flags rewriter spells it
        parity = self._bin("Mul", self._bin("And", self._bin("Shr", self._c(0x9669), self._bin("And", x, self._c(15)), 32), self._c(1)), self._c(4))
        zf = self._flag(BinaryOp(self.m.next_atom(), "CmpEQ", [x, self._c(0)], False, bits=1), 64)
        sf = self._flag(BinaryOp(self.m.next_atom(), "CmpLT", [x, self._c(0)], True, bits=1), 128)
        return self._bin("Or", self._bin("Or", parity, zf), sf)

    def test_known_bits_are_sound(self):
        x, y = self._r(16), self._r(24)
        shapes = [
            self._flags_word(x),
            self._bin("Or", self._flags_word(x), self._c(0x202)),
            self._bin("Add", self._flag(BinaryOp(self.m.next_atom(), "CmpNE", [x, y], False, bits=1), 0x800), self._bin("And", y, self._c(0xFF))),
            self._bin("Xor", self._bin("Shl", self._bin("And", x, self._c(0xF0)), self._c(4, 8)), self._c(0xF)),
            Convert(self.m.next_atom(), 16, 32, True, self._bin("Or", self._r(16, 16), self._c(0x8000, 16))),
            Convert(self.m.next_atom(), 16, 32, False, self._r(16, 16)),
            UnaryOp(self.m.next_atom(), "BitwiseNeg", self._bin("And", x, self._c(0xFF00)), bits=32),
            ITE(self.m.next_atom(), BinaryOp(self.m.next_atom(), "CmpEQ", [x, y], False, bits=1), self._c(0x10), self._c(0x30)),
            self._bin("Concat", self._c(0x7F, 16), self._r(24, 16), bits=32),
        ]
        for e in shapes:
            z, o = known_bits(e)
            assert z & o == 0
            ce = to_claripy(e)
            s = claripy.Solver()
            assert not s.satisfiable(extra_constraints=[ce & z != 0]), e
            assert not s.satisfiable(extra_constraints=[ce & o != o]), e
        # nothing claimed where a carry can happen
        assert known_bits(self._bin("Add", self._bin("And", x, self._c(1)), self._c(1))) == (0, 0)

    def test_overflow_test_of_a_logic_flags_word_is_zero(self):
        opt = KnownBitsAndMask(self.proj, self.proj.kb, self.m)
        call = Call(self.m.next_atom(), "RegOpenKeyExA", args=[], bits=32)
        flags = self._vvar(1)
        merged = self._vvar(2)
        b0 = Block(0x1000, 1, statements=[Assignment(self.m.next_atom(), flags, self._flags_word(call))])
        b1 = Block(0x2000, 1, statements=[Assignment(self.m.next_atom(), merged, self._bin("Or", self._vvar(1), self._c(0x202)))])
        graph = networkx.DiGraph()
        graph.add_edge(b0, b1)
        defs = BlockDefs(b1.statements, all_defs=GraphVVarDefs(graph))
        out = opt.optimize(self._bin("And", self._c(0x800), self._vvar(2)), block_defs=defs)
        assert isinstance(out, Const) and out.value == 0
        out = opt.optimize(self._bin("And", self._vvar(2), self._c(0x200)), block_defs=defs)
        assert isinstance(out, Const) and out.value == 0x200
        # the zero flag depends on the call
        assert opt.optimize(self._bin("And", self._vvar(2), self._c(0x40)), block_defs=defs) is None
        # no definitions, no claim
        assert opt.optimize(self._bin("And", self._vvar(2), self._c(0x800))) is None


if __name__ == "__main__":
    unittest.main()

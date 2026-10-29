#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr import claripy
from angr.ailment.expression import BinaryOp, Const, Register, VEXCCallExpression
from angr.ailment.manager import Manager
from angr.analyses.decompiler.ccall_rewriters import CCALL_REWRITERS
from angr.analyses.decompiler.ccall_rewriters.flags_word import _FAMILIES, FlagsWordBuilder
from angr.analyses.decompiler.peephole_optimizations import ExpandMaskedFlagsWord
from angr.analyses.decompiler.peephole_optimizations.known_bits import known_bits
from angr.engines.vex.claripy.ccall import data, pc_calculate_rdata_all

from .ail_equivalence import equivalent, to_claripy


class TestFlagsWord(unittest.TestCase):
    """The rebuilt flags word equals angr's model of the VEX helper for every operand value (checked with Z3)."""

    def _check(self, platform):
        m = Manager()
        bits = data[platform]["size"]
        deps = [Register(m.next_atom(), off, bits) for off in (16, 24, 32)]
        sym = [to_claripy(d) for d in deps]
        ops = dict(_FAMILIES[platform])
        ops[data[platform]["OpTypes"]["G_CC_OP_COPY"]] = ("COPY", bits)
        for op_v in sorted(ops):
            out = FlagsWordBuilder(m, platform, {}).build(op_v, *deps, m.next_atom())
            assert out is not None and out.bits == bits
            ref = pc_calculate_rdata_all(None, op_v, *sym, platform=platform)
            assert equivalent(out, ref), (platform, ops[op_v])

    def test_x86(self):
        self._check("X86")

    def test_amd64(self):
        self._check("AMD64")

    def test_known_bits_of_flags_words_are_sound(self):
        m = Manager()
        deps = [Register(m.next_atom(), off, 32) for off in (16, 24, 32)]
        for op_v in sorted({**_FAMILIES["X86"], 0: None}):
            ccall = VEXCCallExpression(m.next_atom(), "x86g_calculate_eflags_all", (Const(m.next_atom(), op_v, 32), *deps), 32)
            z, o = known_bits(ccall)
            ref = to_claripy(ccall)
            s = claripy.Solver()
            assert not s.satisfiable(extra_constraints=[ref & z != 0]), op_v
            assert not s.satisfiable(extra_constraints=[ref & o != o]), op_v

    def test_masked_flags_word_is_expanded(self):
        proj = angr.load_shellcode(b"\x90", "X86")
        m = Manager()
        opt = ExpandMaskedFlagsWord(proj, proj.kb, m)
        deps = [Register(m.next_atom(), off, 32) for off in (16, 24, 32)]
        for op_v in (3, 6, 15, 18, 24, 27):
            ccall = VEXCCallExpression(m.next_atom(), "x86g_calculate_eflags_all", (Const(m.next_atom(), op_v, 32), *deps), 32)
            expr = BinaryOp(m.next_atom(), "And", [ccall, Const(m.next_atom(), 0x40, 32)], False, bits=32)
            out = opt.optimize(expr)
            assert out is not None and equivalent(expr, out), op_v
        # the whole word, or bits outside the flags, stay a ccall
        assert opt.optimize(BinaryOp(m.next_atom(), "And", [ccall, Const(m.next_atom(), 0x10000, 32)], False, bits=32)) is None

    def test_x86_rewriter_folds_constant_thunk(self):
        proj = angr.load_shellcode(b"\x90", "X86")
        m = Manager()
        c = lambda v: Const(m.next_atom(), v, 32)  # noqa: E731
        # LOGICL on 64: ZF = 0, PF = 0 (one bit set), SF = 0
        ccall = VEXCCallExpression(m.next_atom(), "x86g_calculate_eflags_all", (c(15), c(64), c(0), c(0)), 32)
        out = CCALL_REWRITERS["X86"](ccall, proj, m).result
        assert out is not None
        assert claripy.simplify(to_claripy(out)).concrete_value == 0
        ccall = VEXCCallExpression(m.next_atom(), "x86g_calculate_eflags_all", (c(6), c(5), c(5), c(0)), 32)
        out = CCALL_REWRITERS["X86"](ccall, proj, m).result
        # SUBL 5 - 5: ZF and PF
        assert claripy.simplify(to_claripy(out)).concrete_value == 0x44


if __name__ == "__main__":
    unittest.main()

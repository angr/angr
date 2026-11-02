#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Register, Tmp, VEXCCallExpression
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.peephole_optimizations import (
    RemoveIdFlag,
    RemoveUnusedNdeps,
    vm_peephole_optimizations,
)
from angr.analyses.decompiler.utils import peephole_optimize_exprs
from angr.utils.ail import BlockDefs


class TestRflagsCcallPeepholes(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.manager = Manager()

    def _c(self, v, bits=64):
        return Const(self.manager.next_atom(), v, bits)

    def _ccall(self, op=0x14, ndep=None):
        dep1 = Register(self.manager.next_atom(), 16, 64)
        return VEXCCallExpression(
            self.manager.next_atom(),
            "amd64g_calculate_rflags_all",
            (self._c(op), dep1, self._c(0), self._c(0) if ndep is None else ndep),
            bits=64,
        )

    def _flag_term(self, reg_offset, mask):
        reg = Register(self.manager.next_atom(), reg_offset, 64)
        shifted = BinaryOp(self.manager.next_atom(), "Mul", [reg, self._c(mask)], False, bits=64)
        return BinaryOp(self.manager.next_atom(), "And", [shifted, self._c(mask)], False, bits=64)

    def _or(self, a, b):
        return BinaryOp(self.manager.next_atom(), "Or", [a, b], False, bits=64)

    def test_registered(self):
        opts = vm_peephole_optimizations()
        assert RemoveIdFlag in opts and RemoveUnusedNdeps in opts

    def test_remove_id_flag_on_the_ccall(self):
        opt = RemoveIdFlag(self.proj, self.proj.kb, self.manager)
        ccall = self._ccall()
        out = opt.optimize(self._or(ccall, self._flag_term(200, 0x200000)))
        assert out.likes(ccall)
        assert opt.optimize(self._or(ccall, self._flag_term(200, 0x100))) is None

    def test_remove_id_flag_through_a_tmp(self):
        # the converter keeps the ccall in a tmp; only the tmp is Or'ed with the id/ac/d terms
        opt = RemoveIdFlag(self.proj, self.proj.kb, self.manager)
        t0 = Tmp(self.manager.next_atom(), 0, 64)
        t1 = Tmp(self.manager.next_atom(), 1, 64)
        block = Block(
            0x1000,
            4,
            statements=[
                Assignment(self.manager.next_atom(), t0, self._ccall()),
                Assignment(
                    self.manager.next_atom(),
                    t1,
                    BinaryOp(self.manager.next_atom(), "Add", [t0, self._c(1)], False, bits=64),
                ),
            ],
        )
        defs = BlockDefs(block.statements)
        # the walker is bottom-up: the inner Or goes first, then the outer one sees the tmp again
        out = opt.optimize(self._or(t0, self._flag_term(200, 0x200000)), block=block, block_defs=defs)
        assert out.likes(t0)
        out = opt.optimize(self._or(out, self._flag_term(192, 0x40000)), block=block, block_defs=defs)
        assert out.likes(t0)
        # a tmp that holds something else is not a flags word
        assert opt.optimize(self._or(t1, self._flag_term(200, 0x200000)), block=block, block_defs=defs) is None

    def test_remove_unused_ndep_is_dispatched_on_the_ccall(self):
        ndep = Register(self.manager.next_atom(), 168, 64)
        t0 = Tmp(self.manager.next_atom(), 0, 64)
        block = Block(0x1000, 4, statements=[Assignment(self.manager.next_atom(), t0, self._ccall(ndep=ndep))])
        opt = RemoveUnusedNdeps(self.proj, self.proj.kb, self.manager)
        assert peephole_optimize_exprs(block, [opt])
        src = block.statements[0].src
        assert isinstance(src, VEXCCallExpression)
        assert isinstance(src.operands[3], Const) and src.operands[3].value == 0


if __name__ == "__main__":
    unittest.main()

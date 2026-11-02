#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import archinfo
import networkx

import angr
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Extract,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, ConditionalJump, SideEffectStatement
from angr.analyses.decompiler.format_calls import FormatCallModel, find_defs_overwritten_by_calls

SCANF, PRINTF = 0x2000, 0x2010
FORMATS = {b"%d": 0x100, b"%ld": 0x110, b"%lld": 0x120, b"%d %d": 0x130, b"%*d": 0x140, b"%s": 0x150, b"%n": 0x160}


class TestScanfOverwrittenDefinitions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        image = bytearray(0x200)
        for text, addr in FORMATS.items():
            image[addr : addr + len(text)] = text
        cls.proj = angr.load_shellcode(bytes(image), "AMD64")
        cls.proj.hook(SCANF, angr.SIM_PROCEDURES["libc"]["scanf"]())
        cls.proj.hook(PRINTF, angr.SIM_PROCEDURES["libc"]["printf"]())

    def setUp(self):
        self.m = Manager()
        self.arch = self.proj.arch

    def _c(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _var(self, varid=1, off=-24, bits=64):
        return VirtualVariable(self.m.next_atom(), varid, bits, VirtualVariableCategory.STACK, oident=off)

    def _low(self, var, bits=32):
        return Extract(self.m.next_atom(), bits, var, self._c(0), archinfo.Endness.LE)

    def _ref(self, expr):
        return UnaryOp(self.m.next_atom(), "Reference", expr, bits=64)

    def _call(self, target, *args):
        return SideEffectStatement(self.m.next_atom(), Call(self.m.next_atom(), self._c(target), args=list(args)))

    def _def(self, var, value=7):
        return Assignment(self.m.next_atom(), var, self._c(value, var.bits))

    def _branch_on(self, expr):
        cond = BinaryOp(self.m.next_atom(), "CmpEQ", [expr, self._c(5, expr.bits)], False, bits=1)
        return ConditionalJump(self.m.next_atom(), cond, self._c(0x3000), self._c(0x4000))

    def _dead(self, *stmts, use=None):
        """Definition at index 0 of the first block; ``use`` is the statement of a successor block."""
        head = Block(0x1000, 8, statements=list(stmts))
        graph = networkx.DiGraph()
        graph.add_node(head)
        if use is not None:
            graph.add_edge(head, Block(0x1100, 4, statements=[use]))
        dead = find_defs_overwritten_by_calls(graph, FormatCallModel(self.proj), self.arch)
        return 0 in dead.get((head.addr, head.idx), set())

    def test_flag_word_before_scanf_is_dead(self):
        v = self._var()
        fmt = self._c(FORMATS[b"%d"])
        assert self._dead(
            self._def(v), self._call(SCANF, fmt, self._ref(self._low(v))), use=self._branch_on(self._low(v))
        )
        # the whole variable as the destination
        w = self._var(bits=32)
        assert self._dead(self._def(w), self._call(SCANF, fmt, self._ref(w)), use=self._branch_on(w))
        # the second of two conversions
        a = self._var(2, off=-32, bits=32)
        fmt2 = self._c(FORMATS[b"%d %d"])
        assert self._dead(self._def(w), self._call(SCANF, fmt2, self._ref(a), self._ref(w)), use=self._branch_on(w))

    def test_width_must_cover_every_read(self):
        v = self._var()
        # %d writes 4 of the 8 bytes the use reads
        assert not self._dead(
            self._def(v), self._call(SCANF, self._c(FORMATS[b"%d"]), self._ref(v)), use=self._branch_on(v)
        )
        # long is 4 bytes in one runtime and 8 in another
        assert not self._dead(
            self._def(v), self._call(SCANF, self._c(FORMATS[b"%ld"]), self._ref(v)), use=self._branch_on(v)
        )
        assert self._dead(
            self._def(v), self._call(SCANF, self._c(FORMATS[b"%lld"]), self._ref(v)), use=self._branch_on(v)
        )

    def test_read_before_the_call_keeps_it(self):
        v = self._var(bits=32)
        read = Assignment(self.m.next_atom(), self._var(9, off=-64, bits=32), v)
        assert not self._dead(
            self._def(v), read, self._call(SCANF, self._c(FORMATS[b"%d"]), self._ref(v)), use=self._branch_on(v)
        )

    def test_unknown_format_keeps_it(self):
        v = self._var(bits=32)
        fmt_var = VirtualVariable(self.m.next_atom(), 7, 64, VirtualVariableCategory.REGISTER, oident=16)
        for fmt in (fmt_var, self._c(FORMATS[b"%*d"])):
            assert not self._dead(self._def(v), self._call(SCANF, fmt, self._ref(v)), use=self._branch_on(v))

    def test_argument_beyond_the_conversions_keeps_it(self):
        v = self._var(bits=32)
        a = self._var(2, off=-32, bits=32)
        assert not self._dead(
            self._def(v), self._call(SCANF, self._c(FORMATS[b"%d"]), self._ref(a), self._ref(v)), use=self._branch_on(v)
        )

    def test_printf_reads(self):
        v = self._var(bits=32)
        for fmt in (b"%s", b"%n", b"%d"):
            assert not self._dead(
                self._def(v), self._call(PRINTF, self._c(FORMATS[fmt]), self._ref(v)), use=self._branch_on(v)
            )

    def test_other_references_keep_it(self):
        v = self._var(bits=32)
        fmt = self._c(FORMATS[b"%d"])
        # the address escapes elsewhere
        leak = Assignment(self.m.next_atom(), self._var(9, off=-64), self._ref(v))
        assert not self._dead(self._def(v), self._call(SCANF, fmt, self._ref(v)), use=leak)
        # another version of the slot is referenced
        older = self._var(5, off=-24, bits=32)
        ptr = Assignment(self.m.next_atom(), self._var(9, off=-64), self._ref(older))
        assert not self._dead(self._def(v), self._call(SCANF, fmt, self._ref(v)), self._branch_on(v), use=ptr)


if __name__ == "__main__":
    unittest.main()

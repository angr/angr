#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Insert,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Return, Store
from angr.knowledge_plugins.functions import Function


class TestInsertLowBitsReads(unittest.TestCase):
    """_propagate_insert_low_bits_reads copies an inserted value into truncating reads, but not a large one."""

    @staticmethod
    def _simplify(value_terms: int) -> list:
        proj = angr.load_shellcode(b"\xc3", "AMD64")
        regs = proj.arch.registers
        rdi = VirtualVariable(1, 1, 64, VirtualVariableCategory.REGISTER, oident=regs["rdi"][0])
        rsi = VirtualVariable(2, 2, 64, VirtualVariableCategory.REGISTER, oident=regs["rsi"][0])
        v = VirtualVariable(3, 3, 64, VirtualVariableCategory.REGISTER, oident=regs["rax"][0])
        idx = iter(range(100, 10000))

        # an 8-bit value of 2 * value_terms + 1 nodes
        value = Convert(next(idx), 64, 8, False, rsi)
        for i in range(value_terms):
            value = BinaryOp(next(idx), "Xor", [value, Const(next(idx), i + 1, 8)], False, bits=8)

        def read():
            return Convert(next(idx), 64, 8, False, VirtualVariable(next(idx), 3, 64, v.category, oident=v.oident))

        block = Block(
            0x401000,
            0x10,
            statements=[
                Assignment(0, v, Insert(next(idx), rdi, Const(next(idx), 0, 64), value, "Iend_LE"), ins_addr=0x401000),
                Store(
                    1,
                    Const(next(idx), 0x500000, 64),
                    BinaryOp(next(idx), "Add", [read(), read()], False, bits=8),
                    1,
                    "Iend_LE",
                    ins_addr=0x401004,
                ),
                Return(2, [VirtualVariable(next(idx), 3, 64, v.category, oident=v.oident)], ins_addr=0x401008),
            ],
            idx=0,
        )
        graph = networkx.DiGraph()
        graph.add_node(block)
        func = Function(proj.kb.functions, 0x401000)
        simp = proj.analyses.AILSimplifier(func, func_graph=graph, ail_manager=ailment.Manager())
        return next(iter(simp.func_graph)).statements

    @staticmethod
    def _store_reads_vvar(stmts) -> bool:
        store = next(s for s in stmts if isinstance(s, Store))
        return all(isinstance(op, Convert) and isinstance(op.operand, VirtualVariable) for op in store.data.operands)

    def test_small_value_is_copied(self):
        assert not self._store_reads_vvar(self._simplify(2))

    def test_large_value_is_not_duplicated(self):
        assert self._store_reads_vvar(self._simplify(20))


if __name__ == "__main__":
    unittest.main()

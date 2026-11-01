#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import BinaryOp, Const, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return, Store
from angr.knowledge_plugins.functions import Function


class _NodeCounter(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.count = 0

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        self.count += 1
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


def _nodes(stmt) -> int:
    counter = _NodeCounter()
    counter.walk_statement(stmt)
    return counter.count


class TestVMShallowDefDuplication(unittest.TestCase):
    """SPropagator (VM bodies) copies a shallow stack-slot definition into every use in one statement."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\xc3", "AMD64")
        self.proj.vm_deobfuscation = True
        self.idx = iter(range(100, 1_000_000))
        self.rdi = VirtualVariable(
            next(self.idx), 1, 64, VirtualVariableCategory.REGISTER, oident=self.proj.arch.registers["rdi"][0]
        )

    def _slot(self, i):
        return VirtualVariable(next(self.idx), 10 + i, 64, VirtualVariableCategory.STACK, oident=-8 * (i + 1))

    def _use(self, vvar):
        # another occurrence of vvar: a distinct expression index, as in lifted code
        return VirtualVariable(next(self.idx), vvar.varid, vvar.bits, vvar.category, oident=vvar.oident)

    def _bin(self, op, a, b):
        return BinaryOp(next(self.idx), op, [a, b], False, bits=64)

    def _const(self, v, bits=64):
        return Const(next(self.idx), v, bits)

    def _simplify(self, stmts, rounds=1):
        stmts = [*stmts, Return(len(stmts), [], ins_addr=0x402004)]
        graph = networkx.DiGraph()
        graph.add_node(Block(0x401000, 0x10, statements=stmts, idx=0))
        func = Function(self.proj.kb.functions, 0x401000)
        for _ in range(rounds):
            simp = self.proj.analyses.AILSimplifier(
                func, func_graph=graph, ail_manager=ailment.Manager(), remove_dead_memdefs=False
            )
            graph = simp.func_graph
        return next(iter(graph)).statements

    def test_duplicated_into_a_deep_statement(self):
        # s = ~(rdi >> 32), used twice in a statement already past the depth guard: MBA folds need it inline
        s = self._slot(0)
        data = self._bin("Xor", self._bin("Add", s, self._const(5)), self._bin("Mul", self._use(s), self._const(3)))
        for i in range(14):
            data = self._bin("Add", data, self._const(i + 1))
        high = self._bin("Shr", self.rdi, self._const(32, 8))
        stmts = [
            Assignment(0, s, UnaryOp(next(self.idx), "BitwiseNeg", high, bits=64), ins_addr=0x401000),
            Store(1, self._const(0x500000), data, 8, "Iend_LE", ins_addr=0x401004),
        ]
        store = next(st for st in self._simplify(stmts) if isinstance(st, Store))
        assert store.data.depth > 13
        assert "vvar_10" not in str(store) and str(store).count("BitwiseNeg") == 2

    def test_duplication_chain_stays_bounded(self):
        # s_i = (s_{i-1} >> 3) | (s_{i-1} * 7): each fold doubles the uses, but also deepens the definition it lands
        # in, so the chain stops after two levels instead of growing as 2**n
        stmts = []
        prev = self.rdi
        for i in range(24):
            s = self._slot(i)
            src = self._bin(
                "Or", self._bin("Shr", prev, self._const(3, 8)), self._bin("Mul", self._use(prev), self._const(7))
            )
            stmts.append(Assignment(i, s, src, ins_addr=0x401000 + i))
            prev = s
        stmts.append(Store(len(stmts), self._const(0x500000), prev, 8, "Iend_LE", ins_addr=0x402000))
        out = self._simplify(stmts, rounds=8)
        largest = max(_nodes(st) for st in out)
        assert 7 * 2 < largest <= 64


if __name__ == "__main__":
    unittest.main()

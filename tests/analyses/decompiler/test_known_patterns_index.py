#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import networkx

import angr
from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Return
from angr.analyses.decompiler.known_patterns import KnownPattern, KnownPatternFinder, PAny, PBinOp, PChoice, PConst
from angr.analyses.decompiler.known_patterns.dsl import expr_const_operands, pattern_index_keys
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _mul_pattern(name, const=None):
    operand = PAny() if const is None else PConst(values=frozenset({const}))
    return KnownPattern(
        name=name, display_name=name, call_name=name, pattern=PBinOp("Mul", (PAny(), operand)), params=()
    )


class TestIndexKeys(unittest.TestCase):
    def test_a_constant_operand_becomes_part_of_the_key(self):
        keys = pattern_index_keys(PBinOp("Mul", (PAny(), PConst(values=frozenset({3, 5})))))
        assert keys == [("BinaryOp", "Mul", 3), ("BinaryOp", "Mul", 5)]
        assert pattern_index_keys(PBinOp("Mul", (PAny(), PConst(value=7)))) == [("BinaryOp", "Mul", 7)]

    def test_operator_sets_expand_instead_of_collapsing(self):
        keys = pattern_index_keys(PBinOp(frozenset({"Shr", "Sar"}), (PAny(), PAny())))
        assert keys == [("BinaryOp", "Sar", None), ("BinaryOp", "Shr", None)]

    def test_a_choice_is_the_union_of_its_alternatives(self):
        node = PChoice(PBinOp("Add", (PAny(), PAny())), PBinOp("Sub", (PAny(), PConst(value=1))))
        assert pattern_index_keys(node) == [("BinaryOp", "Add", None), ("BinaryOp", "Sub", 1)]
        assert pattern_index_keys(PChoice(PAny(), PBinOp("Add", (PAny(), PAny())))) is None

    def test_a_predicate_constant_stays_unindexed(self):
        keys = pattern_index_keys(PBinOp("Mul", (PAny(), PConst(pred=lambda v: v > 0))))
        assert keys == [("BinaryOp", "Mul", None)], "a predicate cannot be enumerated, so the op alone is the key"

    def test_literal_operands_of_an_expression(self):
        manager = Manager()
        x = VirtualVariable(manager.next_atom(), 1, 64, VirtualVariableCategory.REGISTER, oident=16)
        expr = BinaryOp(manager.next_atom(), "Mul", [x, Const(manager.next_atom(), 9, 64)], False)
        assert expr_const_operands(expr) == (9,)
        assert expr_const_operands(x) == ()


class TestFinderIndex(unittest.TestCase):
    """A thousand Mul-keyed patterns that each need their own constant must not all be
    tried at every multiply. This is the std::vector<T>::size family on a Warbird function."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.func = cfg.functions["main"]

    def _graph(self, n_muls: int):
        manager = Manager()
        stmts = []
        for i in range(n_muls):
            x = VirtualVariable(manager.next_atom(), 10 + i, 64, VirtualVariableCategory.REGISTER, oident=16)
            y = VirtualVariable(manager.next_atom(), 1000 + i, 64, VirtualVariableCategory.REGISTER, oident=24)
            # multiplies by a constant no pattern asks for
            mul = BinaryOp(manager.next_atom(), "Mul", [x, Const(manager.next_atom(), 0x7777 + i, 64)], False)
            stmts.append(Assignment(manager.next_atom(), y, mul))
        stmts.append(Return(manager.next_atom(), []))
        block = Block(self.func.addr, 1, statements=stmts)
        graph = networkx.DiGraph()
        graph.add_node(block)
        return graph

    def _count(self, patterns, graph) -> int:
        calls = 0
        original = KnownPatternFinder._try_match

        def spy(self, *args, **kwargs):
            nonlocal calls
            calls += 1
            return original(self, *args, **kwargs)

        KnownPatternFinder._try_match = spy
        try:
            self.proj.analyses.KnownPatternFinder(self.func, graph, patterns=patterns)
        finally:
            KnownPatternFinder._try_match = original
        return calls

    def test_constant_keyed_patterns_are_only_tried_where_their_constant_is(self):
        patterns = [_mul_pattern(f"vec{c}", const=c) for c in range(1, 1001)]
        graph = self._graph(50)
        calls = self._count(patterns, graph)
        assert calls == 0, f"no multiply carries any of the thousand constants, yet {calls} attempts were made"

    def test_an_unconstrained_pattern_is_still_tried_at_every_multiply(self):
        patterns = [_mul_pattern(f"vec{c}", const=c) for c in range(1, 1001)] + [_mul_pattern("any_mul")]
        calls = self._count(patterns, self._graph(50))
        assert calls == 50

    def test_a_pattern_whose_constant_occurs_is_tried_there(self):
        patterns = [_mul_pattern(f"vec{c}", const=c) for c in range(1, 1001)] + [_mul_pattern("hit", const=0x7777)]
        calls = self._count(patterns, self._graph(50))
        assert calls == 1


if __name__ == "__main__":
    unittest.main()

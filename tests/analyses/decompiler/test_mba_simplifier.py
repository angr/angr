#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment.expression import BinaryOp, Const, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.mba_simplifier import (
    ComposedMBASimplifier,
    LinearMBASolver,
    MBATemplateSimplifier,
)

BITS = 64


class TestMBATemplateSimplifier(unittest.TestCase):
    def setUp(self):
        self.m = Manager(arch=None)
        self.s = MBATemplateSimplifier(ail_manager=self.m)
        self.x = Register(self.m.next_atom(), 16, BITS)
        self.y = Register(self.m.next_atom(), 24, BITS)

    def _c(self, v):
        return Const(self.m.next_atom(), v, BITS)

    def _b(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=BITS)

    def _u(self, op, a):
        return UnaryOp(self.m.next_atom(), op, a)

    def test_recognises_the_classic_identities(self):
        x, y = self.x, self.y
        cases = [
            # (x ^ y) + 2*(x & y)  ==  x + y
            (self._b("Add", self._b("Xor", x, y), self._b("Mul", self._c(2), self._b("And", x, y))), "Add"),
            # (x | y) + (x & y)  ==  x + y
            (self._b("Add", self._b("Or", x, y), self._b("And", x, y)), "Add"),
            # (x | y) - (x & y)  ==  x ^ y
            (self._b("Sub", self._b("Or", x, y), self._b("And", x, y)), "Xor"),
            # x + y - 2*(x & y)  ==  x ^ y
            (self._b("Sub", self._b("Add", x, y), self._b("Mul", self._c(2), self._b("And", x, y))), "Xor"),
            # (x & ~y) | (~x & y)  ==  x ^ y
            (
                self._b(
                    "Or",
                    self._b("And", x, self._u("BitwiseNeg", y)),
                    self._b("And", self._u("BitwiseNeg", x), y),
                ),
                "Xor",
            ),
        ]
        for expr, expected_op in cases:
            out = self.s.simplify(expr)
            assert out is not None, f"{expr} was not recognised"
            assert out.op == expected_op, f"{expr} -> {out}, expected a {expected_op}"

    def test_leaves_a_non_identity_alone(self):
        # x + (x & y) is not any of the templates; it must not be rewritten into one
        expr = self._b("Add", self.x, self._b("And", self.x, self._b("Or", self.x, self.y)))
        assert self.s.simplify(expr) is None

    def test_refuses_expressions_outside_the_mba_fragment(self):
        # a shift is not in the fragment, so the subtree is not analysed at all
        shifted = self._b("Shl", self.x, self._c(3))
        expr = self._b("Add", self._b("Xor", self.x, self.y), shifted)
        assert self.s.simplify(expr) is None

    def test_refuses_mixed_widths(self):
        narrow = Register(self.m.next_atom(), 32, 32)
        expr = BinaryOp(self.m.next_atom(), "Add", [self._b("Xor", self.x, self.y), narrow], False, bits=BITS)
        assert self.s.simplify(expr) is None

    def test_small_expressions_are_left_alone(self):
        # nothing to gain: the template would be no smaller than the expression
        assert self.s.simplify(self._b("Xor", self.x, self.y)) is None

    def test_every_rewrite_is_proved(self):
        """A rewrite only happens after the solver agrees; the counter must reflect that."""
        expr = self._b("Add", self._b("Or", self.x, self.y), self._b("And", self.x, self.y))
        assert self.s.simplify(expr) is not None
        assert self.s.simplified == 1
        assert self.s.verified_away == 0



class TestLinearMBASolver(unittest.TestCase):
    """Synthesis finds the simplest equivalent instead of matching a fixed list."""

    def setUp(self):
        self.m = Manager(arch=None)
        self.s = LinearMBASolver(ail_manager=self.m)
        self.x = Register(self.m.next_atom(), 16, BITS)
        self.y = Register(self.m.next_atom(), 24, BITS)
        self.z = Register(self.m.next_atom(), 32, BITS)

    def _c(self, v):
        return Const(self.m.next_atom(), v, BITS)

    def _b(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=BITS)

    def _u(self, op, a):
        return UnaryOp(self.m.next_atom(), op, a)

    def test_synthesises_the_classic_identities(self):
        x, y = self.x, self.y
        cases = [
            (self._b("Add", self._b("Xor", x, y), self._b("Add", self._b("And", x, y), self._b("And", x, y))), "Add"),
            (self._b("Add", self._b("Or", x, y), self._b("And", x, y)), "Add"),
            (self._b("Sub", self._b("Or", x, y), self._b("And", x, y)), "Xor"),
        ]
        for expr, expected in cases:
            out = self.s.synthesize(expr)
            assert out is not None, f"{expr} was not reduced"
            assert out.op == expected, f"{expr} -> {out}"

    def test_unwraps_a_double_negation(self):
        # -(~x) - 1 == x
        expr = self._b("Sub", self._u("Neg", self._u("BitwiseNeg", self.x)), self._c(1))
        out = self.s.synthesize(expr)
        assert out is not None and out.likes(self.x)

    def test_never_trades_arithmetic_for_boolean(self):
        """
        `(x ^ y) + z + 1` and `z - ~(x ^ y)` are equal, and the second has fewer nodes -- but it
        is the more obfuscated of the two. Optimising node count picks it; the cost model must not.
        """
        expr = self._b("Add", self._b("Xor", self.x, self.y), self._b("Add", self.z, self._c(1)))
        assert self.s.synthesize(expr) is None

    def test_cost_prices_boolean_above_arithmetic(self):
        arithmetic = self._b("Add", self.x, self.y)
        boolean = self._b("Xor", self.x, self.y)
        assert LinearMBASolver._cost_of(boolean) > LinearMBASolver._cost_of(arithmetic)

    def test_refuses_more_variables_than_it_can_enumerate(self):
        w = Register(self.m.next_atom(), 40, BITS)
        expr = self._b(
            "Add",
            self._b("Xor", self.x, self.y),
            self._b("Add", self._b("And", self.z, w), self._c(1)),
        )
        assert self.s.synthesize(expr) is None


class TestComposedMBASimplifier(unittest.TestCase):
    """Composing the definition chain, so a value is characterised by behaviour not by shape."""

    def _graph(self):
        import networkx
        from angr.ailment.block import Block
        from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
        from angr.ailment.statement import Assignment

        m = Manager(arch=None)

        def vvar(varid, bits=8):
            return VirtualVariable(m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=varid)

        def c(v, bits=8):
            return Const(m.next_atom(), v, bits)

        def b(op, x, y, bits=8):
            return BinaryOp(m.next_atom(), op, [x, y], False, bits=bits)

        # v1 = input ^ 0x5a ; v2 = v1 + 7 ; v3 = (v2 - 7) ^ 0x5a   -- an obfuscated identity
        src = vvar(100)
        stmts = [
            Assignment(m.next_atom(), vvar(1), b("Xor", src, c(0x5A)), ins_addr=0x1000),
            Assignment(m.next_atom(), vvar(2), b("Add", vvar(1), c(7)), ins_addr=0x1004),
            Assignment(m.next_atom(), vvar(3), b("Xor", b("Sub", vvar(2), c(7)), c(0x5A)), ins_addr=0x1008),
        ]
        block = Block(0x1000, 12, statements=stmts)
        graph = networkx.DiGraph()
        graph.add_node(block)
        return graph, m, vvar(3), str(src)

    def test_composes_a_chain_into_its_behaviour(self):
        graph, m, target, input_name = self._graph()
        c = ComposedMBASimplifier(graph, ail_manager=m)
        got = c.characterize(target)
        assert got is not None, "the chain was not characterised"
        names, table, space = got
        assert names == [input_name]
        assert space == 256
        assert table == list(range(256)), "the chain is an identity and the table should say so"

    def test_finds_the_true_inputs_through_definitions(self):
        graph, m, target, input_name = self._graph()
        c = ComposedMBASimplifier(graph, ail_manager=m)
        assert c._inputs_of(target, frozenset()) == {input_name}

    def test_evaluation_agrees_with_the_chain(self):
        graph, m, target, input_name = self._graph()
        c = ComposedMBASimplifier(graph, ail_manager=m)
        for probe in (0, 1, 0x5A, 0x7F, 0xFF):
            assert c.evaluate(target, {input_name: probe}, {}) == probe


class TestComposedSynthesis(unittest.TestCase):
    """Synthesis driven by composed behaviour rather than by the shape of one subtree."""

    def _chain(self, obfuscate):
        import networkx
        from angr.ailment.block import Block
        from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
        from angr.ailment.statement import Assignment

        m = Manager(arch=None)

        def vvar(varid, bits=8):
            return VirtualVariable(m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=varid)

        def c(v, bits=8):
            return Const(m.next_atom(), v, bits)

        def b(op, x, y):
            return BinaryOp(m.next_atom(), op, [x, y], False, bits=8)

        src = vvar(100)
        stmts = [Assignment(m.next_atom(), vvar(1), obfuscate(src, b, c), ins_addr=0x1000)]
        block = Block(0x1000, 4, statements=stmts)
        graph = networkx.DiGraph()
        graph.add_node(block)
        return graph, m, vvar(1), src

    def test_sees_through_a_chain_to_the_input(self):
        # ((x ^ 0x5a) + 7 - 7) ^ 0x5a  ==  x, spread over one long expression
        def obf(x, b, c):
            return b("Xor", b("Sub", b("Add", b("Xor", x, c(0x5A)), c(7)), c(7)), c(0x5A))

        graph, m, target, src = self._chain(obf)
        s = ComposedMBASimplifier(graph, ail_manager=m)
        out = s.simplify(target)
        assert out is not None, "the chain was not seen through"
        assert out.likes(src), f"expected the input back, got {out}"

    def test_recovers_an_addition_hidden_in_boolean_form(self):
        # (x ^ 0x33) + 0x33 is not x, but it is affine; the search should find something cheaper
        def obf(x, b, c):
            return b("Add", b("Xor", b("Xor", x, c(0x33)), c(0x33)), c(5))

        graph, m, target, src = self._chain(obf)
        s = ComposedMBASimplifier(graph, ail_manager=m)
        out = s.simplify(target)
        assert out is not None
        assert LinearMBASolver._cost_of(out) < s._composed_cost(target)

    def test_refuses_when_the_space_was_only_sampled(self):
        """A match on samples is evidence, not proof, and must not be acted on."""
        import networkx
        from angr.ailment.block import Block
        from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
        from angr.ailment.statement import Assignment

        m = Manager(arch=None)
        wide_in = VirtualVariable(m.next_atom(), 200, 64, VirtualVariableCategory.REGISTER, oident=200)
        dst = VirtualVariable(m.next_atom(), 201, 64, VirtualVariableCategory.REGISTER, oident=201)
        # a 64-bit value whose whole width matters: too large to enumerate
        src = BinaryOp(m.next_atom(), "Mul", [wide_in, Const(m.next_atom(), 0x9E3779B9, 64)], False, bits=64)
        block = Block(0x1000, 4, statements=[Assignment(m.next_atom(), dst, src, ins_addr=0x1000)])
        graph = networkx.DiGraph()
        graph.add_node(block)
        s = ComposedMBASimplifier(graph, ail_manager=m)
        assert s.simplify(dst) is None

if __name__ == "__main__":
    unittest.main()

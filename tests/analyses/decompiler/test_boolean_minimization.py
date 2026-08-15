from __future__ import annotations

import random

import claripy

from angr.analyses.decompiler.boolean_minimization import MinimizedFormula, atom_column, full_table, minimize
from angr.analyses.decompiler.condition_processor import ConditionProcessor


def _evaluate(formula: bool | MinimizedFormula, num_atoms: int) -> int:
    """
    Evaluate a minimized formula back into a truth table, so it can be compared against the input.
    """

    if formula is True:
        return full_table(num_atoms)
    if formula is False:
        return 0

    all_ones = full_table(num_atoms)
    columns = [atom_column(atom_id, num_atoms) for atom_id in range(num_atoms)]

    def _literal(literal: int) -> int:
        column = columns[abs(literal) - 1]
        return column if literal > 0 else all_ones & ~column

    if formula.is_sop:
        table = 0
        for term in formula.terms:
            product = all_ones
            for literal in term:
                product &= _literal(literal)
            table |= product
        return table

    table = all_ones
    for clause in formula.terms:
        total = 0
        for literal in clause:
            total |= _literal(literal)
        table &= total
    return table


def test_atom_column():
    assert atom_column(0, 1) == 0b10
    assert atom_column(0, 2) == 0b1010
    assert atom_column(1, 2) == 0b1100
    assert full_table(2) == 0b1111
    assert full_table(3) == 0xFF


def test_minimize_is_exhaustively_correct_for_small_formulas():
    for num_atoms in (0, 1, 2, 3):
        for truth_table in range(1 << (1 << num_atoms)):
            formula = minimize(truth_table, num_atoms)
            assert _evaluate(formula, num_atoms) == truth_table, (num_atoms, truth_table, formula)


def test_minimize_is_correct_for_random_formulas():
    rand = random.Random(0xDECAFBAD)
    for num_atoms in range(4, 9):
        for _ in range(25):
            truth_table = rand.getrandbits(1 << num_atoms)
            formula = minimize(truth_table, num_atoms)
            assert _evaluate(formula, num_atoms) == truth_table, (num_atoms, truth_table, formula)


def test_minimize_constants():
    assert minimize(0, 3) is False
    assert minimize(full_table(3), 3) is True
    a = atom_column(0, 2)
    assert minimize(a & (full_table(2) & ~a), 2) is False
    assert minimize(a | (full_table(2) & ~a), 2) is True


def test_minimize_absorption_and_consensus():
    all_ones = full_table(3)
    a, b, c = (atom_column(i, 3) for i in range(3))

    formula = minimize((a & b) | (a & (all_ones & ~b)), 3)
    assert formula.terms == ((1,),)

    formula = minimize(a | ((all_ones & ~a) & b), 3)
    assert _evaluate(formula, 3) == a | b
    assert formula.literal_count == 2

    formula = minimize((a & b) | ((all_ones & ~a) & c) | (b & c), 3)
    assert len(formula.terms) == 2
    assert formula.literal_count == 4


class TestSimplifyCondition:
    """
    Tests for the claripy side of the minimizer: ConditionProcessor.simplify_condition.
    """

    @staticmethod
    def _equivalent(cond_a, cond_b) -> bool:
        return not claripy.Solver().satisfiable(extra_constraints=(cond_a != cond_b,))

    def test_absorption(self):
        p = claripy.BoolS("p", explicit_name=True)
        q = claripy.BoolS("q", explicit_name=True)
        simplified = ConditionProcessor.simplify_condition(claripy.Or(p, claripy.And(claripy.Not(p), q)))
        assert simplified is claripy.Or(p, q)

    def test_redundant_branch_collapses(self):
        p = claripy.BoolS("p", explicit_name=True)
        q = claripy.BoolS("q", explicit_name=True)
        simplified = ConditionProcessor.simplify_condition(
            claripy.Or(claripy.And(p, q), claripy.And(p, claripy.Not(q)))
        )
        assert simplified is p

    def test_comparisons_are_unified(self):
        x = claripy.BVS("x", 32, explicit_name=True)
        p = claripy.BoolS("p", explicit_name=True)
        cond = claripy.Or(claripy.And(x == 0, p), claripy.And(x != 0, p))
        assert ConditionProcessor.simplify_condition(cond) is p

    def test_unsigned_comparisons_are_unified(self):
        x = claripy.BVS("x", 32, explicit_name=True)
        y = claripy.BVS("y", 32, explicit_name=True)
        p = claripy.BoolS("p", explicit_name=True)
        cond = claripy.Or(claripy.And(claripy.ULT(x, y), p), claripy.And(claripy.UGE(x, y), p))
        assert ConditionProcessor.simplify_condition(cond) is p

    def test_over_the_limits_is_returned_untouched(self):
        cond = claripy.Or(*[claripy.BVS(f"v{i}", 32, explicit_name=True) == i for i in range(12)])
        assert ConditionProcessor.simplify_condition(cond) is cond

        cond = claripy.BoolS("b", explicit_name=True)
        for i in range(12):
            cond = claripy.And(cond, claripy.BoolS(f"b{i}", explicit_name=True))
        assert ConditionProcessor.simplify_condition(cond) is cond

    def test_random_conditions_stay_equivalent(self):
        rand = random.Random(0x1234)
        x, y, z = (claripy.BVS(name, 32, explicit_name=True) for name in ("x", "y", "z"))
        leaves = [
            x == 0,
            x != 0,
            x < y,
            x > y,
            x <= y,
            x >= y,
            claripy.ULT(x, y),
            claripy.UGE(x, y),
            y == z,
            claripy.BoolS("p", explicit_name=True),
            claripy.BoolS("q", explicit_name=True),
        ]

        def _random_condition(depth):
            if depth == 0:
                return rand.choice(leaves)
            roll = rand.random()
            if roll < 0.2:
                return claripy.Not(_random_condition(depth - 1))
            combine = claripy.And if roll < 0.6 else claripy.Or
            return combine(_random_condition(depth - 1), _random_condition(depth - 1))

        for _ in range(100):
            cond = _random_condition(rand.randint(1, 3))
            simplified = ConditionProcessor.simplify_condition(cond)
            assert isinstance(simplified, claripy.ast.Bool)
            assert self._equivalent(cond, simplified), f"{cond} became {simplified}"

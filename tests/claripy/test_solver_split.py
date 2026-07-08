from __future__ import annotations

import unittest

from angr import claripy


class TestSolverSplit(unittest.TestCase):
    """Solver.split() partitions constraints into independent (variable-connected)
    groups, returning one blank-copy solver per group (like claripy's
    constrained_frontend.split())."""

    def test_independent_groups(self):
        x = claripy.BVS("x", 32, explicit_name=True)
        y = claripy.BVS("y", 32, explicit_name=True)
        z = claripy.BVS("z", 32, explicit_name=True)
        s = claripy.Solver()
        s.add(x > 1)
        s.add(x < 10)
        s.add(y == z)
        groups = s.split()
        self.assertEqual(len(groups), 2)
        var_sets = sorted(sorted(g.variables) for g in groups)
        self.assertEqual(var_sets, [["x"], ["y", "z"]])

    def test_transitively_connected_constraints_stay_together(self):
        a = claripy.BVS("a", 32, explicit_name=True)
        b = claripy.BVS("b", 32, explicit_name=True)
        c = claripy.BVS("c", 32, explicit_name=True)
        s = claripy.Solver()
        s.add(a == b)
        s.add(b == c)
        groups = s.split()
        self.assertEqual(len(groups), 1)
        self.assertEqual(sorted(groups[0].variables), ["a", "b", "c"])

    def test_group_solvers_carry_their_constraints(self):
        x = claripy.BVS("x", 32, explicit_name=True)
        y = claripy.BVS("y", 32, explicit_name=True)
        s = claripy.Solver()
        s.add(x == 7)
        s.add(y == 9)
        groups = {tuple(sorted(g.variables)): g for g in s.split()}
        self.assertEqual(tuple(groups[("x",)].eval(x, 1)), (7,))
        self.assertEqual(tuple(groups[("y",)].eval(y, 1)), (9,))

    def test_empty_and_single_group(self):
        x = claripy.BVS("x", 32, explicit_name=True)
        self.assertEqual(claripy.Solver().split(), [])
        s = claripy.Solver()
        s.add(x > 0)
        s.add(x < 5)
        self.assertEqual(len(s.split()), 1)

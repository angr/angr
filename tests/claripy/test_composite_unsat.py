from __future__ import annotations

import unittest

from angr import claripy


class TestCompositeUnsat(unittest.TestCase):
    def test_add_false_does_not_raise(self):
        # claripy's CompositeFrontend records the unsat state instead of
        # raising from add(); it surfaces through satisfiable().
        solver = claripy.SolverComposite()
        solver.add(claripy.BoolV(False))
        self.assertFalse(solver.satisfiable())

    def test_contradictory_concrete_constraints(self):
        solver = claripy.SolverComposite()
        x = claripy.BVS("x", 32)
        solver.add(x == 1)
        solver.add(x == 2)
        self.assertFalse(solver.satisfiable())

    def test_satisfiable_when_consistent(self):
        solver = claripy.SolverComposite()
        x = claripy.BVS("x", 32)
        solver.add(x == 5)
        self.assertTrue(solver.satisfiable())
        self.assertEqual(tuple(solver.eval(x, 1)), (5,))

    def test_false_makes_otherwise_sat_solver_unsat(self):
        solver = claripy.SolverComposite()
        x = claripy.BVS("x", 32)
        solver.add(x == 5)
        self.assertTrue(solver.satisfiable())
        solver.add(claripy.BoolV(False))
        self.assertFalse(solver.satisfiable())

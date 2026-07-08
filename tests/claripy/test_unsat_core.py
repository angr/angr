from __future__ import annotations

import unittest

import claripy


class TestUnsatCore(unittest.TestCase):
    def test_unsat_core_simple(self):
        """Test basic unsat core functionality"""
        # Create a solver with unsat_core enabled
        s = claripy.Solver(track=True)

        x = claripy.BVS("x", 8)

        # Add contradictory constraints
        s.add(x > 10)  # constraint 0
        s.add(x < 5)  # constraint 1
        s.add(x > 0)  # constraint 2 (not part of unsat core)

        # Should be unsat
        self.assertFalse(s.satisfiable())

        # Get unsat core
        core = s.unsat_core()

        # Core should contain the contradictory constraints
        self.assertGreater(len(core), 0)
        self.assertIn(0, core)
        self.assertIn(1, core)
        # constraint 2 should not be necessary for unsat

    def test_unsat_core_bool(self):
        """Test unsat core with boolean constraints"""
        s = claripy.Solver(track=True)

        a = claripy.BoolS("a")
        b = claripy.BoolS("b")

        # Add contradictory constraints
        s.add(a == b)  # constraint 0
        s.add(a)  # constraint 1: a is true
        s.add(claripy.Not(b))  # constraint 2: b is false

        # Should be unsat
        self.assertFalse(s.satisfiable())

        # Get unsat core - all three constraints are necessary
        core = s.unsat_core()
        self.assertGreater(len(core), 0)

    def test_unsat_core_not_enabled(self):
        """Test that unsat_core raises error when not enabled"""
        s = claripy.Solver()  # unsat_core not enabled

        x = claripy.BVS("x", 8)
        s.add(x > 10)
        s.add(x < 5)

        self.assertFalse(s.satisfiable())

        # Should raise an error
        with self.assertRaises(claripy.ClaripyError):
            s.unsat_core()

    def test_unsat_core_on_sat(self):
        """Test that unsat_core raises error on SAT result"""
        s = claripy.Solver(track=True)

        x = claripy.BVS("x", 8)
        s.add(x > 5)

        # Should be sat
        self.assertTrue(s.satisfiable())

        # Should raise an error because it's SAT
        with self.assertRaises(claripy.ClaripyError):
            s.unsat_core()

    def test_unsat_core_complex(self):
        """Test unsat core with more complex constraints"""
        s = claripy.Solver(track=True)

        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)

        # Add various constraints
        s.add(x + y == 100)  # constraint 0
        s.add(x > 60)  # constraint 1
        s.add(y > 50)  # constraint 2 - makes it unsat with 0 and 1
        s.add(x < 200)  # constraint 3 - not relevant
        s.add(y < 200)  # constraint 4 - not relevant

        # Should be unsat (x > 60 and y > 50 means x + y > 110)
        self.assertFalse(s.satisfiable())

        # Get unsat core
        core = s.unsat_core()
        self.assertGreater(len(core), 0)
        # Core should contain 0, 1, and 2
        self.assertIn(0, core)
        self.assertIn(1, core)
        self.assertIn(2, core)

    def test_unsat_core_composite(self):
        """SolverComposite returns the core of whichever independent child is unsat."""
        s = claripy.SolverComposite(track=True)

        x = claripy.BVS("x", 8)
        y = claripy.BVS("y", 8)

        # Contradictory group on x (constraints 0, 1) plus an independent,
        # satisfiable group on y (constraint 2).
        s.add(x > 10)
        s.add(x < 5)
        s.add(y == 3)

        self.assertFalse(s.satisfiable())

        core = s.unsat_core()
        self.assertGreater(len(core), 0)
        self.assertIn(0, core)
        self.assertIn(1, core)
        # The independent, satisfiable constraint is not part of the core.
        self.assertNotIn(2, core)

    def test_unsat_core_composite_on_sat(self):
        """A satisfiable composite solver has an empty unsat core."""
        s = claripy.SolverComposite(track=True)
        x = claripy.BVS("x", 8)
        y = claripy.BVS("y", 8)
        s.add(x > 1)
        s.add(y < 10)
        self.assertTrue(s.satisfiable())
        self.assertEqual(s.unsat_core(), [])

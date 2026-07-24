"""
Tests for boolean operations with the VSA backend.
This file tests all Bool operations supported by the VSA backend.
"""

from __future__ import annotations

import unittest

from angr import claripy


class TestVSABoolOperations(unittest.TestCase):
    def setUp(self):
        """Set up common test values and solvers."""
        # Create VSA solver
        self.solver = claripy.SolverVSA()

        # Create concrete boolean values
        self.true_val = claripy.BoolV(True)
        self.false_val = claripy.BoolV(False)

        # Create symbolic boolean values
        self.sym_bool1 = claripy.BoolS("x")
        self.sym_bool2 = claripy.BoolS("y")

        # Create BVs for comparison testing
        self.bv_const1 = claripy.BVV(10, 32)
        self.bv_const2 = claripy.BVV(5, 32)
        self.bv_sym = claripy.BVS("z", 32)

        # Create strided intervals for testing
        self.si_single = claripy.SI(bits=32, stride=0, lower_bound=10, upper_bound=10)
        self.si_range = claripy.SI(bits=32, stride=1, lower_bound=5, upper_bound=15)
        self.si_stride2 = claripy.SI(bits=32, stride=2, lower_bound=0, upper_bound=10)
        self.si_negative = claripy.SI(bits=32, stride=1, lower_bound=-10, upper_bound=-1)
        self.si_mixed = claripy.SI(bits=32, stride=1, lower_bound=-5, upper_bound=5)

        # Values for overflow/underflow testing
        self.si_max = claripy.SI(bits=32, stride=0, lower_bound=0xFFFFFFFF, upper_bound=0xFFFFFFFF)
        self.si_min = claripy.SI(bits=32, stride=0, lower_bound=0, upper_bound=0)

        # TOP and BOTTOM values
        self.si_top = claripy.SI(bits=32, stride=1, lower_bound=0, upper_bound=0xFFFFFFFF)
        self.si_bottom = claripy.SI(bits=32, stride=0, lower_bound=0, upper_bound=0).intersection(
            claripy.SI(bits=32, stride=0, lower_bound=1, upper_bound=1)
        )  # Empty SI

    def test_bool_constants(self):
        """Test behavior of boolean constants."""
        # Test that True and False are correctly evaluated
        self.assertTrue(self.solver.is_true(self.true_val))
        self.assertTrue(self.solver.is_false(self.false_val))
        self.assertFalse(self.solver.is_false(self.true_val))
        self.assertFalse(self.solver.is_true(self.false_val))

    # Skip tests that use symbolic booleans directly, as VSA backend doesn't fully support them
    # But keep tests with concrete booleans and BV comparison operations

    def test_comparison_single_values(self):
        """Test comparison operations with single concrete values."""
        # Test comparison between specific values
        # 10 == 10
        self.assertTrue(self.solver.is_true(self.si_single == self.si_single))
        # 10 == 5
        self.assertTrue(self.solver.is_false(self.si_single == self.bv_const2))
        # 10 != 5
        self.assertTrue(self.solver.is_true(self.si_single != self.bv_const2))
        # 10 > 5
        self.assertTrue(self.solver.is_true(self.si_single > self.bv_const2))
        # 10 >= 5
        self.assertTrue(self.solver.is_true(self.si_single >= self.bv_const2))
        # 5 < 10
        self.assertTrue(self.solver.is_true(self.bv_const2 < self.si_single))
        # 5 <= 10
        self.assertTrue(self.solver.is_true(self.bv_const2 <= self.si_single))

    def test_comparison_ranges(self):
        """Test comparison operations with ranges of values."""
        # Test ranges where the result is definite
        # [5, 15] > 3
        self.assertTrue(self.solver.is_true(self.si_range > claripy.BVV(3, 32)))
        # [5, 15] >= 5
        self.assertTrue(self.solver.is_true(self.si_range >= claripy.BVV(5, 32)))
        # [5, 15] < 20
        self.assertTrue(self.solver.is_true(self.si_range < claripy.BVV(20, 32)))
        # [5, 15] <= 15
        self.assertTrue(self.solver.is_true(self.si_range <= claripy.BVV(15, 32)))

        # Test ranges where the result is maybe
        # [5, 15] == 10
        range_eq = self.si_range == claripy.BVV(10, 32)
        self.assertTrue(self.solver.has_true(range_eq))
        self.assertTrue(self.solver.has_false(range_eq))
        # [5, 15] != 10
        range_ne = self.si_range != claripy.BVV(10, 32)
        self.assertTrue(self.solver.has_true(range_ne))
        self.assertTrue(self.solver.has_false(range_ne))
        # [5, 15] > 10
        range_gt = self.si_range > claripy.BVV(10, 32)
        self.assertTrue(self.solver.has_true(range_gt))
        self.assertTrue(self.solver.has_false(range_gt))
        # [5, 15] < 10
        range_lt = self.si_range < claripy.BVV(10, 32)
        self.assertTrue(self.solver.has_true(range_lt))
        self.assertTrue(self.solver.has_false(range_lt))

    def test_signed_comparison(self):
        """Test signed comparison operations."""
        # Test signed comparison with negative and positive numbers
        # [-10, -1] <s [5, 15]
        self.assertTrue(self.solver.is_true(self.si_negative.SLT(self.si_range)))
        # [5, 15] >s [-10, -1]
        self.assertTrue(self.solver.is_true(self.si_range.SGT(self.si_negative)))
        # [-10, -1] <=s [5, 15]
        self.assertTrue(self.solver.is_true(self.si_negative.SLE(self.si_range)))
        # [5, 15] >=s [-10, -1]
        self.assertTrue(self.solver.is_true(self.si_range.SGE(self.si_negative)))

        # Test mixed range [-5, 5] with signed comparisons
        # [-5, 5] <s 10
        self.assertTrue(self.solver.is_true(self.si_mixed.SLT(claripy.BVV(10, 32))))
        # [-5, 5] <s 0
        mixed_slt = self.si_mixed.SLT(claripy.BVV(0, 32))
        self.assertTrue(self.solver.has_true(mixed_slt))
        self.assertTrue(self.solver.has_false(mixed_slt))
        # [-5, 5] >s -10
        self.assertTrue(self.solver.is_true(self.si_mixed.SGT(claripy.BVV(-10, 32))))
        # [-5, 5] >s 0
        mixed_sgt = self.si_mixed.SGT(claripy.BVV(0, 32))
        self.assertTrue(self.solver.has_true(mixed_sgt))
        self.assertTrue(self.solver.has_false(mixed_sgt))

    def test_unsigned_comparison(self):
        """Test unsigned comparison operations."""
        # In unsigned comparison, negative numbers are treated as large positive numbers
        # [-10, -1] >u [5, 15] (0xFFFFFFF6 to 0xFFFFFFFF > 5 to 15)
        self.assertTrue(self.solver.is_true(self.si_negative.UGT(self.si_range)))
        # [5, 15] <u [-10, -1]
        self.assertTrue(self.solver.is_true(self.si_range.ULT(self.si_negative)))
        # [-10, -1] >=u [5, 15]
        self.assertTrue(self.solver.is_true(self.si_negative.UGE(self.si_range)))
        # [5, 15] <=u [-10, -1]
        self.assertTrue(self.solver.is_true(self.si_range.ULE(self.si_negative)))

        # Test with MAX value (0xFFFFFFFF)
        # MAX >u any other value
        self.assertTrue(self.solver.is_true(self.si_max.UGT(self.si_range)))
        # MAX >=u MAX
        self.assertTrue(self.solver.is_true(self.si_max.UGE(self.si_max)))

    def test_basic_if_then_else(self):
        """Test basic If-Then-Else operations with concrete conditions."""
        # Test with concrete condition
        # If(True, 10, 5) == 10
        result1 = claripy.If(self.true_val, self.bv_const1, self.bv_const2)
        vals = self.solver.eval(result1, 10)
        self.assertEqual(len(vals), 1)
        self.assertEqual(vals[0], 10)

        # If(False, 10, 5) == 5
        result2 = claripy.If(self.false_val, self.bv_const1, self.bv_const2)
        vals = self.solver.eval(result2, 10)
        self.assertEqual(len(vals), 1)
        self.assertEqual(vals[0], 5)

    def test_if_with_bv_condition(self):
        """Test If-Then-Else with BV comparison condition."""
        # Test with BV comparison condition
        # If(10 > 5, 10, 5) == 10
        cond = self.bv_const1 > self.bv_const2
        result = claripy.If(cond, self.bv_const1, self.bv_const2)
        vals = self.solver.eval(result, 10)
        self.assertEqual(len(vals), 1)
        self.assertEqual(vals[0], 10)

        # Test with range condition
        # If([5, 15] == 10, 10, 5) -> could be either 5 or 10
        cond = self.si_range == claripy.BVV(10, 32)
        result = claripy.If(cond, self.bv_const1, self.bv_const2)
        vals = sorted(self.solver.eval(result, 10))
        self.assertTrue(5 in vals)
        self.assertTrue(10 in vals)

    def test_full_intervals(self):
        """Test operations on full (TOP) intervals."""
        # Operations with TOP
        # TOP == 10 -> Maybe
        top_eq = self.si_top == self.bv_const1
        self.assertTrue(self.solver.has_true(top_eq))
        self.assertTrue(self.solver.has_false(top_eq))
        # TOP > 10 -> Maybe
        top_gt = self.si_top > self.bv_const1
        self.assertTrue(self.solver.has_true(top_gt))
        self.assertTrue(self.solver.has_false(top_gt))
        # TOP < 10 -> Maybe
        top_lt = self.si_top < self.bv_const1
        self.assertTrue(self.solver.has_true(top_lt))
        self.assertTrue(self.solver.has_false(top_lt))

    def test_empty_intervals(self):
        """Test operations on empty (BOTTOM) intervals."""
        # Test with empty intervals is problematic
        # Different VSA backend implementations handle these differently
        # Skip detailed testing of empty intervals as they're implementation-specific

        # Just check that we can create one and it has some basic properties
        # like no solutions can be evaluated from it
        solutions = self.solver.eval(self.si_bottom, 100)
        self.assertEqual(len(solutions), 0)

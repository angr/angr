from __future__ import annotations

import unittest

import claripy as claripy
from claripy.fp import FSORT_FLOAT, RM
import math


class TestFPOperations(unittest.TestCase):
    def setUp(self):
        # Create concrete FP values for testing
        self.fp1 = claripy.FPV(1.5, FSORT_FLOAT)
        self.fp2 = claripy.FPV(2.5, FSORT_FLOAT)
        self.fp3 = claripy.FPV(2.8, FSORT_FLOAT)
        self.fp4 = claripy.FPV(1.4, FSORT_FLOAT)
        self.fp5 = claripy.FPV(99.13, FSORT_FLOAT)
        self.fp6 = claripy.FPV(1.04, FSORT_FLOAT)
        self.fp7 = claripy.FPV(4.0, FSORT_FLOAT)
        self.fp_zero = claripy.FPV(0.0, FSORT_FLOAT)
        self.fp_neg = claripy.FPV(-1.5, FSORT_FLOAT)
        self.fp_neg1 = claripy.FPV(-2.0, FSORT_FLOAT)
        self.fp_neg_zero = claripy.FPV(-0.0, FSORT_FLOAT)
        self.fp_inf = claripy.FPV(float("inf"), FSORT_FLOAT)
        self.fp_neg_inf = claripy.FPV(float("-inf"), FSORT_FLOAT)
        self.fp_nan = claripy.FPV(float("nan"), FSORT_FLOAT)

        self.z3 = claripy.SolverZ3()
        self.concrete = claripy.SolverConcrete()

    def _check_equal(self, expr, expected, *, check_bits=False, places=7):
        """
        Assert that a Claripy FP expression equals an expected value.

        Parameters
        ----------
        expr        : Claripy AST (concrete)
        expected    : float | claripy.FPV
        check_bits  : bool
                        if False (default), only compare numeric closeness
                        if True, compare raw bit-vectors as well
        places      : int, default 7

        """

        # if expr.symbolic:
        #     with self.assertRaises(claripy.ClaripyOperationError):
        #         _ = self.concrete.eval(expr, 1)[0]
        #     return

        expr_val = float(self.concrete.eval(expr, 1)[0])

        if hasattr(expected, "raw_to_bv"):  # expected is already FPV
            expected_val = float(self.concrete.eval(expected, 1)[0])
            expected_fp = expected
        else:  # expected is int/float
            expected_val = float(expected)
            expected_fp = None

        if not check_bits:  # Numeric test only when no bit check
            self.assertAlmostEqual(
                expr_val,
                expected_val,
                places=places,
                msg="Expression result does not match expected result.",
            )

        # Bit-pattern comparison
        if check_bits:
            if expected_fp is None:
                expected_fp = claripy.FPV(expected, FSORT_FLOAT)

            self.assertTrue(
                claripy.is_true(expr.raw_to_bv() == expected_fp.raw_to_bv()),
                msg="Bit-level result does not match IEEE-expected value",
            )

    def test_add(self):
        """Test addition operation"""
        result = self.fp1 + self.fp2
        self._check_equal(result, 4.0)

        result = self.fp1 + self.fp3
        self._check_equal(result, 4.3, check_bits=True)

        result = self.fp5 + self.fp6
        self._check_equal(result, 100.17, check_bits=True)

        result = self.fp2 + self.fp_neg
        self._check_equal(result, 1.0)

        result = self.fp_neg + self.fp_neg
        self._check_equal(result, -3.0)

        result = self.fp1 + self.fp_zero
        self._check_equal(result, 1.5)

        result = self.fp1 + self.fp_neg_zero
        self._check_equal(result, 1.5)

        result = self.fp1 + self.fp_neg
        self._check_equal(result, 0)

    def test_sub(self):
        """Test subtraction operation"""
        result = self.fp2 - self.fp1
        self._check_equal(result, 1.0)

        result = self.fp2 - self.fp_neg
        self._check_equal(result, 4.0)

        result = self.fp1 - self.fp1
        self._check_equal(result, 0.0)

    def test_mul(self):
        """Test multiplication operation"""
        # Positive * Positive
        result = self.fp1 * self.fp2
        self._check_equal(result, 3.75)

        # Positive * Negative
        result = self.fp1 * self.fp_neg
        self._check_equal(result, -2.25)

        # Negative * Negative
        result = self.fp1 * self.fp_neg1
        self._check_equal(result, -3.0)

        # Test multiplication with zero
        result = self.fp1 * self.fp_zero
        self._check_equal(result, 0.0)

        # Test multiplication with negative zero
        result = self.fp1 * self.fp_neg_zero
        self._check_equal(result, 0.0)

    def test_div(self):
        """Test division operation"""
        # Test regular division

        result = self.fp1 / self.fp2
        self._check_equal(result, 0.6)

        result = self.fp2 / self.fp1
        self._check_equal(result, 1.6666665077, check_bits=True)

        result = self.fp3 / self.fp4
        self._check_equal(result, 2.0)

        result = self.fp1 / self.fp_neg
        self._check_equal(result, -1.0)

        # Test infinity division -> NaN
        result = self.fp_inf / self.fp_inf
        self._check_equal(result, float("nan"), check_bits=True)

        # 0/0 → NaN
        result = self.fp_zero / self.fp_zero
        self._check_equal(result, float("nan"), check_bits=True)

        # zero numerator → zero
        result = self.fp_zero / self.fp1
        self._check_equal(result, 0.0)

        # zero numerator and infinity denominator → zero
        result = self.fp_zero / self.fp_inf
        self._check_equal(result, 0.0)

        # Finite numerator and infinity denominator → zero
        result = self.fp1 / self.fp_inf
        self._check_equal(result, 0.0)

        # Positive numerator division by negative zero → negative infinity
        result = self.fp1 / self.fp_neg_zero
        self._check_equal(result, float("-inf"), check_bits=True)

        # Negative numerator division by negative zero → positive infinity
        result = self.fp_neg / self.fp_neg_zero
        self._check_equal(result, float("inf"), check_bits=True)

        # Positive numerator division by positive zero → positive infinity
        result = self.fp1 / self.fp_zero
        self._check_equal(result, float("inf"), check_bits=True)

        # Negative numerator division by positive zero → negative infinity
        result = self.fp_neg / self.fp_zero
        self._check_equal(result, float("-inf"), check_bits=True)

    def test_neg(self):
        """Test negation"""
        result = -(self.fp1)
        self._check_equal(result, -1.5)

        result = -(self.fp_neg1)
        self._check_equal(result, 2)

        result = -(self.fp_zero)
        self._check_equal(result, -0.0, check_bits=True)

        result = -(self.fp_neg_zero)
        self._check_equal(result, 0.0, check_bits=True)

    def test_abs(self):
        """Test absolute value"""
        result = abs(self.fp_neg)
        self._check_equal(result, 1.5)

        result = abs(self.fp1)
        self._check_equal(result, 1.5)

        result = abs(self.fp_neg_zero)
        self._check_equal(result, 0.0, check_bits=True)

        result = abs(self.fp_neg_inf)
        self._check_equal(result, float("inf"), check_bits=True)

    def test_eq(self):
        """Test equality"""

        # Test equality with different values
        result = self.fp1 == self.fp2
        self._check_equal(result, False)

        result = self.fp1 == self.fp_neg1
        self._check_equal(result, False)

        result = self.fp_neg_zero == self.fp_zero
        self._check_equal(result, False)

        result = self.fp_neg_inf == self.fp_inf
        self._check_equal(result, False)

        # Test equality with same values
        result = self.fp1 == self.fp1
        self._check_equal(result, True)

        result = self.fp_zero == self.fp_zero
        self._check_equal(result, True)

        result = self.fp_neg_zero == self.fp_neg_zero
        self._check_equal(result, True)

        result = self.fp_inf == self.fp_inf
        self._check_equal(result, True)

        result = self.fp_neg_inf == self.fp_neg_inf
        self._check_equal(result, True)

    def test_ne(self):
        """Test inequality"""

        # Test inequality with different values
        result = self.fp1 != self.fp2
        self._check_equal(result, True)

        result = self.fp1 != self.fp_neg1
        self._check_equal(result, True)

        result = self.fp_neg_zero != self.fp_zero
        self._check_equal(result, True)

        result = self.fp_neg_inf != self.fp_inf
        self._check_equal(result, True)

        # Test inequality with same values
        result = self.fp1 != self.fp1
        self._check_equal(result, False)

        result = self.fp_zero != self.fp_zero
        self._check_equal(result, False)

        result = self.fp_neg_zero != self.fp_neg_zero
        self._check_equal(result, False)

        result = self.fp_inf != self.fp_inf
        self._check_equal(result, False)

        result = self.fp_neg_inf != self.fp_neg_inf
        self._check_equal(result, False)

    def test_lt(self):
        """Test less-than (<) for all operand kinds"""

        # Finite positives
        result = self.fp1 < self.fp2
        self._check_equal(result, True)

        result = self.fp2 < self.fp1
        self._check_equal(result, False)

        # Finite negatives
        result = self.fp_neg1 < self.fp_neg
        self._check_equal(result, True)

        result = self.fp_neg < self.fp_neg1
        self._check_equal(result, False)

        # Mixed sign
        result = self.fp_zero < self.fp_neg
        self._check_equal(result, False)

        result = self.fp_neg < self.fp_zero
        self._check_equal(result, True)

        result = self.fp1 < self.fp_neg_zero
        self._check_equal(result, False)

        result = self.fp_neg_zero < self.fp1
        self._check_equal(result, True)

        result = self.fp1 < self.fp_neg1
        self._check_equal(result, False)

        result = self.fp_neg1 < self.fp1
        self._check_equal(result, True)

        # zeros (+0 and −0 are equal, so < is False both ways)
        result = self.fp_neg_zero < self.fp_zero
        self._check_equal(result, False)

        result = self.fp_zero < self.fp_neg_zero
        self._check_equal(result, False)

        # finite vs ±∞
        result = self.fp1 < self.fp_inf
        self._check_equal(result, True)

        result = self.fp_neg_inf < self.fp1
        self._check_equal(result, True)

        result = self.fp_inf < self.fp1
        self._check_equal(result, False)

        result = self.fp_inf < self.fp_inf
        self._check_equal(result, False)  # ∞ < ∞ is False

        result = self.fp_neg_inf < self.fp_neg_inf
        self._check_equal(result, False)

        # Infinities
        result = self.fp_neg_inf < self.fp_inf
        self._check_equal(result, True)

        result = self.fp_inf < self.fp_neg_inf
        self._check_equal(result, False)

        # NaN comparisons: all ordered comparisons are False
        result = self.fp_nan < self.fp1
        self._check_equal(result, False)

        result = self.fp1 < self.fp_nan
        self._check_equal(result, False)

        result = self.fp_nan < self.fp_nan
        self._check_equal(result, False)

    def test_leq(self):
        """Test less‑than‑or‑equal (<=) for all operand kinds"""

        # Finite positives
        result = self.fp1 <= self.fp2
        self._check_equal(result, True)

        result = self.fp2 <= self.fp1
        self._check_equal(result, False)

        result = self.fp1 <= self.fp1
        self._check_equal(result, True)

        # Finite negatives
        result = self.fp_neg1 <= self.fp_neg
        self._check_equal(result, True)

        result = self.fp_neg <= self.fp_neg1
        self._check_equal(result, False)

        result = self.fp_neg1 <= self.fp_neg1
        self._check_equal(result, True)

        # Mixed sign
        result = self.fp_zero <= self.fp_neg
        self._check_equal(result, False)

        result = self.fp_neg <= self.fp_zero
        self._check_equal(result, True)

        result = self.fp1 <= self.fp_neg_zero
        self._check_equal(result, False)

        result = self.fp_neg_zero <= self.fp1
        self._check_equal(result, True)

        result = self.fp1 <= self.fp_neg1
        self._check_equal(result, False)

        result = self.fp_neg1 <= self.fp1
        self._check_equal(result, True)

        # zeros (+0 and −0 are equal, so ≤ is True both ways)
        result = self.fp_neg_zero <= self.fp_zero
        self._check_equal(result, True)

        result = self.fp_zero <= self.fp_neg_zero
        self._check_equal(result, True)

        # finite vs ±∞
        result = self.fp1 <= self.fp_inf
        self._check_equal(result, True)

        result = self.fp_neg_inf <= self.fp1
        self._check_equal(result, True)

        result = self.fp_inf <= self.fp1
        self._check_equal(result, False)

        result = self.fp_inf <= self.fp_inf  # ∞ ≤ ∞
        self._check_equal(result, True)

        result = self.fp_neg_inf <= self.fp_neg_inf
        self._check_equal(result, True)

        # Infinities
        result = self.fp_neg_inf <= self.fp_inf
        self._check_equal(result, True)

        result = self.fp_inf <= self.fp_neg_inf
        self._check_equal(result, False)

        # NaN comparisons: all ordered comparisons are False
        result = self.fp_nan <= self.fp1
        self._check_equal(result, False)

        result = self.fp1 <= self.fp_nan
        self._check_equal(result, False)

        result = self.fp_nan <= self.fp_nan
        self._check_equal(result, False)

    def test_gt(self):
        """Test greater than"""
        # Finite positives
        result = self.fp2 > self.fp1
        self._check_equal(result, True)

        result = self.fp1 > self.fp2
        self._check_equal(result, False)

        # Finite negatives
        result = self.fp_neg > self.fp_neg1
        self._check_equal(result, True)

        result = self.fp_neg1 > self.fp_neg
        self._check_equal(result, False)

        # Mixed sign
        result = self.fp_zero > self.fp_neg
        self._check_equal(result, True)

        result = self.fp_neg > self.fp_zero
        self._check_equal(result, False)

        result = self.fp1 > self.fp_neg_zero
        self._check_equal(result, True)

        result = self.fp_neg_zero > self.fp1
        self._check_equal(result, False)

        result = self.fp1 > self.fp_neg1
        self._check_equal(result, True)

        result = self.fp_neg1 > self.fp1
        self._check_equal(result, False)

        # Zeros (+0 and −0 are equal: > is False both ways)
        result = self.fp_neg_zero > self.fp_zero
        self._check_equal(result, False)

        result = self.fp_zero > self.fp_neg_zero
        self._check_equal(result, False)

        # finite vs ±∞
        result = self.fp_inf > self.fp1
        self._check_equal(result, True)

        result = self.fp1 > self.fp_inf
        self._check_equal(result, False)

        result = self.fp1 > self.fp_neg_inf
        self._check_equal(result, True)

        result = self.fp_neg_inf > self.fp1
        self._check_equal(result, False)

        # Infinities
        result = self.fp_inf > self.fp_neg_inf
        self._check_equal(result, True)

        result = self.fp_neg_inf > self.fp_inf
        self._check_equal(result, False)

        result = self.fp_inf > self.fp_inf  # ∞ > ∞ is False
        self._check_equal(result, False)

        result = self.fp_neg_inf > self.fp_neg_inf  # −∞ > −∞ is False
        self._check_equal(result, False)

        # NaN comparisons: all ordered comparisons are False
        result = self.fp_nan > self.fp1
        self._check_equal(result, False)

        result = self.fp1 > self.fp_nan
        self._check_equal(result, False)

        result = self.fp_nan > self.fp_nan
        self._check_equal(result, False)

    def test_geq(self):
        """Test greater than or equal"""
        # Finite positives
        result = self.fp2 >= self.fp1
        self._check_equal(result, True)

        result = self.fp1 >= self.fp1
        self._check_equal(result, True)

        result = self.fp1 >= self.fp2
        self._check_equal(result, False)

        # Finite negatives
        result = self.fp_neg >= self.fp_neg1
        self._check_equal(result, True)

        result = self.fp_neg1 >= self.fp_neg1
        self._check_equal(result, True)

        result = self.fp_neg1 >= self.fp_neg
        self._check_equal(result, False)

        # Mixed sign
        result = self.fp_zero >= self.fp_neg
        self._check_equal(result, True)

        result = self.fp_neg >= self.fp_zero
        self._check_equal(result, False)

        result = self.fp1 >= self.fp_neg_zero
        self._check_equal(result, True)

        result = self.fp_neg_zero >= self.fp1
        self._check_equal(result, False)

        result = self.fp1 >= self.fp_neg1
        self._check_equal(result, True)

        result = self.fp_neg1 >= self.fp1
        self._check_equal(result, False)

        # Zeros (+0 and −0 are equal: ≥ is True both ways)
        result = self.fp_neg_zero >= self.fp_zero
        self._check_equal(result, True)

        result = self.fp_zero >= self.fp_neg_zero
        self._check_equal(result, True)

        # Finite vs ±∞
        result = self.fp_inf >= self.fp1
        self._check_equal(result, True)

        result = self.fp1 >= self.fp_inf
        self._check_equal(result, False)

        result = self.fp1 >= self.fp_neg_inf
        self._check_equal(result, True)

        result = self.fp_neg_inf >= self.fp1
        self._check_equal(result, False)

        # Infinities
        result = self.fp_inf >= self.fp_neg_inf
        self._check_equal(result, True)

        result = self.fp_neg_inf >= self.fp_inf
        self._check_equal(result, False)

        result = self.fp_inf >= self.fp_inf  # ∞ ≥ ∞
        self._check_equal(result, True)

        result = self.fp_neg_inf >= self.fp_neg_inf  # −∞ ≥ −∞
        self._check_equal(result, True)

        # NaN comparisons: all ordered comparisons are False
        result = self.fp_nan >= self.fp1
        self._check_equal(result, False)

        result = self.fp1 >= self.fp_nan
        self._check_equal(result, False)

        result = self.fp_nan >= self.fp_nan
        self._check_equal(result, False)

    def test_sqrt(self):
        """Test square root operation"""
        result = claripy.fpSqrt(self.fp1)
        self._check_equal(result, 1.2247449159622192)

        result = claripy.fpSqrt(self.fp7)
        self._check_equal(result, 2.0)

        # Square root of positive zero = +0.0
        result = claripy.fpSqrt(self.fp_zero)
        self._check_equal(result, 0.0, check_bits=True)

        # Square root of negative zero = -0.0
        result = claripy.fpSqrt(self.fp_neg_zero)
        self._check_equal(result, -0.0, check_bits=True)

        # Square root of negative float - NaN
        result = claripy.fpSqrt(self.fp_neg)
        self._check_equal(result, float("nan"), check_bits=True)

        # Square root of negative infinity - NaN
        result = claripy.fpSqrt(self.fp_neg_inf)
        self._check_equal(result, float("nan"), check_bits=True)

        # Positive infinity
        result = claripy.fpSqrt(self.fp_inf)
        self._check_equal(result, float("inf"), check_bits=True)

    def test_special_values(self):
        """Test operations with special values (NaN, Infinity, Subnormal)"""
        # Test NaN comparisons and propagation
        self.assertTrue(claripy.fpIsNaN(self.fp_nan).is_true())
        result = self.fp_nan == self.fp1
        self._check_equal(result, False)
        result = self.fp_nan != self.fp1
        self._check_equal(result, True)

        # Test NaN propagation in operations
        rm = RM.default()
        ops = [
            lambda x, y: claripy.fpAdd(rm, x, y),
            lambda x, y: claripy.fpSub(rm, x, y),
            lambda x, y: claripy.fpMul(rm, x, y),
            lambda x, y: claripy.fpDiv(rm, x, y),
        ]
        for op in ops:
            result = op(self.fp_nan, self.fp1)
            self.assertTrue(claripy.fpIsNaN(result).is_true())
            result = op(self.fp1, self.fp_nan)
            self.assertTrue(claripy.fpIsNaN(result).is_true())

        # Test Infinity comparisons and operations
        self.assertTrue(claripy.fpIsInf(self.fp_inf).is_true())
        result = claripy.fpGT(self.fp_inf, self.fp1)
        self._check_equal(result, True)
        result = claripy.fpLT(self.fp_neg_inf, self.fp1)
        self._check_equal(result, True)

        # Test operations with infinities
        result = claripy.fpAdd(rm, self.fp_inf, self.fp_inf)
        self.assertTrue(claripy.fpIsInf(result).is_true())
        self.assertFalse(claripy.fpLT(result, self.fp_zero).is_true())

        result = claripy.fpAdd(rm, self.fp_inf, self.fp_neg_inf)
        self.assertTrue(claripy.fpIsNaN(result).is_true())

        result = claripy.fpMul(rm, self.fp_inf, self.fp_neg_inf)
        self.assertTrue(claripy.fpIsInf(result).is_true())
        self.assertTrue(claripy.fpLT(result, self.fp_zero).is_true())

    @unittest.skip(
        "claripy does not properly implement roundng modes for concrete values"
    )
    def test_rounding_modes(self):
        """Test operations with different rounding modes"""
        # Test addition with different rounding modes
        # Use values that will produce different results with different rounding modes
        value = claripy.FPV(1.5, FSORT_FLOAT)
        value2 = claripy.FPV(0.2, FSORT_FLOAT)

        result_rne = claripy.fpAdd(RM.RM_NearestTiesEven, value, value2)
        result_rtz = claripy.fpAdd(RM.RM_TowardsZero, value, value2)
        result_rtp = claripy.fpAdd(RM.RM_TowardsPositiveInf, value, value2)
        result_rtn = claripy.fpAdd(RM.RM_TowardsNegativeInf, value, value2)

        # Check that rounding towards positive infinity gives larger result
        self.assertTrue(claripy.fpGT(result_rtp, result_rtz).is_true())
        # Check that rounding towards negative infinity gives smaller result
        self.assertTrue(claripy.fpLT(result_rtn, result_rtz).is_true())

    def test_reverse_ops(self):
        """Test reverse operations"""
        rm = RM.default()
        # Test reverse add
        value = claripy.FPV(2.0, FSORT_FLOAT)
        result = claripy.fpAdd(rm, value, self.fp1)
        expected = claripy.fpAdd(rm, value, self.fp1)
        self._check_equal(result, self.z3.eval(expected, 1)[0])

        # Test reverse subtract
        result = claripy.fpSub(rm, value, self.fp1)
        expected = claripy.fpSub(rm, value, self.fp1)
        self._check_equal(result, self.z3.eval(expected, 1)[0])

    def test_symbolic(self):
        """Test operations with symbolic variables"""
        rm = RM.default()
        # Create symbolic variables
        sym_x = claripy.FPS("x", FSORT_FLOAT)
        sym_y = claripy.FPS("y", FSORT_FLOAT)

        # Test basic operations
        result = claripy.fpAdd(rm, sym_x, self.fp1)
        self.assertTrue(result.symbolic)

        # Test comparisons
        result = claripy.fpLT(sym_x, sym_y)
        self.assertTrue(result.symbolic)

        # Test special value checks
        result = claripy.fpIsNaN(sym_x)
        self.assertTrue(result.symbolic)
        result = claripy.fpIsInf(sym_x)
        self.assertTrue(result.symbolic)

        # Test conversions
        double_sym = sym_x.to_fp(claripy.FSORT_DOUBLE)
        self.assertTrue(double_sym.symbolic)
        self.assertEqual(double_sym.sort.length, 64)

        # Test operations mixing symbolic and concrete
        concrete = claripy.FPV(1.5, FSORT_FLOAT)
        result = claripy.fpAdd(rm, sym_x, concrete)
        self.assertTrue(result.symbolic)

    def test_eval_symbolic_fp(self):
        """Evaluate a symbolic FP through the solver.

        Z3 leaves fp.to_ieee_bv uninterpreted in models, so eval binds the
        value through an auxiliary variable and converts the resulting IEEE
        bits back to a float; the bitvector width selects f32 vs f64.
        """
        s = claripy.SolverZ3()
        x = claripy.FPS("x", FSORT_FLOAT)
        s.add(x == claripy.FPV(1.5, FSORT_FLOAT))
        self.assertEqual(list(s.eval(x, 2)), [1.5])

        s64 = claripy.SolverZ3()
        y = claripy.FPS("y", claripy.FSORT_DOUBLE)
        s64.add(y == claripy.FPV(2.5, claripy.FSORT_DOUBLE))
        self.assertEqual(list(s64.eval(y, 2)), [2.5])

    def test_conversions(self):
        """Test FP conversion operations"""
        rm = RM.default()
        # Test fpToFP from FP
        double_val = self.fp1.to_fp(claripy.FSORT_DOUBLE)
        self.assertEqual(double_val.sort.length, 64)

        # Test conversion of special values
        inf_double = self.fp_inf.to_fp(claripy.FSORT_DOUBLE)
        self.assertTrue(claripy.fpIsInf(inf_double).is_true())

        nan_double = self.fp_nan.to_fp(claripy.FSORT_DOUBLE)
        self.assertTrue(claripy.fpIsNaN(nan_double).is_true())

        # Test fpToIEEEBV and back
        bv = self.fp1.to_bv()
        self.assertEqual(bv.length, 32)  # FSORT_FLOAT is 32 bits

        # Test fpToSBV/fpToUBV with different sizes
        for size in [16, 32, 64]:
            sbv = self.fp1.val_to_bv(size, signed=True)
            ubv = self.fp1.val_to_bv(size, signed=False)
            self.assertEqual(sbv.length, size)
            self.assertEqual(ubv.length, size)

        # Test conversion of special values to BV
        inf_bv = self.fp_inf.to_bv()
        neg_inf_bv = self.fp_neg_inf.to_bv()
        self.assertNotEqual(self.z3.eval(inf_bv, 1)[0], self.z3.eval(neg_inf_bv, 1)[0])


if __name__ == "__main__":
    unittest.main()

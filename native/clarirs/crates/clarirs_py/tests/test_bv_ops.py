from __future__ import annotations

import unittest

import claripy as claripy


class TestBVOperations(unittest.TestCase):
    def setUp(self):
        """Set up common test values and solvers."""
        # Create some common BVs for testing
        self.bv1 = claripy.BVV(10, 32)  # Value 10, 32 bits
        self.bv2 = claripy.BVV(5, 32)  # Value 5, 32 bits
        self.bv_neg = claripy.BVV(-5, 32)  # Negative value
        self.bv_max = claripy.BVV((1 << 32) - 1, 32)  # Maximum 32-bit value
        self.bv_zero = claripy.BVV(0, 32)  # Zero value
        self.bv_one = claripy.BVV(1, 32)  # Value 1

        # Add symbolic variables for testing
        self.sym_x = claripy.BVS("x", 8)  # Symbolic 8-bit value (changed from 32 for rotation)
        self.sym_y = claripy.BVS("y", 8)  # Another symbolic 8-bit value

        # Add more edge cases
        self.bv_int_max = claripy.BVV(0x7FFFFFFF, 32)  # Maximum signed 32-bit integer
        self.bv_int_min = claripy.BVV(-0x80000000, 32)  # Minimum signed 32-bit integer
        self.bv_pow2 = claripy.BVV(1 << 16, 32)  # Power of 2 for division tests

        self.z3 = claripy.SolverZ3()
        self.concrete = claripy.SolverConcrete()

    def _check_equal(self, expr, expected):
        """
        Helper to check equality of BV expressions.

        Args:
            expr: The expression to evaluate
            expected: The expected result
        """
        z3_result = self.z3.eval(expr, 1)[0]
        self.assertEqual(z3_result, expected, "Z3 result does not match expected value")

        if expr.symbolic:
            with self.assertRaises(claripy.ClaripyOperationError):
                self.concrete.eval(expr, 1)[0]
        else:
            concrete_result = self.concrete.eval(expr, 1)[0]
            self.assertEqual(concrete_result, expected, "Concrete result does not match expected value")

    def _check_symbolic_evaluation(self, expr, solver_fn):
        """
        Helper to check properties of symbolic expressions.

        Args:
            expr: The symbolic expression to evaluate
            solver_fn: Function that takes the solver and returns True if property holds
        """
        self.assertTrue(expr.symbolic)  # Verify expression is symbolic
        self.assertTrue(solver_fn(self.z3))  # Verify property holds

    def test_add(self):
        """Test addition operation"""
        result = self.bv1 + self.bv2
        self._check_equal(result, 15)

        # Test overflow
        result = self.bv_max + self.bv_one
        self._check_equal(result, 0)

    def test_sub(self):
        """Test subtraction operation"""
        result = self.bv1 - self.bv2
        self._check_equal(result, 5)

        # Test underflow
        result = self.bv_zero - self.bv_one
        self._check_equal(result, (1 << 32) - 1)

    def test_mul(self):
        """Test multiplication operation"""
        result = self.bv1 * self.bv2
        self._check_equal(result, 50)

        # Test overflow
        big = claripy.BVV(1 << 31, 32)
        result = big * claripy.BVV(2, 32)
        self._check_equal(result, 0)

    def test_div(self):
        """Test division operations with various edge cases."""
        # Regular division
        result = self.bv1 // self.bv2
        self._check_equal(result, 2)

        # Division by power of 2
        result = self.bv_pow2 // self.bv_pow2
        self._check_equal(result, 1)

        # Division of max value
        result = self.bv_max // self.bv2
        self._check_equal(result, self.bv_max.concrete_value // 5)

        # Division with negative values
        result = self.bv_neg // self.bv2
        self._check_equal(result, ((-5) & ((1 << 32) - 1)) // 5)

        # Test division by zero raises exception
        with self.assertRaises(ZeroDivisionError):
            _ = (self.bv1 // self.bv_zero).concrete_value

        # Test symbolic division
        sym_div = self.sym_x // claripy.BVV(2, 8)
        self._check_symbolic_evaluation(sym_div, lambda solver: solver.satisfiable())

    def test_sdiv(self):
        """Test signed division"""
        result = self.bv1.SDiv(self.bv_neg)
        self._check_equal(result, 4294967294)

    def test_mod(self):
        """Test modulo operation"""
        result = self.bv1 % self.bv2
        self._check_equal(result, 0)

        # Test modulo with larger dividend
        result = claripy.BVV(7, 32) % claripy.BVV(3, 32)
        self._check_equal(result, 1)

    def test_smod(self):
        """Test signed modulo"""
        result = self.bv1.SMod(self.bv_neg)
        self._check_equal(result, 0)

    def test_and(self):
        """Test bitwise AND"""
        result = self.bv1 & self.bv2
        self._check_equal(result, 0)

        # Test with all bits set
        result = self.bv_max & self.bv1
        self._check_equal(result, 10)

    def test_or(self):
        """Test bitwise OR"""
        result = self.bv1 | self.bv2
        self._check_equal(result, 15)

        # Test with zero
        result = self.bv1 | self.bv_zero
        self._check_equal(result, 10)

    def test_xor(self):
        """Test bitwise XOR"""
        result = self.bv1 ^ self.bv2
        self._check_equal(result, 15)

        # Test with self (should be zero)
        result = self.bv1 ^ self.bv1
        self._check_equal(result, 0)

    def test_neg(self):
        """Test negation"""
        result = -self.bv1
        self._check_equal(result, (-10) & ((1 << 32) - 1))

    def test_comparisons(self):
        """Test all comparison operations with various edge cases."""
        # Unsigned comparisons
        # Less than
        result = self.bv2 < self.bv1
        self.assertTrue(result.is_true())
        result = self.bv1 < self.bv_neg  # Negative numbers are large in unsigned
        self.assertTrue(result.is_true())

        # Less than or equal
        result = self.bv2 <= self.bv2
        self.assertTrue(result.is_true())
        result = self.bv1 <= self.bv2
        self.assertFalse(result.is_true())

        # Greater than
        result = self.bv1 > self.bv2
        self.assertTrue(result.is_true())
        result = self.bv_neg > self.bv1  # Negative numbers are large in unsigned
        self.assertTrue(result.is_true())

        # Greater than or equal
        result = self.bv2 >= self.bv2
        self.assertTrue(result.is_true())
        result = self.bv2 >= self.bv1
        self.assertFalse(result.is_true())

        # Signed comparisons
        # Less than
        result = self.bv_neg.SLT(self.bv1)
        self.assertTrue(result.is_true())
        result = self.bv1.SLT(self.bv2)
        self.assertFalse(result.is_true())

        # Less than or equal
        result = self.bv_neg.SLE(self.bv1)
        self.assertTrue(result.is_true())
        result = self.bv2.SLE(self.bv2)
        self.assertTrue(result.is_true())

        # Greater than
        result = self.bv1.SGT(self.bv_neg)
        self.assertTrue(result.is_true())
        result = self.bv2.SGT(self.bv1)
        self.assertFalse(result.is_true())

        # Greater than or equal
        result = self.bv2.SGE(self.bv2)
        self.assertTrue(result.is_true())
        result = self.bv_neg.SGE(self.bv1)
        self.assertFalse(result.is_true())

        # Test with symbolic values
        sym_lt = self.sym_x.ULT(claripy.BVV(5, 8))
        self._check_symbolic_evaluation(sym_lt, lambda solver: solver.satisfiable())

        sym_slt = self.sym_x.SLT(claripy.BVV(5, 8))
        self._check_symbolic_evaluation(sym_slt, lambda solver: solver.satisfiable())

    def test_extract(self):
        """Test bit extraction with various ranges and edge cases."""
        # Create a value with known bit patterns
        val = claripy.BVV(0xDEADBEEF, 32)

        # Extract full width
        result = val[31:0]
        self._check_equal(result, 0xDEADBEEF)

        # Extract each byte
        result = val[31:24]
        self._check_equal(result, 0xDE)
        result = val[23:16]
        self._check_equal(result, 0xAD)
        result = val[15:8]
        self._check_equal(result, 0xBE)
        result = val[7:0]
        self._check_equal(result, 0xEF)

        # Extract across byte boundaries
        result = val[27:20]
        self._check_equal(result, 0xEA)  # Fixed: Correct value for bits 27:20

        # Extract single bits
        result = val[31]
        self._check_equal(result, 1)
        result = val[0]
        self._check_equal(result, 1)

        # Test with symbolic value
        sym_extract = self.sym_x[7:4]  # Extract middle bits
        self._check_symbolic_evaluation(sym_extract, lambda solver: solver.satisfiable())

        # Test invalid indices should raise
        with self.assertRaises(claripy.InvalidExtractBounds):
            _ = val[32:0].concrete_value  # Can't extract beyond size

        # Test negative indices (should work like Python slicing)
        result = val[-1:-1]  # Last bit
        self._check_equal(result, 1)  # 0xDEADBEEF ends in 1

    def test_concat(self):
        """Test concatenation with various combinations."""
        # Basic concatenation
        result = self.bv1.concat(self.bv2)
        self.assertEqual(result.length, 64)
        self._check_equal(result, (self.bv1.concrete_value << 32) | self.bv2.concrete_value)

        # Concatenate multiple values
        small1 = claripy.BVV(0xDE, 8)
        small2 = claripy.BVV(0xAD, 8)
        small3 = claripy.BVV(0xBE, 8)
        small4 = claripy.BVV(0xEF, 8)
        result = small1.concat(small2, small3, small4)
        self.assertEqual(result.length, 32)
        self._check_equal(result, 0xDEADBEEF)

        # Concatenate with zero
        result = self.bv1.concat(self.bv_zero)
        self.assertEqual(result.length, 64)
        self._check_equal(result, self.bv1.concrete_value << 32)

        # Concatenate with symbolic value
        sym_concat = small1.concat(self.sym_x)
        self.assertEqual(sym_concat.length, 16)
        self._check_symbolic_evaluation(sym_concat, lambda solver: solver.satisfiable())

    def test_extend_and_chop(self):
        """Test extension and chopping operations with various cases."""
        # Zero extension
        small = claripy.BVV(0xFF, 8)
        result = small.zero_extend(24)
        self.assertEqual(result.length, 32)
        self._check_equal(result, 0xFF)

        # Zero extend symbolic
        sym_extend = self.sym_x.zero_extend(8)
        self.assertEqual(sym_extend.length, 16)
        self._check_symbolic_evaluation(sym_extend, lambda solver: solver.satisfiable())

        # Sign extension
        # Extend positive number
        small_pos = claripy.BVV(0x7F, 8)
        result = small_pos.sign_extend(24)
        self.assertEqual(result.length, 32)
        self._check_equal(result, 0x7F)

        # Extend negative number
        small_neg = claripy.BVV(0x80, 8)  # -128 in 8 bits
        result = small_neg.sign_extend(24)
        self.assertEqual(result.length, 32)
        self._check_equal(result, 0xFFFFFF80)

        # Sign extend symbolic
        sym_sign_extend = self.sym_x.sign_extend(8)
        self.assertEqual(sym_sign_extend.length, 16)
        self._check_symbolic_evaluation(sym_sign_extend, lambda solver: solver.satisfiable())

        # Chop operation
        val = claripy.BVV(0xDEADBEEF, 32)
        # Chop into bytes
        pieces = val.chop(bits=8)
        self.assertEqual(len(pieces), 4)
        self._check_equal(pieces[0], 0xDE)
        self._check_equal(pieces[1], 0xAD)
        self._check_equal(pieces[2], 0xBE)
        self._check_equal(pieces[3], 0xEF)

        # Chop into 16-bit pieces
        pieces = val.chop(bits=16)
        self.assertEqual(len(pieces), 2)
        self._check_equal(pieces[0], 0xDEAD)
        self._check_equal(pieces[1], 0xBEEF)

        # Test invalid chop should raise
        with self.assertRaises(ValueError):
            val.chop(bits=3)  # Not a multiple of length

    def test_rotate(self):
        """Test rotation operations with various shifts."""
        # Create a value with a single bit set
        val = claripy.BVV(1, 8)

        # Rotate left by different amounts
        result = claripy.RotateLeft(val, claripy.BVV(1, 8))
        self._check_equal(result, 2)

        result = claripy.RotateLeft(val, claripy.BVV(4, 8))
        self._check_equal(result, 16)

        result = claripy.RotateLeft(val, claripy.BVV(8, 8))  # Full rotation
        self._check_equal(result, 1)

        # Rotate right by different amounts
        result = claripy.RotateRight(val, claripy.BVV(1, 8))
        self._check_equal(result, 128)

        result = claripy.RotateRight(val, claripy.BVV(4, 8))
        self._check_equal(result, 16)

        result = claripy.RotateRight(val, claripy.BVV(8, 8))  # Full rotation
        self._check_equal(result, 1)

        # Test with symbolic rotation
        sym_rotate = claripy.RotateLeft(val, self.sym_x)
        self._check_symbolic_evaluation(sym_rotate, lambda solver: solver.satisfiable())

    def test_reverse(self):
        """Test bit reversal with various patterns."""
        # Test alternating bits
        val = claripy.BVV(0b10101010, 8)
        result = val.reversed
        self._check_equal(result, 0b10101010)  # Bit pattern is preserved

        # Test single bit
        val = claripy.BVV(0b10000000, 8)
        result = val.reversed
        self._check_equal(result, 0b10000000)  # Bit pattern is preserved

        # Test all bits
        val = claripy.BVV(0b11111111, 8)
        result = val.reversed
        self._check_equal(result, 0b11111111)  # All 1s remain all 1s

        # Test 32-bit value
        val = claripy.BVV(0x12345678, 32)
        result = val.reversed
        self._check_equal(result, 0x78563412)  # Bytes are reversed

    def test_lshr(self):
        """Test logical shift right operation."""
        # Basic shift
        result = self.bv1.LShR(2)
        self._check_equal(result, 2)

        # Shift by width
        result = self.bv1.LShR(32)
        self._check_equal(result, 0)

        # Shift negative value
        result = self.bv_neg.LShR(1)
        self._check_equal(result, (self.bv_neg.concrete_value & ((1 << 32) - 1)) >> 1)

        # Test with symbolic shift amount
        sym_shift = claripy.BVV(8, 8).LShR(self.sym_x)
        self._check_symbolic_evaluation(sym_shift, lambda solver: solver.satisfiable())

    def test_chained_ops(self):
        """Test chaining multiple operations."""
        # Test (a + b) * c
        result = (self.bv1 + self.bv2) * self.bv2
        self._check_equal(result, 75)

        # Test complex expression
        result = (self.bv1 + self.bv2) * self.bv2 // self.bv2
        self._check_equal(result, 15)

        # Test with symbolic values
        sym_chain = (self.sym_x + claripy.BVV(1, 8)) * claripy.BVV(2, 8)
        self._check_symbolic_evaluation(sym_chain, lambda solver: solver.satisfiable())

    def test_mixed_symbolic_concrete(self):
        """Test operations mixing symbolic and concrete values."""
        # Addition
        result = self.sym_x + claripy.BVV(1, 8)
        self._check_symbolic_evaluation(result, lambda solver: solver.satisfiable())

        # Multiplication
        result = self.sym_x * claripy.BVV(2, 8)
        self._check_symbolic_evaluation(result, lambda solver: solver.satisfiable())

        # Complex expression
        result = (self.sym_x + claripy.BVV(1, 8)) * (self.sym_y + claripy.BVV(2, 8))
        self._check_symbolic_evaluation(result, lambda solver: solver.satisfiable())

    def test_pos(self):
        """Test positive operation."""
        # Test positive operation
        result = +self.bv1
        self._check_equal(result, 10)
        result = +self.bv_neg
        self._check_equal(result, ((-5) & ((1 << 32) - 1)))

        # Test with symbolic values
        sym_pos = +self.sym_x
        self._check_symbolic_evaluation(sym_pos, lambda solver: solver.satisfiable())

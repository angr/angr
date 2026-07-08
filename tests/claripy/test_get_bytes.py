from __future__ import annotations

import unittest

import claripy


class TestGetBytes(unittest.TestCase):
    def setUp(self):
        """Set up common test values and solvers."""
        # Create BVs with different sizes and patterns for testing
        self.bv_32bit = claripy.BVV(0xDEADBEEF, 32)  # 32-bit value with recognizable byte pattern
        self.bv_64bit = claripy.BVV(0x0123456789ABCDEF, 64)  # 64-bit value with sequential bytes
        self.bv_8bit = claripy.BVV(0xA5, 8)  # 8-bit value (single byte)
        self.bv_16bit = claripy.BVV(0xCAFE, 16)  # 16-bit value (two bytes)

        # Non-byte-aligned bit widths
        self.bv_10bit = claripy.BVV(0x3F0, 10)  # 10-bit value (not byte-aligned)
        self.bv_31bit = claripy.BVV(0x7FFFFFFF, 31)  # 31-bit value (not byte-aligned)

        # Special patterns
        self.bv_all_ones = claripy.BVV((1 << 32) - 1, 32)  # All bits set to 1
        self.bv_zero = claripy.BVV(0, 32)  # All bits set to 0
        self.bv_alternating = claripy.BVV(0xAAAAAAAA, 32)  # Alternating 1s and 0s

        # Empty bitvector
        self.bv_empty = claripy.BVV(0, 0)  # Zero-length bitvector

        # Symbolic values
        self.sym_x = claripy.BVS("x", 32)  # Symbolic 32-bit value

        # Set up solvers for checking results
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

    def test_get_byte_basic(self):
        """Test basic functionality of get_byte with standard values."""
        # Test extracting bytes from 32-bit value
        self.assertEqual(self.bv_32bit.get_byte(0).args[0], 0xDE)
        self.assertEqual(self.bv_32bit.get_byte(1).args[0], 0xAD)
        self.assertEqual(self.bv_32bit.get_byte(2).args[0], 0xBE)
        self.assertEqual(self.bv_32bit.get_byte(3).args[0], 0xEF)

        # Verify the size of the returned value is always 8 bits
        self.assertEqual(self.bv_32bit.get_byte(0).args[1], 8)
        self.assertEqual(self.bv_32bit.get_byte(3).args[1], 8)

        # Test with 64-bit value
        self.assertEqual(self.bv_64bit.get_byte(0).args[0], 0x01)
        self.assertEqual(self.bv_64bit.get_byte(7).args[0], 0xEF)

    def test_get_byte_edge_cases(self):
        """Test get_byte with edge cases and boundary conditions."""
        # Test with 8-bit value (single byte)
        self.assertEqual(self.bv_8bit.get_byte(0).args[0], 0xA5)

        # Test with 16-bit value
        self.assertEqual(self.bv_16bit.get_byte(0).args[0], 0xCA)
        self.assertEqual(self.bv_16bit.get_byte(1).args[0], 0xFE)

        # Test with non-byte-aligned bit widths
        self.assertEqual(self.bv_10bit.get_byte(0).args[0], 0x3)  # First byte (partial)
        self.assertEqual(self.bv_10bit.get_byte(1).args[0], 0xF0)  # Second byte (partial)

        # Test with 31-bit value
        self.assertEqual(self.bv_31bit.get_byte(0).args[0], 0x7F)  # First byte (partial)
        self.assertEqual(self.bv_31bit.get_byte(3).args[0], 0xFF)  # Last byte

        # Test with special patterns
        self.assertEqual(self.bv_all_ones.get_byte(0).args[0], 0xFF)
        self.assertEqual(self.bv_zero.get_byte(0).args[0], 0x00)
        self.assertEqual(self.bv_alternating.get_byte(0).args[0], 0xAA)

    def test_get_byte_errors(self):
        """Test error cases for get_byte."""
        # Test with invalid index (too large)
        with self.assertRaises(ValueError):
            self.bv_32bit.get_byte(4)

        # Test with invalid index (too large) for smaller values
        with self.assertRaises(ValueError):
            self.bv_8bit.get_byte(1)

        # Test with invalid index (too large) for non-byte-aligned values
        with self.assertRaises(ValueError):
            self.bv_10bit.get_byte(2)

    def test_get_bytes_basic(self):
        """Test basic functionality of get_bytes with standard values."""
        # Test extracting bytes from 32-bit value
        self.assertEqual(self.bv_32bit.get_bytes(0, 1).args[0], 0xDE)
        self.assertEqual(self.bv_32bit.get_bytes(1, 1).args[0], 0xAD)
        self.assertEqual(self.bv_32bit.get_bytes(0, 2).args[0], 0xDEAD)
        self.assertEqual(self.bv_32bit.get_bytes(2, 2).args[0], 0xBEEF)
        self.assertEqual(self.bv_32bit.get_bytes(0, 4).args[0], 0xDEADBEEF)

        # Verify the size of the returned values
        self.assertEqual(self.bv_32bit.get_bytes(0, 1).args[1], 8)
        self.assertEqual(self.bv_32bit.get_bytes(0, 2).args[1], 16)
        self.assertEqual(self.bv_32bit.get_bytes(0, 4).args[1], 32)

        # Test with 64-bit value
        self.assertEqual(self.bv_64bit.get_bytes(0, 1).args[0], 0x01)
        self.assertEqual(self.bv_64bit.get_bytes(0, 8).args[0], 0x0123456789ABCDEF)
        self.assertEqual(self.bv_64bit.get_bytes(4, 4).args[0], 0x89ABCDEF)

    def test_get_bytes_edge_cases(self):
        """Test get_bytes with edge cases and boundary conditions."""
        # Test with 8-bit value (single byte)
        self.assertEqual(self.bv_8bit.get_bytes(0, 1).args[0], 0xA5)

        # Test with 16-bit value
        self.assertEqual(self.bv_16bit.get_bytes(0, 1).args[0], 0xCA)
        self.assertEqual(self.bv_16bit.get_bytes(1, 1).args[0], 0xFE)
        self.assertEqual(self.bv_16bit.get_bytes(0, 2).args[0], 0xCAFE)

        # Test with non-byte-aligned bit widths
        self.assertEqual(self.bv_10bit.get_bytes(0, 1).args[0], 0x3)
        self.assertEqual(self.bv_10bit.get_bytes(0, 2).args[0], 0x3F0)
        self.assertEqual(self.bv_10bit.get_bytes(1, 1).args[0], 0xF0)

        # Test with 31-bit value
        self.assertEqual(self.bv_31bit.get_bytes(0, 1).args[0], 0x7F)
        self.assertEqual(self.bv_31bit.get_bytes(0, 4).args[0], 0x7FFFFFFF)

        # Test with special patterns
        self.assertEqual(self.bv_all_ones.get_bytes(0, 4).args[0], 0xFFFFFFFF)
        self.assertEqual(self.bv_zero.get_bytes(0, 4).args[0], 0x00000000)

        # Test zero-size extraction
        self.assertEqual(self.bv_32bit.get_bytes(0, 0).args[0], 0)
        self.assertEqual(self.bv_32bit.get_bytes(0, 0).args[1], 0)

    def test_get_bytes_errors(self):
        """Test error cases for get_bytes."""
        # Test with invalid index (too large)
        with self.assertRaises(ValueError):
            self.bv_32bit.get_bytes(4, 1)

        # Test with invalid index (too large) for smaller values
        with self.assertRaises(ValueError):
            self.bv_8bit.get_bytes(1, 1)

        # Test with invalid index (too large) for non-byte-aligned values
        with self.assertRaises(ValueError):
            self.bv_10bit.get_bytes(2, 1)

        # Test with size too large - this doesn't actually raise an error
        # as the implementation allows for this
        result = self.bv_32bit.get_bytes(0, 5)
        self.assertEqual(result.args[0], 222)  # First byte (0xDE)

        # Test with index + size too large - this raises a ClaripyOperationError
        with self.assertRaises(claripy.ClaripyOperationError):
            self.bv_32bit.get_bytes(2, 3)

    def test_get_bytes_zero_extension(self):
        """Test zero extension behavior in get_bytes for non-byte-aligned values."""
        # Test with 10-bit value (should be zero-extended to 16 bits)
        result = self.bv_10bit.get_bytes(0, 2)
        self.assertEqual(result.args[1], 16)  # Should be 16 bits
        self.assertEqual(result.args[0], 0x3F0)  # Value should be zero-extended

        # Test with 31-bit value (should be zero-extended to 32 bits)
        result = self.bv_31bit.get_bytes(0, 4)
        self.assertEqual(result.args[1], 32)  # Should be 32 bits
        self.assertEqual(result.args[0], 0x7FFFFFFF)  # Value should be zero-extended

    def test_get_byte_symbolic(self):
        """Test get_byte with symbolic values."""
        # Get a byte from a symbolic value
        sym_byte = self.sym_x.get_byte(0)

        # Verify the result is symbolic
        self.assertTrue(sym_byte.symbolic)

        # Verify the size is 8 bits
        self.assertEqual(sym_byte.size(), 8)

        # Test with constraints using extra_constraints parameter
        self.assertEqual(self.z3.eval(sym_byte, 1, extra_constraints=(self.sym_x == 0xAABBCCDD,))[0], 0xAA)

    def test_get_bytes_symbolic(self):
        """Test get_bytes with symbolic values."""
        # Get bytes from a symbolic value
        sym_bytes = self.sym_x.get_bytes(0, 2)

        # Verify the result is symbolic
        self.assertTrue(sym_bytes.symbolic)

        # Verify the size is 16 bits
        self.assertEqual(sym_bytes.size(), 16)

        # Test with constraints using extra_constraints parameter
        self.assertEqual(self.z3.eval(sym_bytes, 1, extra_constraints=(self.sym_x == 0xAABBCCDD,))[0], 0xAABB)

    def test_combined_operations(self):
        """Test combining get_byte and get_bytes with other operations."""
        # Test arithmetic with get_byte
        result = self.bv_32bit.get_byte(0) + self.bv_32bit.get_byte(1)
        self._check_equal(
            result, 139
        )  # 0xDE (222) + 0xAD (173) = 395, but result is 139 due to 8-bit modulo arithmetic

        # Test concatenation
        result = self.bv_32bit.get_byte(0).concat(self.bv_32bit.get_byte(1))
        self._check_equal(result, 0xDEAD)

        # Test with get_bytes
        result = self.bv_32bit.get_bytes(0, 2) ^ self.bv_32bit.get_bytes(2, 2)
        self._check_equal(result, 0xDEAD ^ 0xBEEF)  # 0xDEAD (57005) ^ 0xBEEF (48879) = 0x6042 (24642)

        # Test with symbolic values
        sym_result = self.sym_x.get_byte(0) + claripy.BVV(1, 8)
        self._check_symbolic_evaluation(sym_result, lambda solver: solver.satisfiable())

    def test_comprehensive_patterns(self):
        """Test get_byte and get_bytes with comprehensive bit patterns."""
        # Create a value with alternating bytes
        alternating_bytes = claripy.BVV(0xA5A5A5A5, 32)

        # Test each byte
        for i in range(4):
            self.assertEqual(alternating_bytes.get_byte(i).args[0], 0xA5)

        # Create a value with sequential bytes
        sequential = claripy.BVV(0x01020304, 32)

        # Test each byte
        self.assertEqual(sequential.get_byte(0).args[0], 0x01)
        self.assertEqual(sequential.get_byte(1).args[0], 0x02)
        self.assertEqual(sequential.get_byte(2).args[0], 0x03)
        self.assertEqual(sequential.get_byte(3).args[0], 0x04)

        # Test get_bytes with various sizes
        self.assertEqual(sequential.get_bytes(0, 2).args[0], 0x0102)
        self.assertEqual(sequential.get_bytes(1, 2).args[0], 0x0203)
        self.assertEqual(sequential.get_bytes(0, 3).args[0], 0x010203)
        self.assertEqual(sequential.get_bytes(1, 3).args[0], 0x020304)

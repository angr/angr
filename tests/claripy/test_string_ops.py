from __future__ import annotations

import unittest

from angr import claripy
from angr.claripy import (
    IntToStr,
    StrConcat,
    StrContains,
    StrIndexOf,
    StrIsDigit,
    StrLen,
    StrPrefixOf,
    StrReplace,
    StrSubstr,
    StrSuffixOf,
    StrToInt,
)
from angr.claripy.ast import BV, Bool, String


class TestStringOperations(unittest.TestCase):
    """
    Test suite for Claripy string operations.
    Tests both concrete and symbolic string operations using Z3 and concrete backends.
    """

    def setUp(self):
        """
        Set up test fixtures.
        Creates concrete and symbolic string values for testing.
        Initializes Z3 and concrete solvers.
        """
        # Create concrete string values for testing
        self.str1 = claripy.StringV("hello")
        self.str2 = claripy.StringV("world")
        self.str_empty = claripy.StringV("")
        self.str_digit = claripy.StringV("123")
        self.str_unicode = claripy.StringV("héllò")
        self.str_special = claripy.StringV("hello\n\t!")

        # Create symbolic string for testing
        self.str_symbolic = claripy.StringS("sym_str")

        # Setup solvers
        self.z3 = claripy.SolverZ3()
        self.concrete = claripy.SolverConcrete()

    def _check_equal(self, expr, expected):
        """
        Helper to check equality of String expressions.

        Args:
            expr: The expression to evaluate
            expected: Expected result value

        Tests both Z3 and concrete backend results when possible.
        For symbolic expressions, verifies concrete backend raises appropriate error.
        """
        z3_result = self.z3.eval(expr, 1)[0]
        self.assertEqual(z3_result, expected, "Z3 result does not match expected value")

        if expr.symbolic:
            with self.assertRaises(claripy.ClaripyOperationError):
                self.concrete.eval(expr, 1)[0]
        else:
            concrete_result = self.concrete.eval(expr, 1)[0]
            self.assertEqual(concrete_result, expected, "Concrete result does not match expected value")

    def test_equality(self):
        """Test string equality and inequality operations"""
        # Test equality
        eq_result = self.str1 == claripy.StringV("hello")
        self._check_equal(eq_result, True)

        neq_result = self.str1 == self.str2
        self._check_equal(neq_result, False)

        # Test inequality
        neq_result2 = self.str1 != self.str2
        self._check_equal(neq_result2, True)

        eq_result2 = self.str1 != claripy.StringV("hello")
        self._check_equal(eq_result2, False)

        # Test with symbolic strings
        sym_eq = self.str1 == self.str_symbolic
        self.assertTrue(isinstance(sym_eq, Bool))

    def test_concat(self):
        """Test string concatenation operation"""
        # Basic concatenation
        result = StrConcat(self.str1, self.str2)
        self._check_equal(result, "helloworld")

        # Empty string concatenation
        result = StrConcat(self.str1, self.str_empty)
        self._check_equal(result, "hello")

        # Unicode concatenation
        result = StrConcat(self.str_unicode, self.str2)
        self._check_equal(result, "héllòworld")

        # Multiple concatenation
        result = StrConcat(self.str1, StrConcat(self.str2, self.str_digit))
        self._check_equal(result, "helloworld123")

        # Symbolic concatenation
        sym_concat = StrConcat(self.str1, self.str_symbolic)
        self.assertTrue(isinstance(sym_concat, String))

    def test_substr(self):
        """Test substring extraction with various edge cases"""
        # Basic substring
        result = StrSubstr(claripy.BVV(0, 64), claripy.BVV(2, 64), self.str1)
        self._check_equal(result, "he")

        # Full string
        result = StrSubstr(claripy.BVV(0, 64), claripy.BVV(5, 64), self.str1)
        self._check_equal(result, "hello")

        # Empty result
        result = StrSubstr(claripy.BVV(5, 64), claripy.BVV(0, 64), self.str1)
        self._check_equal(result, "")

        # Unicode handling
        result = StrSubstr(claripy.BVV(0, 64), claripy.BVV(3, 64), self.str_unicode)
        self._check_equal(result, "hél")

        # Out of bounds
        result = StrSubstr(claripy.BVV(10, 64), claripy.BVV(2, 64), self.str1)
        self._check_equal(result, "")

        # Negative index (should wrap around due to unsigned bitvector)
        result = StrSubstr(claripy.BVV(-1 % (2**64), 64), claripy.BVV(2, 64), self.str1)
        self._check_equal(result, "")

    def test_length(self):
        """Test string length with various types of strings"""
        # Basic length
        result = StrLen(self.str1)
        self._check_equal(result, 5)

        # Empty string
        result = StrLen(self.str_empty)
        self._check_equal(result, 0)

        # Unicode string
        result = StrLen(self.str_unicode)
        self._check_equal(result, 5)

        # Special characters (\n\t count as 1 each)
        result = StrLen(self.str_special)
        self._check_equal(result, 8)

        # Symbolic length
        sym_len = StrLen(self.str_symbolic)
        self.assertTrue(isinstance(sym_len, BV))

    def test_replace(self):
        """Test string replacement with various patterns"""
        # Basic replacement
        result = StrReplace(self.str1, claripy.StringV("he"), claripy.StringV("ye"))
        self._check_equal(result, "yello")

        # Replace with empty string
        result = StrReplace(self.str1, claripy.StringV("he"), self.str_empty)
        self._check_equal(result, "llo")

        # Replace empty string (prepends replacement at start of string)
        result = StrReplace(self.str1, self.str_empty, claripy.StringV("x"))
        self._check_equal(result, "xhello")

        # Overlapping patterns
        str_overlap = claripy.StringV("aaaaa")
        result = StrReplace(str_overlap, claripy.StringV("aa"), claripy.StringV("b"))
        self._check_equal(result, "baaa")

        # Unicode replacement
        result = StrReplace(self.str_unicode, claripy.StringV("é"), claripy.StringV("e"))
        self._check_equal(result, "hellò")

    def test_contains(self):
        """Test string contains with various patterns"""
        # Basic contains
        result = StrContains(self.str1, claripy.StringV("ell"))
        self._check_equal(result, True)

        # Non-matching pattern
        result = StrContains(self.str1, claripy.StringV("xyz"))
        self._check_equal(result, False)

        # Empty string
        result = StrContains(self.str1, self.str_empty)
        self._check_equal(result, True)

        # Full string match
        result = StrContains(self.str1, self.str1)
        self._check_equal(result, True)

        # Unicode pattern
        result = StrContains(self.str_unicode, claripy.StringV("é"))
        self._check_equal(result, True)

        # Special characters
        result = StrContains(self.str_special, claripy.StringV("\n"))
        self._check_equal(result, True)

    def test_prefixes(self):
        """Test string prefix with various patterns"""
        # Basic prefix
        result = StrPrefixOf(claripy.StringV("he"), self.str1)
        self._check_equal(result, True)

        # Non-matching prefix
        result = StrPrefixOf(claripy.StringV("wo"), self.str1)
        self._check_equal(result, False)

        # Empty string prefix
        result = StrPrefixOf(self.str_empty, self.str1)
        self._check_equal(result, True)

        # Full string prefix
        result = StrPrefixOf(self.str1, self.str1)
        self._check_equal(result, True)

        # Unicode prefix
        result = StrPrefixOf(claripy.StringV("hé"), self.str_unicode)
        self._check_equal(result, True)

    def test_suffixes(self):
        """Test string suffix with various patterns"""
        # Basic suffix
        result = StrSuffixOf(claripy.StringV("lo"), self.str1)
        self._check_equal(result, True)

        # Non-matching suffix
        result = StrSuffixOf(claripy.StringV("he"), self.str1)
        self._check_equal(result, False)

        # Empty string suffix
        result = StrSuffixOf(self.str_empty, self.str1)
        self._check_equal(result, True)

        # Full string suffix
        result = StrSuffixOf(self.str1, self.str1)
        self._check_equal(result, True)

        # Unicode suffix
        result = StrSuffixOf(claripy.StringV("ò"), self.str_unicode)
        self._check_equal(result, True)

    def test_index(self):
        """Test string index operations with various patterns"""
        # Basic index
        result = StrIndexOf(self.str1, claripy.StringV("l"), claripy.BVV(0, 64))
        self._check_equal(result, 2)

        # Not found
        result = StrIndexOf(self.str1, claripy.StringV("z"), claripy.BVV(0, 64))
        self._check_equal(result, -1 % (2**64))

        # Empty string pattern
        result = StrIndexOf(self.str1, self.str_empty, claripy.BVV(0, 64))
        self._check_equal(result, 0)

        # Start index beyond string length
        result = StrIndexOf(self.str1, claripy.StringV("l"), claripy.BVV(10, 64))
        self._check_equal(result, -1 % (2**64))

        # Unicode pattern
        result = StrIndexOf(self.str_unicode, claripy.StringV("é"), claripy.BVV(0, 64))
        self._check_equal(result, 1)

    def test_to_int(self):
        """Test string to integer conversion with various inputs"""
        # Basic conversion
        result = StrToInt(self.str_digit)
        self._check_equal(result, 123)

        # Non-numeric string (returns -1 wrapped to unsigned 64-bit)
        result = StrToInt(self.str1)
        self._check_equal(result, -1 % (2**64))

        # Empty string (returns -1 wrapped to unsigned 64-bit)
        result = StrToInt(self.str_empty)
        self._check_equal(result, -1 % (2**64))

        # Number exceeding maximum 64-bit value (returns 0)
        large_num = claripy.StringV("18446744073709551616")  # 2^64
        result = StrToInt(large_num)
        self._check_equal(result, 0)

    def test_int_to_str(self):
        """Test integer to string conversion"""
        # Basic conversion
        result = IntToStr(claripy.BVV(123, 64))
        self._check_equal(result, "123")

        # Zero
        result = IntToStr(claripy.BVV(0, 64))
        self._check_equal(result, "0")

        # Large number
        result = IntToStr(claripy.BVV(9999999999, 64))
        self._check_equal(result, "9999999999")

        # Negative number (should use unsigned interpretation)
        result = IntToStr(claripy.BVV(-123 % (2**64), 64))
        self._check_equal(result, str(-123 % (2**64)))

    def test_is_digit(self):
        """Test string digit checking with various inputs"""
        # Basic digit check
        result = StrIsDigit(self.str_digit)
        self._check_equal(result, True)

        # Non-digit string
        result = StrIsDigit(self.str1)
        self._check_equal(result, False)

        # Empty string
        result = StrIsDigit(self.str_empty)
        self._check_equal(result, False)

        # Mixed content
        result = StrIsDigit(claripy.StringV("123abc"))
        self._check_equal(result, False)

        # Whitespace
        result = StrIsDigit(claripy.StringV(" 123 "))
        self._check_equal(result, False)

        # Non-ASCII digits (like Arabic numerals) are considered valid digits by Z3
        result = StrIsDigit(claripy.StringV("١٢٣"))  # Arabic numerals
        self._check_equal(result, True)

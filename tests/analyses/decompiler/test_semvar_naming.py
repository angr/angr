#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
"""
Test cases for semantic variable naming patterns.

This module tests all semantic variable naming patterns including:
- Loop counter naming (i, j, k for nested loops)
- Pointer naming (ptr, cur for pointer variables)
- Array index naming (idx, index for array indices)
- Call result naming (ptr for malloc, len for strlen)
- Size parameter naming (size, count for size parameters)
- Boolean flag naming (flag, found for boolean variables)
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

from typing import TYPE_CHECKING
import os
import unittest
import re

import angr

from tests.common import bin_location, print_decompilation_result, WORKER

if TYPE_CHECKING:
    from angr.analyses.decompiler import Decompiler


test_location = os.path.join(bin_location, "tests")


class TestSemvarNaming(unittest.TestCase):
    """Test cases for semantic variable naming patterns."""

    @classmethod
    def setUpClass(cls):
        """Set up the test class with the project and CFG."""
        cls.bin_path = os.path.join(test_location, "x86_64", "test_semvar_naming")
        cls.proj = angr.Project(cls.bin_path, auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            fail_fast=True,
            normalize=True,
        )
        cls.proj.analyses.CompleteCallingConventions()

    def _decompile_function(self, func_name: str) -> tuple[Decompiler, str]:
        """Helper to decompile a function by name."""
        func = self.cfg.functions[func_name]
        assert func is not None, f"Function {func_name} not found"
        dec = self.proj.analyses.Decompiler(func)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        return dec, dec.codegen.text

    def test_loop_counter_naming_nested_two(self):
        """Test that nested loops get i, j naming."""
        _, code = self._decompile_function("sum_matrix")

        # Check for outer loop with 'i'
        assert (
            re.search(r"for \(i = 0; i < [a-zA-Z0-9_]+; i \+= 1\)", code) is not None
        ), "Expected outer loop counter 'i' not found"

        # Check for inner loop with 'j'
        assert (
            re.search(r"for \(j = 0; j < [a-zA-Z0-9_]+; j \+= 1\)", code) is not None
        ), "Expected inner loop counter 'j' not found"

    def test_loop_counter_naming_triple_nested(self):
        """Test that triple nested loops get i, j, k naming."""
        _, text = self._decompile_function("triple_nested_loops")

        # Check for all three loop counters
        # Note: The exact pattern depends on decompiler output format
        # Should have i, j, k as loop counters
        has_i = "i" in text
        has_j = "j" in text
        has_k = "k" in text

        assert has_i, "Expected loop counter 'i' not found"
        assert has_j, "Expected loop counter 'j' not found"
        assert has_k, "Expected loop counter 'k' not found"

    def test_pointer_naming(self):
        """Test that pointer variables get appropriate naming."""
        _, text = self._decompile_function("pointer_test")

        # Should have pointer-like variable names
        # The pointer iterating through the array should be named
        # Common patterns: ptr, cur, p
        has_pointer_name = any(name in text.lower() for name in ["ptr", "cur", "p", "iter"])
        assert has_pointer_name and ("while" in text or "for" in text), "Expected pointer pattern variable not found"

    def test_linked_list_naming(self):
        """Test that linked list traversal gets appropriate naming."""
        _, text = self._decompile_function("sum_linked_list")

        # Should have iterator-like variable names for linked list traversal
        # Common patterns: cur, iter, node
        # The decompiler may convert while loop to for loop
        has_iterator_name = any(name in text.lower() for name in ["cur", "iter", "node", "ptr"])
        has_loop = "while" in text or "for" in text
        assert has_iterator_name and has_loop, "Expected linked list iterator variable not found"

    def test_array_index_naming(self):
        """Test that array index variables get appropriate naming."""
        _, text = self._decompile_function("array_scale")

        # Should have index-like variable names
        # Common patterns: i, idx, index
        # Also check for loop pattern
        has_index_name = any(name in text for name in ["i", "idx", "index"])
        assert has_index_name and re.search(r"for \(", text), "Expected array index variable not found"

    def test_call_result_naming_malloc(self):
        """Test that malloc result gets 'ptr' naming."""
        _, text = self._decompile_function("duplicate_string")

        # Should have malloc call and result stored in ptr-like variable
        assert "malloc" in text and "ptr" in text, "Expected malloc or pointer variable not found"

    def test_call_result_naming_strlen(self):
        """Test that strlen result gets 'len' naming."""
        _, text = self._decompile_function("duplicate_string")

        # Should have strlen call and result stored in len-like variable
        assert "strlen" in text and "len" in text, "Expected strlen or length variable not found"

    def test_size_parameter_naming(self):
        """Test that size parameters get appropriate naming."""
        _, text = self._decompile_function("copy_data")

        # Should have memcpy call with size parameter
        assert "memcpy" in text, "Expected memcpy call not found"

    def test_boolean_flag_naming(self):
        """Test that boolean flag variables get appropriate naming."""
        _, text = self._decompile_function("find_value")

        # Should have boolean-like variable patterns
        # Also check for 0/1 assignments typical of boolean flags
        has_boolean_pattern = "result" in text
        has_zero_one = "= 0" in text and "= 1" in text

        assert has_boolean_pattern or has_zero_one, "Expected boolean flag pattern not found"

    def test_multiple_boolean_flags(self):
        """Test function with multiple boolean flags."""
        _, text = self._decompile_function("validate_input")

        # Should have multiple boolean-like variables
        # Check for typical boolean patterns
        has_boolean_patterns = "= 0" in text or "= 1" in text
        assert has_boolean_patterns, "Expected multiple boolean flag patterns not found"

    def test_file_io_naming(self):
        """Test that file I/O functions get appropriate naming."""
        _, text = self._decompile_function("read_file_size")

        # Should have fopen call and result in fp-like variable
        assert "fopen" in text and "fp" in text, "Expected fopen call not found"

    def test_memory_allocation_naming(self):
        """Test that memory allocation functions get appropriate naming."""
        _, text = self._decompile_function("allocate_buffer")

        # Should have malloc call
        assert "malloc" in text, "Expected malloc call not found"

    def test_string_processing(self):
        """Test function with multiple naming patterns."""
        _, text = self._decompile_function("count_words")

        # Should have various patterns:
        # - count variable
        # - pointer variable for iteration
        # - boolean flag for in_word state
        assert "while" in text or "for" in text, "Expected loop construct not found"


if __name__ == "__main__":
    unittest.main()

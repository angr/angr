from __future__ import annotations

import unittest

from angr.utils.library import get_cpp_function_name


class TestLibrary(unittest.TestCase):
    """
    Test functions in angr.utils.library.
    """

    # pylint: disable=no-self-use

    def test_get_cpp_function_name(self):
        input_and_expected = [
            ("", ""),
            ("func", "func"),
            ("func(char*, int)", "func"),
            ("int __cdecl Fxi(int (__cdecl *)(int))", "Fxi"),
            ("public: __cdecl S::S(struct S &&)", "S::S"),
            ("printTwice<int>(int x)", "printTwice<int>"),
        ]

        for input_, expected in input_and_expected:
            with self.subTest(input_=input_):
                assert get_cpp_function_name(input_) == expected

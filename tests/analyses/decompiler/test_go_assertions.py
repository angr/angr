#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from .test_go_decompiler import GoDecompilationTarget, go_binary


class PanickingAssertions(GoDecompilationTarget):
    """
    ``x.(T)`` whose holder is not an interface-typed variable: the sink block calling ``runtime.panicdottype*`` is
    dropped and the data-word reads after the check become the assertion.
    """

    FUNCS = ("main.viaCall", "main.viaField", "main.viaFieldPtr")

    def test_sinks_are_gone(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                assert "panicdottype" not in text and "panicnildottype" not in text, text
                assert "if " not in text.split("{", 1)[1], text

    def test_call_result_holder(self):
        assert "\n    return v2.(int)\n" in self.texts["main.viaCall"], self.texts["main.viaCall"]

    def test_memory_holder(self):
        # a non-pointer type reads the value behind the data word; a pointer-shaped one is the data word itself.
        # The holder is the interface field of the struct h points at (h.v); older renders spelled it (*h).
        assert re.search(r"return (\(\*h\)|h\.v)\.\(string\)\n", self.texts["main.viaField"]), self.texts[
            "main.viaField"
        ]
        assert re.search(r"return (\(\*h\)|h\.v)\.\(\*main\.holder\)\n", self.texts["main.viaFieldPtr"]), self.texts[
            "main.viaFieldPtr"
        ]


class TestAssertionsGo122(PanickingAssertions):
    BINARY = go_binary("go1.22.5", "asserts")


class TestAssertionsGo127(PanickingAssertions):
    BINARY = go_binary("go1.27.1", "asserts")


if __name__ == "__main__":
    unittest.main()

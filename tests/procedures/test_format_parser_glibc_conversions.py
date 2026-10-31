#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""glibc's %m conversion and I flag in FormatParser.printf_argument_types."""

from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.procedures.stubs.format_parser import FormatParser


class TestPrintfGlibcConversions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = FormatParser(project=angr.load_shellcode(b"\x90", "AMD64"))

    def _types(self, fmt: bytes):
        types = self.parser.printf_argument_types(fmt)
        return None if types is None else [t.c_repr() for t in types]

    def test_m_takes_no_argument(self):
        assert self._types(b"%s: %m (%d)") == ["char *", "int"]
        assert self._types(b"%m") == []
        assert self._types(b"%-20m|%*d") == ["int", "int"]

    def test_i_flag(self):
        assert self._types(b"%Id %'Iu") == ["int", "unsigned int"]

    def test_unknown_conversion_is_still_unresolved(self):
        assert self._types(b"%d %ls") is None


if __name__ == "__main__":
    unittest.main()

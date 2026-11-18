#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures"  # pylint:disable=redefined-builtin

import unittest

from angr.procedures.definitions import parse_win32json
from angr.sim_type import SimTypeLength, SimTypePointer


def native_typedef(name: str, native: str) -> dict:
    return {"Kind": "NativeTypedef", "Name": name, "Def": {"Kind": "Native", "Name": native}}


class TestParseWin32Json(unittest.TestCase):
    def test_pointer_sized_integers(self):
        size = parse_win32json.handle_json_type({"Kind": "Native", "Name": "UIntPtr"}, None)
        assert isinstance(size, SimTypeLength)
        assert not size.signed

        wparam = parse_win32json.handle_json_type(native_typedef("WPARAM", "UIntPtr"), None)
        assert isinstance(wparam, SimTypeLength)
        assert not wparam.signed
        assert wparam.label == "WPARAM"

        lparam = parse_win32json.handle_json_type(native_typedef("LPARAM", "IntPtr"), None)
        assert isinstance(lparam, SimTypeLength)
        assert lparam.signed
        assert lparam.label == "LPARAM"

    def test_handles_stay_pointers(self):
        hwnd = parse_win32json.handle_json_type(native_typedef("HWND", "IntPtr"), None)
        assert isinstance(hwnd, SimTypePointer)
        assert hwnd.label == "HWND"


if __name__ == "__main__":
    unittest.main()

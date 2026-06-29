# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestConstHexDisplay(unittest.TestCase):
    """
    End-to-end test for the automatic hex-vs-decimal constant display heuristic
    (angr.utils.constants.should_use_hex).

    Source: binaries/tests_src/const_hex_display.c
    """

    def _decompile_const_sink(self):
        bin_path = os.path.join(test_location, "x86_64", "const_hex_display")
        proj = angr.Project(bin_path)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.functions["const_sink"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        return dec.codegen.text

    def test_const_hex_display(self):
        text = self._decompile_const_sink()

        # Constants that should render in hexadecimal, paired with the decimal
        # form that must NOT appear (regression guard).
        expected_hex = {
            0xFF: "0xff",  # >= 8 consecutive 1 bits
            0x55: "0x55",  # alternating 0101 bit pattern
            0x1111: "0x1111",  # repeated nibble bit pattern
            0x100: "0x100",  # power-of-two flag
            0x1200: "0x1200",  # round hex, low byte zero
            0xDEADBEEF: "0xdeadbeef",  # well-known magic constant
        }
        # Constants that should render in decimal, paired with the hex form that
        # must NOT appear.
        expected_dec = {
            10000: "10000",  # run of identical decimal digits
            5000: "5000",  # round decimal (multiple of 1000)
            12345: "12345",  # plain number, no structure
            42: "42",  # plain small number
        }

        for value, hex_str in expected_hex.items():
            assert f"= {hex_str};" in text, f"expected `= {hex_str};` (value {value}) in:\n{text}"
            assert f"= {value};" not in text, f"did not expect decimal `= {value};` in:\n{text}"

        for value, dec_str in expected_dec.items():
            assert f"= {dec_str};" in text, f"expected `= {dec_str};` (value {value}) in:\n{text}"
            assert f"= {hex(value)};" not in text, f"did not expect hex `= {hex(value)};` in:\n{text}"


if __name__ == "__main__":
    unittest.main()

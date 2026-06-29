#!/usr/bin/env python3
# pylint:disable=no-self-use,unused-argument,missing-class-docstring
from __future__ import annotations

import unittest

from angr.utils.constants import should_use_hex


class TestShouldUseHex(unittest.TestCase):
    """Tests for the hex-vs-decimal display heuristic :func:`should_use_hex`."""

    def _assert_hex(self, *values, bits=32):
        for v in values:
            assert should_use_hex(v, bits) is True, f"expected hex for {v} (0x{v & ((1 << bits) - 1):x})"

    def _assert_dec(self, *values, bits=32):
        for v in values:
            assert should_use_hex(v, bits) is False, f"expected decimal for {v} (0x{v & ((1 << bits) - 1):x})"

    def test_magic_constants(self):
        self._assert_hex(0xDEADBEEF, 0xCAFEBABE, 0xBAADF00D, 0xFEEDFACE, 0xDEADC0DE)

    def test_alignment_masks(self):
        self._assert_hex(0xFFFFFFF0, 0xFFFFFFE0, 0xFFFFFFFC, 0xFFFFFFF8)
        self._assert_hex(0xFFFFFFFFFFFFFFF0, bits=64)

    def test_consecutive_ones(self):
        # >= 8 consecutive 1 bits in a sub-word mask
        self._assert_hex(0xFF, 0x1FF, 0xFFF, 0xFFFF)
        # 0xFF0: eight 1s then zeros
        self._assert_hex(0xFF0)
        # exactly 8 consecutive ones is enough
        self._assert_hex(0xFF00, 0x1FE)  # 0x1FE = 0b1_1111_1110 -> eight 1s
        # a sub-word mask stays hex in a wider type
        self._assert_hex(0xFFFFFF, bits=64)  # 24 ones, not a type boundary

    def test_type_saturating_values_stay_decimal(self):
        # values that saturate their declared width are rendered as signed decimal by the codegen,
        # so the heuristic must not force them to hex
        self._assert_dec(0xFFFFFFFF, 0xFFFFFFFE, 0x7FFFFFFF, bits=32)  # -1, -2, INT_MAX
        self._assert_dec(0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF, bits=64)  # -1, INT64_MAX

    def test_consecutive_ones_below_threshold(self):
        # 7 consecutive 1s is not enough on its own
        self._assert_dec(0x7F, 0x7E)  # 0x7F = 0b0111_1111 (seven 1s)

    def test_repeated_bit_patterns(self):
        # alternating 0101 / 1010
        self._assert_hex(0x55, 0xAA, 0x5555, 0xAAAA, 0x55555555, 0xAAAAAAAA)
        # repeated nibble 0001 / 0011
        self._assert_hex(0x1111, 0x3333, 0x11111111)
        # repeated byte (period 8)
        self._assert_hex(0xABAB, 0x12121212, 0x41414141)

    def test_power_of_two_flags(self):
        self._assert_hex(0x100, 0x200, 0x400, 0x1000, 0x4000, 0x10000, 0x80000000)

    def test_power_of_two_below_threshold_stays_decimal(self):
        # powers of two below 0x100 with no other hex signal
        self._assert_dec(0x10, 0x20, 0x40, 0x80)

    def test_round_hex_low_byte_zero(self):
        self._assert_hex(0x1200, 0x300, 0x12300, 0xAB00)

    def test_decimal_digit_runs(self):
        # > 3 consecutive identical decimal digits
        self._assert_dec(10000, 11111, 1000000, 99999, 22220)

    def test_round_decimal(self):
        self._assert_dec(1000, 2000, 5000, 20000, 123000)

    def test_small_magnitudes(self):
        self._assert_dec(0, 1, 2, 5, 9)

    def test_plain_decimal(self):
        self._assert_dec(11, 16, 32, 42, 100, 127, 255 - 1, 12345)

    def test_zero_is_decimal(self):
        self._assert_dec(0)

    def test_negative_values(self):
        # negative inputs are interpreted as their unsigned two's-complement form using ``bits``
        # -16 in 32-bit is 0xFFFFFFF0 -> alignment mask -> hex
        self._assert_hex(-16, bits=32)
        # -1 in 32-bit is 0xFFFFFFFF -> type-saturating -> decimal (the codegen renders it as -1)
        self._assert_dec(-1, bits=32)

    def test_bits_none_defaults_to_value_width(self):
        # should not raise when bits is unknown
        assert should_use_hex(0xFF, None) is True
        assert should_use_hex(42, None) is False


if __name__ == "__main__":
    unittest.main()

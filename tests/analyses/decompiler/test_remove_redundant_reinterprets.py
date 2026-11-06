"""Tests for removing redundant reinterpret expressions."""

from __future__ import annotations

import unittest

from angr.ailment.expression import Const, Reinterpret
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import RemoveRedundantReinterprets


class TestRemoveRedundantReinterprets(unittest.TestCase):
    """Test constant bit-pattern reinterpretation."""

    def test_integer_constants_are_reduced_to_their_declared_width(self):
        """Integer constants are interpreted using only their declared-width bits."""
        optimizer = RemoveRedundantReinterprets(None, None, Manager())
        cases = (
            (32, (1 << 64) | 0x3F800000, 1.0),
            (32, -1082130432, -1.0),
            (64, (1 << 100) | 0x3FF0000000000000, 1.0),
        )
        for bits, value, expected in cases:
            with self.subTest(bits=bits, value=value):
                operand = Const(None, value, bits)
                expr = Reinterpret(None, bits, "I", bits, "F", operand)
                result = optimizer.optimize(expr)
                assert isinstance(result, Const)
                self.assertEqual(result.value, expected)


if __name__ == "__main__":
    unittest.main()

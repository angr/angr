from __future__ import annotations

import pickle
import unittest

from angr import claripy


class TestPickle(unittest.TestCase):
    """Unpickling must rebuild an expression with every operand it was pickled with."""

    def assert_round_trip(self, expr):
        restored = pickle.loads(pickle.dumps(expr))
        self.assertEqual(restored.hash(), expr.hash())
        self.assertEqual(len(restored.args), len(expr.args))

    def test_nary_bool(self):
        x = claripy.BVS("x", 32)
        b = claripy.BoolS("b")
        self.assert_round_trip(claripy.And(x != 1, x <= 5, x != 0, x != 3))
        self.assert_round_trip(claripy.Or(x == 1, x == 2, x == 3))
        self.assert_round_trip(claripy.xor(claripy.xor(b, x == 2), x == 3))

    def test_nary_bv(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        self.assert_round_trip(x + y + 3 + x)
        self.assert_round_trip(x * y * 5)
        self.assert_round_trip(x & y & 7)
        self.assert_round_trip(x | y | 8)
        self.assert_round_trip(x ^ y ^ 9)

    def test_fp_min_max_fma_round(self):
        x = claripy.FPS("x", claripy.FSORT_DOUBLE)
        y = claripy.FPS("y", claripy.FSORT_DOUBLE)
        rm = claripy.fp.RM.RM_TowardsZero
        self.assert_round_trip(claripy.fpMin(x, y))
        self.assert_round_trip(claripy.fpMax(x, y))
        self.assert_round_trip(claripy.fpFMA(rm, x, y, x))
        self.assert_round_trip(claripy.fpRoundToIntegral(rm, x))

    def test_rounding_modes(self):
        for name in dir(claripy.fp.RM):
            if name.startswith("RM_"):
                rm = getattr(claripy.fp.RM, name)
                self.assertEqual(pickle.loads(pickle.dumps(rm)), rm)


if __name__ == "__main__":
    unittest.main()

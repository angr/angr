from __future__ import annotations

import unittest

import claripy


class TestSimplifyConstruction(unittest.TestCase):
    """AST-building entry points that bind their operation result before
    wrapping it (`chop`, `Concat`) simplify it, so a concrete result is folded
    and interned rather than returned as a raw `Extract`/`Concat`."""

    def test_concat_of_concrete_folds(self):
        c = claripy.Concat(claripy.BVV(0, 32), claripy.BVV(0x1337, 32))
        self.assertEqual(c.op, "BVV")
        self.assertEqual(c.concrete_value, 0x1337)
        # interned: equal to the directly-built constant
        self.assertIs(c, claripy.BVV(0x1337, 64))

    def test_chop_of_concrete_folds(self):
        bytes_ = claripy.BVV(0x41424344, 32).chop(8)
        self.assertEqual([b.op for b in bytes_], ["BVV"] * 4)
        self.assertEqual([b.concrete_value for b in bytes_], [0x41, 0x42, 0x43, 0x44])

    def test_chop_isolates_concrete_from_symbolic(self):
        # The concrete high half must come back concrete even when concatenated
        # with a symbolic low half (the chopped pieces are simplified).
        v = claripy.Concat(claripy.BVV(0xAABBCCDD, 32), claripy.BVS("s", 32))
        hi = v.chop(8)[0]
        self.assertFalse(hi.symbolic)
        self.assertEqual(hi.concrete_value, 0xAA)


if __name__ == "__main__":
    unittest.main()

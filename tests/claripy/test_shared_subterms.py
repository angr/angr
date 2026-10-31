from __future__ import annotations

import unittest

from angr import claripy


def _shared_chain(x, y, depth):
    # every level uses the previous one twice: a DAG of size O(depth), a tree of size O(2**depth)
    e = x
    for _ in range(depth):
        e = (e * y + 0x1234567) ^ claripy.LShR(e, 3)
    return e


def _concrete_chain(x, y, depth):
    m = 0xFFFFFFFF
    e = x
    for _ in range(depth):
        e = (((e * y) & m) + 0x1234567) & m ^ (e >> 3)
    return e


class TestSharedSubterms(unittest.TestCase):
    """Solver queries must be linear in the DAG size of an expression, not in its tree size."""

    DEPTH = 40

    def test_is_true(self):
        x, y = claripy.BVS("x", 32), claripy.BVS("y", 32)
        e = _shared_chain(x, y, self.DEPTH)
        s = claripy.Solver()
        self.assertFalse(s.is_true(e > 0))
        self.assertFalse(s.is_false(e > 0))

    def test_eval(self):
        x, y = claripy.BVS("x", 32), claripy.BVS("y", 32)
        e = _shared_chain(x, y, self.DEPTH)
        for s in (claripy.Solver(), claripy.SolverReplacement(auto_replace=False)):
            s.add([x == 3, y == 5])
            expected = _concrete_chain(3, 5, self.DEPTH)
            self.assertEqual(list(s.eval(e, 2)), [expected])
            self.assertEqual(list(s.eval(e, 1)), [expected])

    def test_simplify_cancels_shared_term(self):
        x, y = claripy.BVS("x", 32), claripy.BVS("y", 32)
        e = _shared_chain(x, y, self.DEPTH)
        # assertTrue: a failing assertIs would repr the DAG as a tree
        self.assertTrue(claripy.simplify((e + x) - (y + e) + y) is x)


if __name__ == "__main__":
    unittest.main()

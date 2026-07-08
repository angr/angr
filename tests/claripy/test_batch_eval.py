from __future__ import annotations

import unittest

from angr import claripy


class TestBatchEval(unittest.TestCase):
    def test_batch_eval_joint_model(self):
        # Each tuple must be drawn from a single model: x + y == 10 has to hold
        # for every returned (x, y) pair, which evaluating the expressions
        # independently would not guarantee.
        s = claripy.Solver()
        x = claripy.BVS("x", 8)
        y = claripy.BVS("y", 8)
        s.add(x + y == 10)

        results = s.batch_eval([x, y], 50)
        self.assertTrue(results)
        self.assertTrue(all(isinstance(t, tuple) and len(t) == 2 for t in results))
        for xv, yv in results:
            self.assertEqual((xv + yv) % 256, 10)
        # Tuples are distinct.
        self.assertEqual(len(set(results)), len(results))

    def test_batch_eval_mixed_types(self):
        s = claripy.Solver()
        x = claripy.BVS("x", 8)
        s.add(x == 7)
        flag = claripy.BVS("flag", 8)
        s.add(flag == 1)
        cond = flag == 1  # a Bool expression
        f = claripy.FPS("f", claripy.FSORT_DOUBLE)
        s.add(f == claripy.FPV(2.5, claripy.FSORT_DOUBLE))

        (row,) = s.batch_eval([x, cond, f], 1)
        xv, cv, fv = row
        self.assertEqual(xv, 7)
        self.assertIs(cv, True)
        self.assertEqual(fv, 2.5)

    def test_batch_eval_string(self):
        s = claripy.Solver()
        st = claripy.StringS("s")
        s.add(st == claripy.StringV("hi"))
        self.assertEqual(s.batch_eval([st], 1), [("hi",)])

    def test_batch_eval_empty(self):
        s = claripy.Solver()
        self.assertEqual(s.batch_eval([], 5), [])

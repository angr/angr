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
        self.assertEqual(s.batch_eval([], 5), [()])


SOLVERS = {
    "replacement": lambda: claripy.SolverReplacement(auto_replace=False),
    "replacement_auto": lambda: claripy.SolverReplacement(),
    "solver": claripy.Solver,
    "z3": claripy.SolverZ3,
    "cacheless": claripy.SolverCacheless,
    "composite": claripy.SolverComposite,
    "hybrid": claripy.SolverHybrid,
}


class TestBatchEvalRowsAreModels(unittest.TestCase):
    def setUp(self):
        self.x = claripy.BVS("x", 8)
        self.y = claripy.BVS("y", 8)
        self.exprs = [self.x, self.x + 1, claripy.ULT(self.x, 2), self.y]
        self.expected = {(v, v + 1, v < 2, v ^ 0x5A) for v in range(6)}

    def assert_rows(self, s, rows, expected, n, extra=()):
        self.assertEqual(len(rows), min(n, len(expected)))
        self.assertEqual(len(set(rows)), len(rows))
        self.assertTrue(set(rows) <= expected, set(rows) - expected)
        for row in rows:
            pins = [e == v for e, v in zip(self.exprs, row)]
            self.assertTrue(s.satisfiable(extra_constraints=list(extra) + pins), row)

    def test_rows_with_constraints(self):
        for name, mk in SOLVERS.items():
            with self.subTest(name):
                s = mk()
                s.add(claripy.ULT(self.x, 6))
                s.add(self.y == self.x ^ 0x5A)
                for n in (1, 3, 100):
                    self.assert_rows(s, s.batch_eval(self.exprs, n), self.expected, n)

    def test_rows_with_replacement(self):
        s = claripy.SolverReplacement(auto_replace=False)
        s.add(claripy.ULT(self.x, 6))
        s.add_replacement(self.y, self.x ^ 0x5A)
        for n in (1, 2, 100):
            self.assert_rows(s, s.batch_eval(self.exprs, n), self.expected, n)

    def test_rows_with_extra_constraints(self):
        for name, mk in SOLVERS.items():
            with self.subTest(name):
                s = mk()
                s.add(claripy.ULT(self.x, 6))
                s.add(self.y == self.x ^ 0x5A)
                extra = [self.x != 0, self.x != 3]
                expected = {r for r in self.expected if r[0] not in (0, 3)}
                rows = s.batch_eval(self.exprs, 100, extra_constraints=extra)
                self.assert_rows(s, rows, expected, 100, extra)
                self.assertEqual(len(s.batch_eval(self.exprs, 100)), 6)

    def test_rows_across_composite_children(self):
        s = claripy.SolverComposite()
        s.add(claripy.ULT(self.x, 2))
        s.add(claripy.ULT(self.y, 3))
        rows = s.batch_eval([self.x, self.y, self.x + self.y], 100)
        self.assertEqual(set(rows), {(a, b, a + b) for a in range(2) for b in range(3)})
        self.assertEqual(len(rows), 6)

    def test_rows_mixed_sorts(self):
        s = claripy.SolverReplacement(auto_replace=False)
        f = claripy.FPS("f", claripy.FSORT_DOUBLE)
        s.add(claripy.Or(f == claripy.FPV(1.5, claripy.FSORT_DOUBLE), f == claripy.FPV(-2.0, claripy.FSORT_DOUBLE)))
        s.add(claripy.ULT(self.x, 2))
        b = claripy.BoolS("b")
        s.add(b == (self.x == 1))
        rows = s.batch_eval([f, b, self.x], 10)
        self.assertEqual(set(rows), {(fv, xv == 1, xv) for fv in (1.5, -2.0) for xv in (0, 1)})
        self.assertEqual(len(rows), 4)

    def test_rows_strings(self):
        s = claripy.SolverReplacement(auto_replace=False)
        st = claripy.StringS("st")
        s.add(claripy.Or(st == claripy.StringV("hi"), st == claripy.StringV("yo")))
        s.add(claripy.ULT(self.x, 2))
        rows = s.batch_eval([st, self.x], 10)
        self.assertEqual(set(rows), {(sv, xv) for sv in ("hi", "yo") for xv in (0, 1)})
        self.assertEqual(len(rows), 4)

    def test_unsat(self):
        for name, mk in SOLVERS.items():
            with self.subTest(name):
                s = mk()
                s.add(claripy.ULT(self.x, 2))
                s.add(claripy.UGT(self.x, 5))
                self.assertEqual(s.batch_eval(self.exprs, 3), [])

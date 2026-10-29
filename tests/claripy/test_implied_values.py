from __future__ import annotations

import random
import time
import unittest

from angr import claripy


def _deep_sp_expr(sp, depth):
    # byte shuffles of sp[31:0], the shape of VMProtect handler arithmetic over the stack pointer
    lo = sp[31:0]
    e = lo
    for i in range(depth):
        e = ((e << (i % 7 + 1)) | claripy.LShR(e, 32 - (i % 7 + 1))) ^ (lo[15:0].zero_extend(16) + i)
    return e


class TestImpliedValues(unittest.TestCase):
    def test_extract_equality_pins_deep_expression(self):
        sp = claripy.BVS("sp", 64)
        e = _deep_sp_expr(sp, 400)
        expected = [e.replace(sp, claripy.BVV(0x123456787FFF0000, 64)).simplify().concrete_value]
        for cls in (claripy.Solver, lambda: claripy.SolverReplacement(auto_replace=False)):
            s = cls()
            s.add(sp[31:0] == 0x7FFF0000)
            t = time.perf_counter()
            self.assertEqual(s.eval(e, 3), expected)
            self.assertLess(time.perf_counter() - t, 2.0)

    def test_unpinned_bits_still_solved(self):
        sp = claripy.BVS("sp", 64)
        s = claripy.Solver()
        s.add(sp[31:0] == 0x7FFF0000)
        self.assertEqual(len(s.eval(sp[63:32], 3)), 3)

    def test_unsat_constraints_give_no_value(self):
        x = claripy.BVS("x", 8)
        s = claripy.Solver()
        s.add(x == 1)
        s.add(x == 2)
        self.assertEqual(s.eval(x + 1, 2), [])

    def test_boolean_constraints_pin_ite(self):
        a = claripy.BoolS("a")
        b = claripy.BoolS("b")
        y = claripy.BVS("y", 8)
        s = claripy.Solver()
        s.add(claripy.And(a, y == 3))
        s.add(claripy.Not(b))
        self.assertEqual(s.eval(claripy.If(a, claripy.If(b, claripy.BVV(1, 8), y), claripy.BVV(2, 8)), 2), [3])

    def test_matches_cacheless_on_random_expressions(self):
        rng = random.Random(7)
        x = claripy.BVS("x", 16)
        lo, hi = x[7:0], x[15:8]
        for _ in range(150):
            c = rng.randrange(256)
            e = lo if rng.random() < 0.5 else hi
            for _ in range(rng.randrange(1, 6)):
                k = claripy.BVV(rng.randrange(256), 8)
                o = hi if rng.random() < 0.3 else lo
                e = rng.choice([lambda: e + k, lambda: e ^ o, lambda: e & k, lambda: e * o, lambda: e | k])()
            ref = claripy.SolverCacheless()
            ref.add(lo == c)
            s = claripy.Solver()
            s.add(lo == c)
            got = s.eval(e, 2)
            want = ref.eval(e, 2)
            if len(want) == 1:
                self.assertEqual(got, want)
            else:
                self.assertEqual(len(got), 2)


if __name__ == "__main__":
    unittest.main()

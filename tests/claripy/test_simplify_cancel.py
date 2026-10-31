from __future__ import annotations

import time
import unittest

from angr import claripy


class Taint(claripy.Annotation):
    # like PUSHAN's VM taint annotations
    eliminatable = False
    relocatable = True

    def __init__(self, tag):
        self.tag = tag

    def __eq__(self, other):
        return type(other) is Taint and other.tag == self.tag

    def __hash__(self):
        return hash(("Taint", self.tag))


class Droppable(claripy.Annotation):
    eliminatable = True
    relocatable = False


class TestSimplifyCancel(unittest.TestCase):
    def test_examples(self):
        y = claripy.BVS("y", 32)
        c = claripy.BVV(3, 32)
        self.assertIs(claripy.simplify((c + y) - y), c)
        self.assertIs(claripy.simplify(5 - (7 + y) + y + 7), claripy.BVV(5, 32))

    def test_format_pointer(self):
        y = claripy.BVS("y", 64)
        k, c = 0x140005000, 0x7F123456
        r = claripy.simplify((k - (c + y)) + y + c)
        self.assertTrue(r.concrete)
        self.assertEqual(r.concrete_value, k)

    def test_partial_and_coefficients(self):
        a, b, c = (claripy.BVS(n, 32) for n in "abc")
        self.assertIs(claripy.simplify(a - (b + c) + c), claripy.simplify(a - b))
        self.assertIs(claripy.simplify(a + a + b - b - a), a)
        self.assertIs(claripy.simplify(a * 3 - a * 3 + 1), claripy.BVV(1, 32))
        e = claripy.simplify(a + b - c)
        self.assertEqual(e.variables, {a.args[0], b.args[0], c.args[0]})

    def test_wraparound_and_widths(self):
        x = claripy.BVS("x", 32)
        self.assertIs(claripy.simplify(x + 0xFFFFFFFF + 1), x)
        x8, y8 = claripy.BVS("x8", 8), claripy.BVS("y8", 8)
        self.assertIs(claripy.simplify(x8 * 0x80 + x8 * 0x80), claripy.BVV(0, 8))
        z = claripy.ZeroExt(24, (x8 + y8) - y8)
        self.assertIs(claripy.simplify(z), claripy.ZeroExt(24, x8))
        a = claripy.BVS("a", 64)
        lo, hi = a[31:0], a[63:32]
        self.assertIs(claripy.simplify(x - lo + lo), x)
        self.assertIn("a", str(claripy.simplify(lo + x - hi)))
        w = claripy.BVS("w", 128)
        self.assertIs(claripy.simplify(w + (2**128 - 1) + 5 - w), claripy.BVV(4, 128))

    def test_annotations(self):
        y, x = claripy.BVS("y", 32), claripy.BVS("x", 32)
        yt = y.annotate(Taint(1))
        r = claripy.simplify((3 + yt) - yt)
        self.assertTrue(r.concrete)
        self.assertEqual(r.concrete_value, 3)
        self.assertIn(Taint(1), r.annotations)
        # annotations tell leaves apart (variable recovery annotates distinct `top`s)
        self.assertTrue(claripy.simplify((3 + yt) - y).symbolic)
        self.assertTrue(claripy.simplify((3 + yt) - y.annotate(Taint(2))).symbolic)

        yd = y.annotate(Droppable())
        self.assertIs(claripy.simplify((x + yd) - yd), x)

        yp = y.annotate(claripy.SimplificationAvoidanceAnnotation())
        r = claripy.simplify((x + yp) - (yp + 3))
        self.assertEqual(len(r.variables), 2)

    def test_shared_dag(self):
        # assertTrue, not assertIs: a failure repr would print these DAGs as exponential trees
        x = claripy.BVS("x", 64)
        t0 = time.time()
        e = x
        for _ in range(60):
            e = (e + e) - e
        self.assertTrue(claripy.simplify(e) is x)
        e, total = x, 0
        for i in range(16):
            k, c = 0x1000 + i, 0x77 * i
            e = ((k - (c + e)) + e + c) + e
            total += k
        self.assertTrue(claripy.simplify(e) is claripy.simplify(x + total))
        self.assertLess(time.time() - t0, 2)


if __name__ == "__main__":
    unittest.main()

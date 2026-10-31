from __future__ import annotations

import random
import time
import unittest

import z3

from angr import claripy


class Taint(claripy.Annotation):
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


def to_z3(e):
    decls = "".join(
        f"(declare-fun |{leaf.args[0]}| () (_ BitVec {leaf.size()}))" for leaf in e.leaf_asts() if leaf.op == "BVS"
    )
    s = decls + f"(declare-fun __r () (_ BitVec {e.size()}))(assert (= __r {e.smtlib()}))"
    return z3.parse_smt2_string(s)[0].arg(1)


def z3_constant(e):
    """The constant z3 reduces `e` to, or None."""
    zs = z3.simplify(to_z3(e))
    return zs.as_long() if z3.is_bv_value(zs) else None


class TestSimplifyKnownBits(unittest.TestCase):
    def assert_folds(self, e, value):
        r = claripy.simplify(e)
        self.assertTrue(r.concrete)
        self.assertEqual(r.concrete_value, value)
        self.assertEqual(z3_constant(e), value)

    def test_examples(self):
        r = claripy.BVS("r", 64)
        self.assert_folds((r & 0x68) | 0xF8, 0xF8)
        e = r | 0x201
        for op, k in [
            ("^", 0x7FF75452EF80),
            ("-", 0x42),
            ("^", 0xC9),
            ("+", 0x7FF75452EF04),
            ("|", 0x7FF75452EF05),
            ("^", 0x7FF75452ED99),
            ("|", 0xCC),
            ("^", 0xFFFFFFFFFFFFFF32),
            ("&", 0x7FF75452EE04),
            ("^", 0x106),
            ("+", 0x80),
            ("^", 0x7FF75452EE84),
            ("+", 0x5C),
            ("^", 0x82),
        ]:
            e = {"^": e.__xor__, "-": e.__sub__, "+": e.__add__, "|": e.__or__, "&": e.__and__}[op](k)
        self.assert_folds(e, 0x3E0)
        s = claripy.BVS("s", 64)
        e = (
            (((((((s & 0x40) - 0xFFFFFFFFFFFFFFE0) | 0xFB) ^ 0x7FF75452EF88) | 0xFFFFFFFFFFFFFFE0) * 2) | 0xCC) & 0x80
        ) - 0xF7
        self.assert_folds(e, 0xFFFFFFFFFFFFFF89)
        # an rflags bit: zero-extended 1-bit flag shifted into place, masked back out
        f = claripy.BVS("f", 1)
        self.assert_folds(((claripy.ZeroExt(63, f) << 6) | 2) & 0xFFBF, 2)

    def test_partial_knowledge_keeps_shape(self):
        x, n = claripy.BVS("x", 64), claripy.BVS("n", 64)
        for e in [
            x | 0xF0,
            x & 0xF0,
            (x & 0xFF00) + 1,
            (x | 1) ^ 0xFF,
            ((x & 0xFF) + 0xFF) & 0x100,
            claripy.LShR(x, n),
        ]:
            self.assertIs(claripy.simplify(e), e)
            self.assertIsNone(z3_constant(e))

    def test_annotations(self):
        x = claripy.BVS("x", 32)
        xt = x.annotate(Taint(1))
        r = claripy.simplify((xt & 0x68) | 0xF8)
        self.assertTrue(r.concrete)
        self.assertEqual(r.concrete_value, 0xF8)
        self.assertIn(Taint(1), r.annotations)
        r = claripy.simplify((x.annotate(Droppable()) & 0x68) | 0xF8)
        self.assertTrue(r.concrete)
        self.assertEqual(len(r.annotations), 0)
        # pinned terms are opaque: their bits are unknown, and a pinned node is never folded
        xp = x.annotate(claripy.SimplificationAvoidanceAnnotation())
        self.assertTrue(claripy.simplify(xp | 0xF8).symbolic)
        inner = (x & 0x68).annotate(claripy.SimplificationAvoidanceAnnotation())
        self.assertTrue(claripy.simplify(inner | 0xF8).symbolic)
        self.assertTrue(claripy.simplify(inner).symbolic)

    def test_random_against_z3(self):
        """Random mask/shift/add chains: every native fold agrees with z3, and nothing that z3
        leaves symbolic folds natively."""
        rng = random.Random(0x5EED)
        folded = 0
        t0 = time.time()
        for width in (8, 32, 64):
            x, y = claripy.BVS("x", width), claripy.BVS("y", width)
            mask = (1 << width) - 1
            for _ in range(120):
                e = rng.choice([x, y, x & rng.getrandbits(width), x | rng.getrandbits(width)])
                for _ in range(rng.randint(2, 7)):
                    k = rng.getrandbits(width) & mask
                    op = rng.randrange(12)
                    if op == 0:
                        e = e & k
                    elif op == 1:
                        e = e | k
                    elif op == 2:
                        e = e ^ k
                    elif op == 3:
                        e = e + k
                    elif op == 4:
                        e = e - k
                    elif op == 5:
                        e = e << rng.randrange(width)
                    elif op == 6:
                        e = claripy.LShR(e, rng.randrange(width))
                    elif op == 7:
                        e = e >> rng.randrange(width)
                    elif op == 8:
                        e = e * (1 << rng.randrange(width))
                    elif op == 9:
                        e = claripy.If(x == y, e, e | k)
                    elif op == 10:
                        e = ~e
                    else:
                        e = claripy.Concat(e[width - 1 : width // 2], (e | k)[width // 2 - 1 : 0])
                r = claripy.simplify(e)
                zc = z3_constant(e)
                if r.concrete:
                    folded += 1
                    self.assertEqual(r.concrete_value, zc, f"native folded {e} to {r} but z3 gives {zc}")
                elif zc is not None:
                    # z3 may know more (e.g. through x - x); the native fold must just never disagree
                    solver = claripy.Solver()
                    self.assertEqual(solver.eval(r, 2), (zc,))
        self.assertGreater(folded, 50)
        self.assertLess(time.time() - t0, 5)

    def test_shared_dag(self):
        x = claripy.BVS("x", 64)
        t0 = time.time()
        e = x
        for i in range(60):
            e = (((e ^ (0x10000 + i)) | e) & ~(1 << (i % 60))) & 0xFFFFFFFFFFFFFFFF
        self.assertTrue(claripy.simplify(e).symbolic)
        e = x
        for i in range(60):
            e = (((e & 0xFF00) + e) | (0xF0 + i)) & 0xF0
        r = claripy.simplify(e)
        self.assertTrue(r.concrete)
        self.assertEqual(r.concrete_value, 0xF0)
        self.assertLess(time.time() - t0, 2)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

from angr import claripy

# Every solver flavour that answers min/max with the constraint solver.
CONSTRAINT_SOLVERS = (
    claripy.Solver,
    claripy.SolverCacheless,
    claripy.SolverHybrid,
    claripy.SolverReplacement,
    claripy.SolverComposite,
)


class TestSolverSignedMinMax(unittest.TestCase):
    """Solver.min/max with signed=True return signed integers, as claripy does."""

    def test_negative_range(self):
        for cls in CONSTRAINT_SOLVERS:
            with self.subTest(solver=cls.__name__):
                x = claripy.BVS("x", 8)
                s = cls()
                s.add(x.SLT(0))
                self.assertEqual(s.min(x, signed=True), -128)
                self.assertEqual(s.max(x, signed=True), -1)
                # The unsigned view of the same range is unchanged.
                self.assertEqual(s.min(x), 128)
                self.assertEqual(s.max(x), 255)

    def test_mixed_sign_range(self):
        for cls in CONSTRAINT_SOLVERS:
            with self.subTest(solver=cls.__name__):
                x = claripy.BVS("x", 32)
                s = cls()
                s.add(x.SGE(-5))
                s.add(x.SLE(7))
                self.assertEqual(s.min(x, signed=True), -5)
                self.assertEqual(s.max(x, signed=True), 7)
                self.assertEqual(s.min(x), 0)
                self.assertEqual(s.max(x), 2**32 - 1)

    def test_non_negative_range(self):
        for cls in CONSTRAINT_SOLVERS:
            with self.subTest(solver=cls.__name__):
                x = claripy.BVS("x", 16)
                s = cls()
                s.add(x.SGE(3))
                s.add(x.SLE(9))
                self.assertEqual(s.min(x, signed=True), 3)
                self.assertEqual(s.max(x, signed=True), 9)

    def test_unconstrained(self):
        x = claripy.BVS("x", 8)
        s = claripy.Solver()
        self.assertEqual(s.min(x, signed=True), -128)
        self.assertEqual(s.max(x, signed=True), 127)

    def test_wide_bitvectors(self):
        for bits in (64, 65, 128, 256):
            for cls in CONSTRAINT_SOLVERS:
                with self.subTest(bits=bits, solver=cls.__name__):
                    x = claripy.BVS("x", bits)
                    lo = -(2 ** (bits - 1)) + 3
                    hi = 2 ** (bits - 2) + 1
                    s = cls()
                    s.add(x.SGE(lo))
                    s.add(x.SLE(hi))
                    self.assertEqual(s.min(x, signed=True), lo)
                    self.assertEqual(s.max(x, signed=True), hi)

                    s = cls()
                    s.add(x.SLT(-1))
                    self.assertEqual(s.min(x, signed=True), -(2 ** (bits - 1)))
                    self.assertEqual(s.max(x, signed=True), -2)
                    self.assertEqual(s.max(x), 2**bits - 2)

    def test_extra_constraints(self):
        x = claripy.BVS("x", 8)
        s = claripy.Solver()
        s.add(x.SLE(10))
        self.assertEqual(s.min(x, extra_constraints=[x.SGE(-3)], signed=True), -3)
        self.assertEqual(s.max(x, extra_constraints=[x.SLT(-3)], signed=True), -4)

    def test_concrete_expression(self):
        """A concrete negative value reads back negative from every solver."""
        value = claripy.BVV(-5, 70)
        for cls in (*CONSTRAINT_SOLVERS, claripy.SolverConcrete, claripy.SolverVSA):
            with self.subTest(solver=cls.__name__):
                s = cls()
                self.assertEqual(s.min(value, signed=True), -5)
                self.assertEqual(s.max(value, signed=True), -5)
                self.assertEqual(s.min(value), 2**70 - 5)
                self.assertEqual(s.max(value), 2**70 - 5)

    def test_hybrid_exact_and_approximate(self):
        x = claripy.BVS("x", 8)
        s = claripy.SolverHybrid()
        s.add(x.SLT(0))
        self.assertEqual(s.min(x, signed=True, exact=True), -128)
        self.assertEqual(s.max(x, signed=True, exact=True), -1)
        # The approximate (VSA) backend over-approximates, but still reports
        # signed bounds as signed integers.
        self.assertEqual(s.min(x, signed=True, exact=False), -128)
        self.assertLessEqual(s.max(x, signed=True, exact=False), 127)

    def test_matches_vsa_module(self):
        """The VSA solver agrees with claripy.vsa's signed bounds."""
        for expr in (claripy.BVV(0x80, 8), claripy.BVV(-1, 128), claripy.BVS("x", 8)):
            with self.subTest(expr=expr):
                s = claripy.SolverVSA()
                self.assertEqual(s.min(expr, signed=True), claripy.vsa.min(expr, signed=True))
                self.assertEqual(s.max(expr, signed=True), claripy.vsa.max(expr, signed=True))


if __name__ == "__main__":
    unittest.main()

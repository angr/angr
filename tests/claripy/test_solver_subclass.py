from __future__ import annotations

import unittest

from angr import claripy


class TestSolverCopiesKeepSubclass(unittest.TestCase):
    """branch(), blank_copy(), split() and merge() return the same Python class as their source."""

    def test_copies_keep_class(self):
        x, y = claripy.BVS("x", 8), claripy.BVS("y", 8)
        for make in (
            claripy.Solver,
            claripy.SolverZ3,
            claripy.SolverCacheless,
            claripy.SolverConcrete,
            claripy.SolverVSA,
            claripy.SolverHybrid,
            claripy.SolverComposite,
            lambda: claripy.SolverReplacement(auto_replace=False),
        ):
            s = make()
            cls = type(s)
            with self.subTest(cls=cls.__name__):
                if cls is not claripy.SolverConcrete:
                    s.add([x > 1, y < 9])
                self.assertIs(type(s.branch()), cls)
                self.assertIs(type(s.blank_copy()), cls)
                self.assertTrue(all(type(part) is cls for part in s.split()))
                mc = claripy.BoolS("mc")
                _, merged = s.merge([s.branch()], [mc, ~mc])
                self.assertIs(type(merged), cls)
                _, merged = s.branch().merge([s.branch()], [mc, ~mc], common_ancestor=s)
                self.assertIs(type(merged), cls)

    def test_replacement_branch_keeps_replacements(self):
        x = claripy.BVS("x", 8)
        s = claripy.SolverReplacement(auto_replace=False)
        s.add_replacement(x, claripy.BVV(3, 8))
        b = s.branch()
        self.assertIsInstance(b, claripy.SolverReplacement)
        self.assertEqual(b.eval(x, 2), [3])


if __name__ == "__main__":
    unittest.main()

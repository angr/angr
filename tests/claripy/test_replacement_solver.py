from __future__ import annotations

import pickle
import unittest

from angr import claripy


class TestReplacementSolver(unittest.TestCase):
    def test_replacement_solver_exists(self):
        """SolverReplacement is exported and constructible."""
        s = claripy.SolverReplacement()
        self.assertIsInstance(s, claripy.Solver)

    def test_auto_replace_default_extracts_replacements(self):
        """By default (auto_replace=True) `x == c` is turned into a replacement."""
        s = claripy.SolverReplacement()
        x = claripy.BVS("x", 8)
        s.add(x == 5)
        self.assertEqual(s.eval(x, 1)[0], 5)

    def test_auto_replace_true_keyword(self):
        """Passing auto_replace=True explicitly behaves like the default."""
        s = claripy.SolverReplacement(auto_replace=True)
        x = claripy.BVS("x", 8)
        s.add(x == 9)
        self.assertEqual(s.eval(x, 1)[0], 9)

    def test_auto_replace_false_disables_extraction(self):
        """With auto_replace=False, adding `x == c` does not register a
        replacement, but explicit replacements still work."""
        s = claripy.SolverReplacement(auto_replace=False)
        x = claripy.BVS("x", 8)
        s.add(x == 5)

        # The backend still solves the constraint, so x evaluates to 5.
        self.assertEqual(s.eval(x, 1)[0], 5)

        # Explicit replacements override the value regardless of auto_replace.
        s.add_replacement(x, claripy.BVV(7, 8))
        self.assertEqual(s.eval(x, 1)[0], 7)

    def test_auto_replace_clear_replacements(self):
        s = claripy.SolverReplacement()
        x = claripy.BVS("x", 8)
        s.add_replacement(x, claripy.BVV(3, 8))
        self.assertEqual(s.eval(x, 1)[0], 3)
        s.clear_replacements()
        # After clearing, x is unconstrained again (any value is allowed).
        self.assertTrue(s.satisfiable())

    def test_auto_replace_branch_preserves_setting(self):
        """branch() clones the solver, keeping auto_replace=False."""
        s = claripy.SolverReplacement(auto_replace=False)
        b = s.branch()
        x = claripy.BVS("x", 8)
        b.add(x == 5)
        b.add_replacement(x, claripy.BVV(4, 8))
        self.assertEqual(b.eval(x, 1)[0], 4)

    def test_auto_replace_pickle_roundtrip(self):
        """auto_replace survives a pickle round-trip."""
        s = claripy.SolverReplacement(auto_replace=False)
        restored = pickle.loads(pickle.dumps(s))
        self.assertIsInstance(restored, claripy.Solver)
        x = claripy.BVS("x", 8)
        restored.add(x == 5)
        restored.add_replacement(x, claripy.BVV(6, 8))
        self.assertEqual(restored.eval(x, 1)[0], 6)


class _Marker(claripy.Annotation):
    eliminatable = True
    relocatable = True


class TestReplacementSolverPushanApi(unittest.TestCase):
    """The surface the data-sensitive analyses (pushan) reach into."""

    def test_timeout_kwarg(self):
        s = claripy.SolverReplacement(auto_replace=False, timeout=1234)
        self.assertEqual(s.timeout, 1234)

    def test_apply_replacements_without_eval(self):
        s = claripy.SolverReplacement(auto_replace=False)
        x, y = claripy.BVS("x", 8), claripy.BVS("y", 8)
        s.add_replacement(x, claripy.BVV(5, 8))
        replaced = s.apply_replacements(x + y)
        self.assertNotIn("x", str(replaced.variables))
        self.assertIn("y", str(replaced.variables))

    def test_lookup_ignores_annotations(self):
        s = claripy.SolverReplacement(auto_replace=False)
        x = claripy.BVS("x", 8)
        s.add_replacement(x, claripy.BVV(5, 8))
        annotated = x.annotate(_Marker())
        self.assertNotEqual(hash(annotated), hash(x))
        self.assertEqual(s.eval(annotated + 1, 2), [6])
        self.assertIs(s.get_replacement(annotated).concrete_value, 5)
        self.assertIsNone(s.get_replacement(claripy.BVS("y", 8)))

    def test_replacement_registered_on_annotated_fires_on_bare(self):
        s = claripy.SolverReplacement(auto_replace=False)
        x = claripy.BVS("x", 8)
        s.add_replacement(x.annotate(_Marker()), claripy.BVV(9, 8))
        self.assertEqual(s.eval(x, 2), [9])

    def test_flattened_add_prefix(self):
        s = claripy.SolverReplacement(auto_replace=False)
        x, y, z = (claripy.BVS(n, 8) for n in "xyz")
        s.add_replacement(x + y, claripy.BVV(7, 8))
        total = x + y + z
        self.assertEqual(total.op, "__add__")
        self.assertEqual(len(total.args), 3)
        replaced = s.apply_replacements(total)
        self.assertNotIn("x", str(replaced.variables))
        self.assertIn("z", str(replaced.variables))

    def test_replacements_dict_and_import(self):
        a = claripy.SolverReplacement(auto_replace=False)
        b = claripy.SolverReplacement(auto_replace=False)
        x, y = claripy.BVS("x", 8), claripy.BVS("y", 8)
        a.add_replacement(x, claripy.BVV(1, 8))
        b.add_replacement(y, claripy.BVV(2, 8))
        self.assertEqual(len(a.replacements), 1)
        # keys are Base.hash(); Python's hash() folds the u64 into Py_hash_t and differs
        self.assertEqual(a.replacements[x.hash()].concrete_value, 1)
        a.import_replacements(b)
        self.assertEqual(len(a.replacements), 2)
        self.assertEqual(a.eval(x + y, 2), [3])

    def test_merge_unions_replacements(self):
        a = claripy.SolverReplacement(auto_replace=False)
        b = claripy.SolverReplacement(auto_replace=False)
        x, y = claripy.BVS("x", 8), claripy.BVS("y", 8)
        a.add_replacement(x, claripy.BVV(1, 8))
        b.add_replacement(y, claripy.BVV(2, 8))
        c1, c2 = claripy.BoolS("c1"), claripy.BoolS("c2")
        merged_occurred, merged = a.merge([b], [c1, c2])
        self.assertTrue(merged_occurred)
        self.assertEqual(len(merged.replacements), 2)
        self.assertEqual(merged.eval(x + y, 2), [3])


class TestLeafAsts(unittest.TestCase):
    def test_leaf_asts_dedup_and_order(self):
        x, y = claripy.BVS("x", 8), claripy.BVS("y", 8)
        expr = (x + y) * (x + claripy.BVV(3, 8))
        leaves = expr.leaf_asts()
        self.assertTrue(all(leaf.depth == 1 for leaf in leaves))
        names = sorted(str(leaf.variables) for leaf in leaves if leaf.symbolic)
        # x appears twice in the expression but once among the leaves
        self.assertEqual(len([leaf for leaf in leaves if leaf.symbolic]), 2)
        self.assertEqual(len(names), 2)
        self.assertEqual([leaf.concrete_value for leaf in leaves if leaf.concrete], [3])
        self.assertEqual(x.leaf_asts()[0].hash(), x.hash())

    def test_add_replacement_coerces_python_values(self):
        """int/bool replacement values are coerced like Python claripy; other values are ignored."""
        x = claripy.BVS("x", 64)
        b = claripy.BoolS("b")
        s = claripy.SolverReplacement(auto_replace=False)
        s.add_replacement(0x28 + x, 0x1234)
        self.assertEqual(list(s.eval(0x28 + x, 2)), [0x1234])
        s.add_replacement(b, True)
        self.assertEqual(list(s.eval(claripy.If(b, claripy.BVV(1, 8), claripy.BVV(2, 8)), 2)), [1])
        s.add_replacement(x, "junk")
        self.assertEqual(len(s.eval(x, 2)), 2)


if __name__ == "__main__":
    unittest.main()

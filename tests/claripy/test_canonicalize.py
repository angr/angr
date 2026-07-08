from __future__ import annotations

import itertools
import unittest

from angr import claripy


class TestCanonicalize(unittest.TestCase):
    def test_no_args_renames_to_canonical(self):
        x = claripy.BVS("x", 32)
        canon = (x + 1).canonicalize()[-1]
        # The lone variable becomes v0.
        self.assertIn("v0", str(canon))
        self.assertNotIn("x", str(canon))

    def test_structurally_equal_exprs_canonicalize_equal(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        a = (x + 1) * x
        b = (y + 1) * y
        self.assertTrue(a.canonicalize()[-1].identical(b.canonicalize()[-1]))

    def test_distinct_exprs_stay_distinct(self):
        x = claripy.BVS("x", 32)
        self.assertFalse((x + 1).canonicalize()[-1].identical((x + 2).canonicalize()[-1]))

    def test_shared_var_map_and_counter(self):
        # Canonicalize a constraint, then values under the same mapping so the
        # same variable keeps the same canonical name across expressions.
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)

        nmap, ncounter, _ = (x > 5).canonicalize()
        n_val = (x + 7).canonicalize(var_map=nmap, counter=ncounter)[-1]

        umap, ucounter, _ = (y > 5).canonicalize()
        u_val = (y + 7).canonicalize(var_map=umap, counter=ucounter)[-1]

        self.assertTrue(n_val.identical(u_val))

    def test_var_map_is_mutated_in_place(self):
        x = claripy.BVS("x", 32)
        var_map = {}
        returned, _, _ = (x + 1).canonicalize(var_map=var_map)
        self.assertIs(returned, var_map)
        self.assertEqual(len(var_map), 1)

    def test_counter_accepts_int(self):
        x = claripy.BVS("x", 32)
        # clarirs returns an int counter; it must also accept one back.
        _, counter, _ = (x + 1).canonicalize(counter=0)
        self.assertEqual(counter, 1)

    def test_counter_accepts_iterator(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        # claripy passes an itertools.count; it is advanced in place and
        # returned as-is.
        counter = itertools.count(0)
        _, returned, _canon = (x + y).canonicalize(counter=counter)
        self.assertIs(returned, counter)
        # Two distinct variables consumed v0 and v1; next value is 2.
        self.assertEqual(next(counter), 2)

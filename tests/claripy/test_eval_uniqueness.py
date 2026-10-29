from __future__ import annotations

import functools
import json
import operator
import os
import unittest

from angr import claripy

DATA = os.path.join(os.path.dirname(__file__), "data", "vmp_key_flag.json")

_NARY = {
    "__add__": operator.add,
    "__sub__": operator.sub,
    "__xor__": operator.xor,
    "__or__": operator.or_,
    "__and__": operator.and_,
    "__lshift__": operator.lshift,
}


def _load_dag(path):
    built = []
    for op, args in json.load(open(path, encoding="utf-8")):
        a = [built[x["ref"]] if isinstance(x, dict) else x for x in args]
        if op == "BVV":
            v = claripy.BVV(a[0], a[1])
        elif op == "BVS":
            v = claripy.BVS(a[0], a[1], explicit_name=True)
        elif op in _NARY:
            v = functools.reduce(_NARY[op], a)
        elif op == "__invert__":
            v = ~a[0]
        else:
            v = getattr(claripy, op)(*a)
        built.append(v)
    return built[-1]


class TestEvalUniqueness(unittest.TestCase):
    def test_unique_value_of_vm_flag_over_widened_key(self):
        # A VMProtect flag over a decryption key widened to an unconstrained variable by a state
        # merge (netsky1_vmp): constant, but proving it unique took z3's incremental core minutes.
        e = _load_dag(DATA)
        self.assertEqual(e.variables, frozenset({"key"}))
        s = claripy.SolverReplacement(auto_replace=False, timeout=5000)
        self.assertEqual(s.eval(e, 2), [1])

    def test_eval_n_enumerates_distinct_values(self):
        x = claripy.BVS("x", 8)
        s = claripy.SolverReplacement(auto_replace=False)
        s.add(claripy.ULT(x, 5))
        self.assertEqual(sorted(s.eval(x, 10)), [0, 1, 2, 3, 4])
        self.assertEqual(len(s.eval(x, 3)), 3)


if __name__ == "__main__":
    unittest.main()

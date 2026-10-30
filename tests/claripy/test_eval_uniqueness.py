from __future__ import annotations

import functools
import gzip
import json
import operator
import os
import unittest

from angr import claripy

DATA = os.path.join(os.path.dirname(__file__), "data", "vmp_key_flag.json")
STORE_ADDR_DATA = os.path.join(os.path.dirname(__file__), "data", "vmp_store_addr.json.gz")

_NARY = {
    "__add__": operator.add,
    "__sub__": operator.sub,
    "__xor__": operator.xor,
    "__or__": operator.or_,
    "__and__": operator.and_,
    "__lshift__": operator.lshift,
    "__rshift__": operator.rshift,
    "__eq__": operator.eq,
    "__ne__": operator.ne,
}


def _build(op, a):
    if op == "BVV":
        return claripy.BVV(a[0], a[1])
    if op == "BVS":
        return claripy.BVS(a[0], a[1], explicit_name=True)
    if op == "BoolS":
        return claripy.BoolS(a[0], explicit_name=True)
    if op == "BoolV":
        return claripy.BoolV(a[0])
    if op in _NARY:
        return functools.reduce(_NARY[op], a)
    if op == "__invert__":
        return ~a[0]
    return getattr(claripy, op)(*a)


def _load_dag(path):
    built = []
    for op, args in json.load(open(path, encoding="utf-8")):
        built.append(_build(op, [built[x["ref"]] if isinstance(x, dict) else x for x in args]))
    return built[-1]


def _load_query(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        d = json.load(f)
    built = []
    for op, args in d["nodes"]:
        built.append(_build(op, [built[x["ref"]] if isinstance(x, dict) else x for x in args]))
    return [built[i] for i in d["constraints"]], built[d["expr"]]


class TestEvalUniqueness(unittest.TestCase):
    def test_unique_value_of_vm_flag_over_widened_key(self):
        # A VMProtect flag over a decryption key widened to an unconstrained variable by a state
        # merge (netsky1_vmp): constant, but proving it unique took z3's incremental core minutes.
        e = _load_dag(DATA)
        self.assertEqual(e.variables, frozenset({"key"}))
        s = claripy.SolverReplacement(auto_replace=False, timeout=5000)
        self.assertEqual(s.eval(e, 2), [1])

    def test_eval_n_reads_the_model_of_a_fresh_solver_round(self):
        # A VMProtect store address (libpng-ultra-vmp): its second or third value exhausts the
        # incremental round budget and is found by a fresh solver with rounds still to go; pushing
        # the exclusion scope before reading that model failed with "there is no current model".
        constraints, e = _load_query(STORE_ADDR_DATA)
        s = claripy.SolverReplacement(auto_replace=False, timeout=300000)
        for c in constraints:
            s.add(c)
        self.assertEqual(len(set(s.eval(e, 4))), 4)

    def test_eval_n_enumerates_distinct_values(self):
        x = claripy.BVS("x", 8)
        s = claripy.SolverReplacement(auto_replace=False)
        s.add(claripy.ULT(x, 5))
        self.assertEqual(sorted(s.eval(x, 10)), [0, 1, 2, 3, 4])
        self.assertEqual(len(s.eval(x, 3)), 3)


if __name__ == "__main__":
    unittest.main()

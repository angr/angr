from __future__ import annotations

import os
import unittest

import z3

import angr
from angr import claripy
from angr.concretization_strategies.any_named import SimConcretizationStrategyAnyNamed
from tests.common import bin_location


def _parses(smt: str) -> bool:
    try:
        z3.parse_smt2_string(smt)
    except z3.Z3Exception:
        return False
    return True


class TestSmtlibSymbols(unittest.TestCase):
    """Solver.to_smt2() must render every variable name as a legal SMT-LIB symbol."""

    # Names angr mints itself. None is a simple symbol.
    QUOTED = [
        "ailexpr_(r0<64> Add 0x8<64>)",
        "[mem_7ffe_1_64]",
        "mem_7ffe{UNINITIALIZED}",
        "Func_read_Arg#0",
        "has space",
        "0starts_with_digit",
        "pipe|name",
        "back\\slash",
    ]
    # Legal simple symbols: emitted verbatim, as before.
    SIMPLE = ["x", "mem_7ffe_1_64", "reg_rax_0_64", "cgc-flag-byte-0", "a.b/c<=>?!@$%^&*+~"]

    def test_quoted_symbols_parse_and_solve(self):
        for name in self.QUOTED:
            x = claripy.BVS(name, 32, explicit_name=True)
            s = claripy.Solver()
            s.add(x == 0x41)
            smt = s.to_smt2()
            escaped = name.replace("\\", "\\\\").replace("|", "\\|")
            self.assertIn(f"(declare-fun |{escaped}| () (_ BitVec 32))\n", smt)
            self.assertIn(f"(assert (= |{escaped}| (_ bv65 32)))\n", smt)
            z = z3.Solver()
            z.add(z3.parse_smt2_string(smt))
            self.assertEqual(z.check(), z3.sat, smt)
            model = z.model()
            self.assertEqual(str(model.eval(z3.BitVec(name, 32), model_completion=True)), "65")

    def test_quoted_symbols_every_sort(self):
        name = "has space"
        fsort = claripy.fp.FSORT_DOUBLE
        for ast in (
            claripy.BoolS(name, explicit_name=True),
            claripy.FPS(name, fsort, explicit_name=True) == claripy.FPV(1.0, fsort),
            claripy.StringS(name, explicit_name=True) == claripy.StringV("v"),
        ):
            s = claripy.Solver()
            s.add(ast)
            smt = s.to_smt2()
            self.assertIn(f"(declare-fun |{name}| ()", smt)  # "has space" needs no escaping
            self.assertTrue(_parses(smt), smt)

    def test_simple_symbols_unquoted(self):
        # No-regression guard: a legal simple symbol must not be quoted.
        for name in self.SIMPLE:
            x = claripy.BVS(name, 32, explicit_name=True)
            s = claripy.Solver()
            s.add(x == 1)
            smt = s.to_smt2()
            self.assertIn(f"(declare-fun {name} () (_ BitVec 32))\n", smt)
            self.assertNotIn("|", smt)
            self.assertTrue(_parses(smt), smt)

    def test_any_named_strategy_names_are_quoted(self):
        # AnyNamed names the variable "[<repr>]". Parsing the whole script additionally needs the
        # unrelated (bvreverse ...) rendering fixed, so assert quoting only.
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        state = proj.factory.entry_state()
        state.memory.read_strategies = [SimConcretizationStrategyAnyNamed(), *(state.memory.read_strategies or [])]
        ptr = claripy.BVS("ptr", 64)
        value = state.memory.load(ptr, 8)
        bracketed = [v for v in value.variables if v.startswith("[")]
        self.assertTrue(bracketed, value.variables)
        state.solver.add(value == 0x41)
        s = claripy.Solver()
        for c in state.solver.constraints:
            s.add(c)
        smt = s.to_smt2()
        name = bracketed[0]
        self.assertIn(f"(declare-fun |{name}| () (_ BitVec 64))\n", smt)
        # No bare occurrence of the name anywhere in the script.
        self.assertEqual(smt.count(name), smt.count(f"|{name}|"))

    def test_any_named_pipe_in_name_round_trips(self):
        # A disjunctive address mints a name containing "|", which must be escaped.
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        state = proj.factory.entry_state()
        state.memory.read_strategies = [SimConcretizationStrategyAnyNamed(), *(state.memory.read_strategies or [])]
        addr = claripy.BVS("p", 64) | claripy.BVS("q", 64)
        value = state.memory.load(addr, 8)
        piped = [v for v in value.variables if "|" in v]
        self.assertTrue(piped, value.variables)
        name = piped[0]
        s = claripy.Solver()
        s.add(claripy.BVS(name, 64, explicit_name=True) == 0x41)
        smt = s.to_smt2()
        escaped = name.replace("\\", "\\\\").replace("|", "\\|")
        self.assertIn(f"(declare-fun |{escaped}| () (_ BitVec 64))\n", smt)
        self.assertTrue(_parses(smt), smt)
        # z3 must read the name back unchanged.
        parsed = z3.parse_smt2_string(smt)
        declared = list(z3.z3util.get_vars(z3.And(*parsed)))
        self.assertEqual(declared[0].decl().name(), name)

    def test_real_execution_constraints_parse(self):
        # No-regression guard: every path constraint of a real execution keeps serializing.
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        simgr = proj.factory.simulation_manager()
        simgr.run()
        checked = 0
        for state in simgr.deadended:
            if not state.solver.constraints:
                continue
            s = claripy.Solver()
            for c in state.solver.constraints:
                s.add(c)
            smt = s.to_smt2()
            self.assertTrue(_parses(smt), smt)
            checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()

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


def _declared(smt: str) -> dict[str, z3.SortRef]:
    assertions = z3.parse_smt2_string(smt)
    return {v.decl().name(): v.sort() for v in z3.z3util.get_vars(z3.And(*assertions))}


def _z3_model(smt: str) -> z3.ModelRef:
    z = z3.Solver()
    z.add(z3.parse_smt2_string(smt))
    assert z.check() == z3.sat, smt
    return z.model()


class TestSmtlibSymbols(unittest.TestCase):
    """Solver.to_smt2() must render every variable name as a legal SMT-LIB symbol."""

    QUOTED = {
        "ailexpr_(r0<64> Add 0x8<64>)": "|ailexpr_(r0<64> Add 0x8<64>)|",
        "[mem_7ffe_1_64]": "|[mem_7ffe_1_64]|",
        "mem_7ffe{UNINITIALIZED}": "|mem_7ffe{UNINITIALIZED}|",
        "Func_read_Arg#0": "|Func_read_Arg#0|",
        "has space": "|has space|",
        "0starts_with_digit": "|0starts_with_digit|",
        "": "||",
        "café": "|café|",
        "let": "|let|",
        "forall": "|forall|",
        "!": "|!|",
        "assert": "|assert|",
        "check-sat": "|check-sat|",
        "@solver_internal": "|@solver_internal|",
        ".solver_internal": "|.solver_internal|",
    }
    # Escaped the way z3 prints them, which z3 >= 5.3 cannot parse back.
    ESCAPED = {
        "pipe|name": "|pipe\\|name|",
        "back\\slash": "|back\\\\slash|",
        "[p_0_64 | q_1_64]": "|[p_0_64 \\| q_1_64]|",
    }
    # Legal simple symbols: emitted verbatim, as before.
    SIMPLE = [
        "x",
        "mem_7ffe_1_64",
        "reg_rax_0_64",
        "cgc-flag-byte-0",
        "a.b/c<=>?!@$%^&*+~",
        "Let",
        "assert_0",
    ]
    SORT_NAMES = ["has space", "let", "@x", "x"]

    def test_quoted_symbol_rendering(self):
        for name, expected in {**self.QUOTED, **self.ESCAPED}.items():
            with self.subTest(name=name):
                self.assertEqual(claripy.BVS(name, 32, explicit_name=True).smtlib(), expected)
                self.assertEqual(claripy.BoolS(name, explicit_name=True).smtlib(), expected)
                self.assertEqual(claripy.FPS(name, claripy.fp.FSORT_DOUBLE, explicit_name=True).smtlib(), expected)
                self.assertEqual(claripy.StringS(name, explicit_name=True).smtlib(), expected)

    def test_escaped_symbols_match_z3(self):
        for name in self.ESCAPED:
            with self.subTest(name=name):
                self.assertEqual(claripy.BVS(name, 32, explicit_name=True).smtlib(), z3.BitVec(name, 32).sexpr())

    def test_quoted_symbols_parse_and_solve(self):
        for name in self.QUOTED:
            if name == "":
                continue  # z3 cannot declare the empty symbol
            with self.subTest(name=name):
                s = claripy.Solver()
                s.add(claripy.BVS(name, 32, explicit_name=True) == 0x41)
                smt = s.to_smt2()
                self.assertEqual(_declared(smt), {name: z3.BitVecSort(32)}, smt)
                model = _z3_model(smt)
                self.assertEqual(model.eval(z3.BitVec(name, 32), model_completion=True).as_long(), 0x41)

    def test_quoted_symbols_every_sort(self):
        fsort = claripy.fp.FSORT_DOUBLE
        for name in self.SORT_NAMES:
            for ast, sort in (
                (claripy.BoolS(name, explicit_name=True), z3.BoolSort()),
                (claripy.BVS(name, 32, explicit_name=True) == 1, z3.BitVecSort(32)),
                (claripy.FPS(name, fsort, explicit_name=True) == claripy.FPV(1.0, fsort), z3.Float64()),
                (claripy.StringS(name, explicit_name=True) == claripy.StringV("v"), z3.StringSort()),
            ):
                with self.subTest(name=name, sort=sort):
                    s = claripy.Solver()
                    s.add(ast)
                    smt = s.to_smt2()
                    self.assertEqual(_declared(smt), {name: sort}, smt)

    def test_simple_symbols_unquoted(self):
        # No-regression guard: a legal simple symbol must not be quoted.
        for name in self.SIMPLE:
            with self.subTest(name=name):
                x = claripy.BVS(name, 32, explicit_name=True)
                self.assertEqual(x.smtlib(), name)
                s = claripy.Solver()
                s.add(x == 1)
                smt = s.to_smt2()
                self.assertNotIn("|", smt)
                self.assertEqual(_declared(smt), {name: z3.BitVecSort(32)}, smt)

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
        s.add(state.solver.constraints)
        smt = s.to_smt2()
        name = bracketed[0]
        quoted = z3.BitVec(name, 64).sexpr()
        self.assertEqual(claripy.BVS(name, 64, explicit_name=True).smtlib(), quoted)
        self.assertIn(quoted, smt)
        # No bare occurrence of the name anywhere in the script.
        self.assertEqual(smt.count(name), smt.count(quoted))

    def test_any_named_pipe_in_name_is_escaped(self):
        # A disjunctive address mints a name containing "|", which must be escaped.
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        state = proj.factory.entry_state()
        state.memory.read_strategies = [SimConcretizationStrategyAnyNamed(), *(state.memory.read_strategies or [])]
        addr = claripy.BVS("p", 64) | claripy.BVS("q", 64)
        value = state.memory.load(addr, 8)
        piped = [v for v in value.variables if "|" in v]
        self.assertTrue(piped, value.variables)
        name = piped[0]
        x = claripy.BVS(name, 64, explicit_name=True)
        quoted = z3.BitVec(name, 64).sexpr()
        self.assertEqual(x.smtlib(), quoted)
        s = claripy.Solver()
        s.add(x == 0x41)
        smt = s.to_smt2()
        self.assertEqual(smt.count(quoted), 2)  # declaration and assertion

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
            s.add(state.solver.constraints)
            smt = s.to_smt2()
            self.assertTrue(_parses(smt), smt)
            checked += 1
        self.assertGreater(checked, 0)


class TestSmtlibStringLiterals(unittest.TestCase):
    LITERALS = {
        "hello": '"hello"',
        "": '""',
        'say "hi"': '"say ""hi"""',
        "back\\slash": '"back\\u{5c}slash"',
        "\\u{41}": '"\\u{5c}u{41}"',
        "tab\tnewline\n": '"tab\\u{9}newline\\u{a}"',
        "nul\x00del\x7f": '"nul\\u{0}del\\u{7f}"',
        "café \U0001f600": '"caf\\u{e9} \\u{1f600}"',
        "printable ~!@#$%^&*()|'`": '"printable ~!@#$%^&*()|\'`"',
    }

    def test_string_literal_rendering(self):
        for value, expected in self.LITERALS.items():
            with self.subTest(value=value):
                self.assertEqual(claripy.StringV(value).smtlib(), expected)

    def test_string_literals_round_trip(self):
        for value in self.LITERALS:
            with self.subTest(value=value):
                s = claripy.Solver()
                s.add(claripy.StringS("s", explicit_name=True) == claripy.StringV(value))
                smt = s.to_smt2()
                model = _z3_model(smt)
                var = z3.String("s")
                length = model.eval(z3.Length(var)).as_long()
                # z3's string printing re-escapes, so compare code points.
                codes = [model.eval(z3.StrToCode(z3.SubString(var, i, 1))).as_long() for i in range(length)]
                self.assertEqual(codes, [ord(c) for c in value], smt)


if __name__ == "__main__":
    unittest.main()

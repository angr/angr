#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import unittest

from angr import SIM_LIBRARIES, SimState, claripy
from tests.common import minimal_project

BASE = 0x100000
ACCEPT = BASE + 0x1000


def make_state():
    return SimState(project=minimal_project("AMD64"), mode="symbolic")


def put(state, addr, data: bytes):
    state.memory.store(addr, claripy.BVV(data, len(data) * 8))


def call(name, state, *args):
    proc = SIM_LIBRARIES["libc.so.6"][0].get(name, state.project.arch)
    ret = proc.execute(state, arguments=list(args)).ret_expr
    assert ret is not None
    return ret


class TestStrScan(unittest.TestCase):
    def test_procedures_are_implemented(self):
        lib = SIM_LIBRARIES["libc.so.6"][0]
        arch = minimal_project("AMD64").arch
        for name in ("strrchr", "strspn", "strcspn", "strpbrk"):
            proc = lib.get(name, arch)
            self.assertFalse(getattr(proc, "is_stub", False), f"{name} is still a stub SimProcedure")

    def test_strrchr(self):
        state = make_state()
        put(state, BASE, b"abca\x00")

        def rchr(byte):
            return state.solver.eval(call("strrchr", state, claripy.BVV(BASE, 64), claripy.BVV(byte, 32)))

        self.assertEqual(rchr(ord("a")), BASE + 3)  # last 'a'
        self.assertEqual(rchr(ord("z")), 0)  # not found
        self.assertEqual(rchr(0), BASE + 4)  # searching for NUL returns the terminator

    def test_strspn(self):
        state = make_state()
        put(state, BASE, b"aabbc\x00")
        put(state, ACCEPT, b"ab\x00")
        span = call("strspn", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))
        self.assertEqual(state.solver.eval(span), 4)

    def test_strcspn(self):
        state = make_state()
        put(state, BASE, b"xxabc\x00")
        put(state, ACCEPT, b"ab\x00")
        span = call("strcspn", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))
        self.assertEqual(state.solver.eval(span), 2)

    def test_strpbrk(self):
        state = make_state()
        put(state, BASE, b"hello world\x00")
        put(state, ACCEPT, b"ow\x00")
        ptr = call("strpbrk", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))
        self.assertEqual(state.solver.eval(ptr), BASE + 4)
        put(state, ACCEPT, b"zq\x00")
        ptr = call("strpbrk", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))
        self.assertEqual(state.solver.eval(ptr), 0)

    def test_empty_accept_set(self):
        """The empty set is an edge case where spn and cspn differ."""
        state = make_state()
        put(state, BASE, b"abc\x00")
        put(state, ACCEPT, b"\x00")
        self.assertEqual(state.solver.eval(call("strspn", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))), 0)
        self.assertEqual(state.solver.eval(call("strcspn", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))), 3)
        self.assertEqual(state.solver.eval(call("strpbrk", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))), 0)

    def test_strcspn_without_rejected_byte(self):
        state = make_state()
        put(state, BASE, b"abc\x00")
        put(state, ACCEPT, b"xyz\x00")
        span = call("strcspn", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))
        self.assertEqual(state.solver.eval(span), 3)

    def test_symbolic_haystack(self):
        """A symbolic haystack must produce a constrained expression, not a crash."""
        state = make_state()
        put(state, ACCEPT, b"ab\x00")
        for i in range(6):
            state.memory.store(BASE + i, claripy.BVS(f"c{i}", 8))
        for name, extra in (
            ("strrchr", (claripy.BVV(ord("a"), 32),)),
            ("strspn", (claripy.BVV(ACCEPT, 64),)),
            ("strcspn", (claripy.BVV(ACCEPT, 64),)),
            ("strpbrk", (claripy.BVV(ACCEPT, 64),)),
        ):
            result = call(name, state, claripy.BVV(BASE, 64), *extra)
            self.assertIsNotNone(result, name)

    def test_strrchr_symbolic_char(self):
        state = make_state()
        put(state, BASE, b"abca\x00")
        c = claripy.BVS("c", 32)
        result = call("strrchr", state, claripy.BVV(BASE, 64), c)
        self.assertTrue(state.solver.symbolic(result))
        for char_val, expected in ((ord("a"), BASE + 3), (ord("b"), BASE + 1), (0, BASE + 4), (ord("z"), 0)):
            branch = state.copy()
            branch.solver.add(c == char_val)
            self.assertEqual(branch.solver.eval(result), expected)

    def test_strrchr_symbolic_nul_does_not_match_past_terminator(self):
        state = make_state()
        c1 = claripy.BVS("c1", 8)
        put(state, BASE, b"a")
        state.memory.store(BASE + 1, c1)
        put(state, BASE + 2, b"a\x00")
        result = call("strrchr", state, claripy.BVV(BASE, 64), claripy.BVV(ord("a"), 32))

        early_nul = state.copy()
        early_nul.solver.add(c1 == 0)
        self.assertTrue(early_nul.solver.satisfiable())
        self.assertEqual(early_nul.solver.eval(result), BASE)

        non_nul = state.copy()
        non_nul.solver.add(c1 == ord("x"))
        self.assertEqual(non_nul.solver.eval(result), BASE + 2)

        state2 = make_state()
        c0 = claripy.BVS("c0", 8)
        state2.memory.store(BASE, c0)
        put(state2, BASE + 1, b"a\x00")
        result2 = call("strrchr", state2, claripy.BVV(BASE, 64), claripy.BVV(ord("a"), 32))
        empty = state2.copy()
        empty.solver.add(c0 == 0)
        self.assertTrue(empty.solver.satisfiable())
        self.assertEqual(empty.solver.eval(result2), 0)

    def test_strpbrk_symbolic_nul_does_not_match_past_terminator(self):
        state = make_state()
        c0 = claripy.BVS("c0", 8)
        state.memory.store(BASE, c0)
        put(state, BASE + 1, b"o\x00")
        put(state, ACCEPT, b"o\x00")
        result = call("strpbrk", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))

        empty = state.copy()
        empty.solver.add(c0 == 0)
        self.assertEqual(empty.solver.eval(result), 0)

        non_nul = state.copy()
        non_nul.solver.add(c0 == ord("x"))
        self.assertEqual(non_nul.solver.eval(result), BASE + 1)

    def test_long_concrete_string(self):
        state = make_state()
        put(state, BASE, b"a" * 150 + b"x\x00")
        put(state, ACCEPT, b"a\x00")
        self.assertEqual(state.solver.eval(call("strspn", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))), 150)
        put(state, ACCEPT, b"x\x00")
        self.assertEqual(state.solver.eval(call("strcspn", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))), 150)
        self.assertEqual(
            state.solver.eval(call("strpbrk", state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))), BASE + 150
        )
        self.assertEqual(
            state.solver.eval(call("strrchr", state, claripy.BVV(BASE, 64), claripy.BVV(ord("x"), 32))), BASE + 150
        )

    def test_symbolic_accept_set(self):
        state = make_state()
        put(state, BASE, b"abc\x00")
        state.memory.store(ACCEPT, claripy.BVS("a0", 8))
        put(state, ACCEPT + 1, b"\x00")
        for name in ("strspn", "strcspn", "strpbrk"):
            result = call(name, state, claripy.BVV(BASE, 64), claripy.BVV(ACCEPT, 64))
            self.assertTrue(state.solver.symbolic(result), name)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.procedures.posix"  # pylint:disable=redefined-builtin

import unittest

from angr import SIM_LIBRARIES, SimState, claripy
from tests.common import minimal_project

BYTE_ORDER_PROCEDURES = ("ntohs", "ntohl", "htons", "htonl")


def make_state():
    return SimState(project=minimal_project("AMD64"), mode="symbolic")


def call(name, state, *args):
    proc = SIM_LIBRARIES["libc.so.6"][0].get(name, state.project.arch)
    return proc.execute(state, arguments=list(args)).ret_expr


class TestByteOrder(unittest.TestCase):
    def test_procedures_are_implemented(self):
        """ntohs/ntohl used to fall back to ReturnUnconstrained stubs; they must not anymore."""
        lib = SIM_LIBRARIES["libc.so.6"][0]
        arch = minimal_project("AMD64").arch
        for name in BYTE_ORDER_PROCEDURES:
            proc = lib.get(name, arch)
            self.assertFalse(getattr(proc, "is_stub", False), f"{name} is still a stub SimProcedure")

    def test_concrete_values(self):
        for name, value, width, expected in (
            ("ntohs", 0x1234, 16, 0x3412),
            ("htons", 0x1234, 16, 0x3412),
            ("ntohl", 0x12345678, 32, 0x78563412),
            ("htonl", 0x12345678, 32, 0x78563412),
        ):
            state = make_state()
            result = call(name, state, claripy.BVV(value, width))
            self.assertFalse(state.solver.symbolic(result), f"{name}({value:#x}) produced a symbolic value")
            self.assertEqual(state.solver.eval(result) & ((1 << width) - 1), expected, name)

    def test_symbolic_argument(self):
        """A symbolic argument must be byte swapped, not replaced by a fresh unconstrained value."""
        for name, width, value, expected in (
            ("ntohs", 16, 0x1234, 0x3412),
            ("ntohl", 32, 0x12345678, 0x78563412),
        ):
            state = make_state()
            sym = claripy.BVS("x", width)
            result = call(name, state, sym)
            state.solver.add(sym == value)
            self.assertNotIn("unconstrained", str(result), name)
            self.assertEqual(state.solver.eval(result) & ((1 << width) - 1), expected, name)


if __name__ == "__main__":
    unittest.main()

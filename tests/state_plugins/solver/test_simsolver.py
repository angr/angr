#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

import struct
import unittest
from unittest import mock

import angr
from angr import claripy
from tests.common import minimal_project


class TestSolverEvalCasting(unittest.TestCase):
    """
    Basic test cases of SimSolver::eval's `cast_to` function.
    """

    def test_eval_cast_bvv_to_bytes(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        assert s.solver.eval(claripy.BVV(0, 0), cast_to=bytes) == b""
        assert s.solver.eval(claripy.BVV(0, 8), cast_to=bytes) == b"\x00"
        assert s.solver.eval(claripy.BVV(0x12345678, 32), cast_to=bytes) == b"\x12\x34\x56\x78"

    def test_eval_cast_bvv_to_bytes__non_8bit_length_multiple(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        for nbits in [1, 2, 7]:
            with self.subTest(nbits=nbits), self.assertRaises(ValueError):
                s.solver.eval(claripy.BVV(0, nbits), cast_to=bytes)

    def test_eval_cast_fpv_to_bytes(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        value = 1.23456
        fpv = claripy.FPV(value, claripy.FSORT_FLOAT)
        assert s.solver.eval(fpv, cast_to=bytes) == struct.pack(">f", value)
        fpv = claripy.FPV(value, claripy.FSORT_DOUBLE)
        assert s.solver.eval(fpv, cast_to=bytes) == struct.pack(">d", value)

    def test_eval_cast_fpv_to_int(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        value = 1.23456
        fpv = claripy.FPV(value, claripy.FSORT_FLOAT)
        assert s.solver.eval(fpv, cast_to=int) == int.from_bytes(struct.pack(">f", value), "big")
        fpv = claripy.FPV(value, claripy.FSORT_DOUBLE)
        assert s.solver.eval(fpv, cast_to=int) == int.from_bytes(struct.pack(">d", value), "big")

    def test_eval_cast_bool_to_bytes(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        assert s.solver.eval(claripy.BoolV(False), cast_to=bytes) == b"\x00"
        assert s.solver.eval(claripy.BoolV(True), cast_to=bytes) == b"\x01"

    def test_eval_cast_bool_to_int(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        assert s.solver.eval(claripy.BoolV(False), cast_to=int) == 0
        assert s.solver.eval(claripy.BoolV(True), cast_to=int) == 1


class TestSolverEvalConcreteShortcut(unittest.TestCase):
    """
    The eval* family short-circuits values that are already concrete Python primitives.
    """

    def test_eval_python_primitives(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        for value in [7, True, 1.5, "abc"]:
            with self.subTest(value=value):
                assert s.solver.eval(value) == value
                assert s.solver.eval_one(value) == value
                assert s.solver.eval_upto(value, 2) == [value]

    def test_eval_string_ast(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        assert s.solver.eval(claripy.StringV("abc")) == "abc"
        assert s.solver.eval_upto(claripy.StringV("abc"), 2) == ["abc"]


class TestSolverErrors(unittest.TestCase):
    """Solver interrupts must remain distinguishable from unsat and other errors."""

    def test_interrupt_preserved(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        for method, args in (("satisfiable", ()), ("eval", (claripy.BVS("x", 8),))):
            error = claripy.ClaripySolverInterruptError("timeout")
            with self.subTest(method=method), mock.patch.object(claripy.Solver, method, side_effect=error):
                with self.assertRaises(claripy.ClaripySolverInterruptError) as caught:
                    getattr(s.solver, method)(*args)
                assert caught.exception is error

    def test_error_conversion(self):
        s = angr.SimState(project=minimal_project("AMD64"), mode="symbolic")
        for error_type, expected in (
            (claripy.UnsatError, angr.errors.SimUnsatError),
            (claripy.ClaripyError, angr.errors.SimSolverModeError),
        ):
            error = error_type("solver error")
            with self.subTest(error=error_type), mock.patch.object(claripy.Solver, "satisfiable", side_effect=error):
                with self.assertRaises(expected) as caught:
                    s.solver.satisfiable()
                assert caught.exception.__cause__ is error

    def test_interrupted_successors(self):
        project = angr.load_shellcode(b"\xff\xe0", arch="amd64")
        for lazy, method in ((False, "satisfiable"), (True, "eval")):
            with self.subTest(lazy=lazy):
                state = project.factory.blank_state(add_options={angr.options.LAZY_SOLVES} if lazy else set())
                state.regs.rax = claripy.BVS("target", 64)
                state.solver.add(state.regs.rax == 0x10)
                simgr = project.factory.simgr(state, save_unsat=True)
                error = claripy.ClaripySolverInterruptError("timeout")
                with mock.patch.object(claripy.Solver, method, side_effect=error):
                    simgr.step()
                assert simgr.stashes.get("interrupted", []) == [state]
                assert not simgr.errored
                assert not simgr.active
                assert not simgr.unsat
                assert not simgr.pruned
                simgr.move(from_stash="interrupted", to_stash="active").step()
                assert [s.addr for s in simgr.active] == [0x10]


if __name__ == "__main__":
    unittest.main()

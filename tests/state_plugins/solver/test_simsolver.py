#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

import struct
import unittest

import claripy

import angr


class TestSolverEvalCasting(unittest.TestCase):
    """
    Basic test cases of SimSolver::eval's `cast_to` function.
    """

    def test_eval_cast_bvv_to_bytes(self):
        s = angr.SimState(arch="AMD64", mode="symbolic")
        assert s.solver.eval(claripy.BVV(0, 0), cast_to=bytes) == b""
        assert s.solver.eval(claripy.BVV(0, 8), cast_to=bytes) == b"\x00"
        assert s.solver.eval(claripy.BVV(0x12345678, 32), cast_to=bytes) == b"\x12\x34\x56\x78"

    def test_eval_cast_bvv_to_bytes__non_8bit_length_multiple(self):
        s = angr.SimState(arch="AMD64", mode="symbolic")
        for nbits in [1, 2, 7]:
            with self.subTest(nbits=nbits), self.assertRaises(ValueError):
                s.solver.eval(claripy.BVV(0, nbits), cast_to=bytes)

    def test_eval_cast_fpv_to_bytes(self):
        s = angr.SimState(arch="AMD64", mode="symbolic")
        value = 1.23456
        fpv = claripy.FPV(value, claripy.FSORT_FLOAT)
        assert s.solver.eval(fpv, cast_to=bytes) == struct.pack(">f", value)
        fpv = claripy.FPV(value, claripy.FSORT_DOUBLE)
        assert s.solver.eval(fpv, cast_to=bytes) == struct.pack(">d", value)

    def test_eval_cast_fpv_to_int(self):
        s = angr.SimState(arch="AMD64", mode="symbolic")
        value = 1.23456
        fpv = claripy.FPV(value, claripy.FSORT_FLOAT)
        assert s.solver.eval(fpv, cast_to=int) == int.from_bytes(struct.pack(">f", value), "big")
        fpv = claripy.FPV(value, claripy.FSORT_DOUBLE)
        assert s.solver.eval(fpv, cast_to=int) == int.from_bytes(struct.pack(">d", value), "big")

    def test_eval_cast_bool_to_bytes(self):
        s = angr.SimState(arch="AMD64", mode="symbolic")
        assert s.solver.eval(claripy.BoolV(False), cast_to=bytes) == b"\x00"
        assert s.solver.eval(claripy.BoolV(True), cast_to=bytes) == b"\x01"

    def test_eval_cast_bool_to_int(self):
        s = angr.SimState(arch="AMD64", mode="symbolic")
        assert s.solver.eval(claripy.BoolV(False), cast_to=int) == 0
        assert s.solver.eval(claripy.BoolV(True), cast_to=int) == 1


if __name__ == "__main__":
    unittest.main()

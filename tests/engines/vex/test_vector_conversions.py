# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import struct
from unittest import TestCase, main

import angr
from angr import claripy
from angr.engines.vex.claripy.irop import vexop_to_simop

binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..", "binaries", "tests")

# lanes: 1.0, 2.0, 3.0, -4.0
FLOATS = claripy.BVV(0x3F800000_40000000_40400000_C0800000, 128)
# lanes: 1, 2, 3, -4
INTS = claripy.BVV(0x00000001_00000002_00000003_FFFFFFFC, 128)
RM_TOWARDS_ZERO = claripy.BVV(3, 32)


class TestVectorConversions(TestCase):
    def test_fp_to_int_lanes_keep_their_sign(self):
        # the S of Iop_F32toI32Sx4 is the lane signedness; -4.0 must not saturate to 0
        r = vexop_to_simop("Iop_F32toI32Sx4").calculate(RM_TOWARDS_ZERO, FLOATS)
        assert r.concrete_value == 0x00000001_00000002_00000003_FFFFFFFC

        r = vexop_to_simop("Iop_F32toI32Sx4_RZ").calculate(FLOATS)
        assert r.concrete_value == 0x00000001_00000002_00000003_FFFFFFFC

        r = vexop_to_simop("Iop_F32toI32Ux4_RZ").calculate(FLOATS)
        assert r.concrete_value == 0x00000001_00000002_00000003_00000000

    def test_int_to_fp_is_lane_wise(self):
        r = vexop_to_simop("Iop_I32StoF32x4").calculate(RM_TOWARDS_ZERO, INTS)
        assert r.concrete_value == FLOATS.concrete_value

        # the deprecated forms carry no rounding-mode operand
        r = vexop_to_simop("Iop_I32StoF32x4_DEP").calculate(INTS)
        assert r.concrete_value == FLOATS.concrete_value
        r = vexop_to_simop("Iop_I32UtoF32x4_DEP").calculate(INTS)
        assert r.concrete_value == 0x3F800000_40000000_40400000_4F800000  # 4294967292.0f

    def test_scalar_fp_to_int_unchanged(self):
        r = vexop_to_simop("Iop_F64toI32S").calculate(RM_TOWARDS_ZERO, claripy.BVV(0xC010000000000000, 64))
        assert r.concrete_value == 0xFFFFFFFC
        r = vexop_to_simop("Iop_F64toI32U").calculate(RM_TOWARDS_ZERO, claripy.BVV(0x4010000000000000, 64))
        assert r.concrete_value == 4


class TestVectorConversionBinaries(TestCase):
    """
    Symbolically execute the conversion routines of binaries/tests_src/vector_conversions*.c: each takes an input
    buffer and writes four converted lanes to an output buffer.
    """

    IN_ADDR = 0x1000000
    OUT_ADDR = 0x1001000

    @staticmethod
    def _run(proj: angr.Project, name: str, prototype: str, inbuf: bytes) -> bytes:
        state = proj.factory.blank_state()
        state.memory.store(TestVectorConversionBinaries.IN_ADDR, inbuf)
        state.memory.store(TestVectorConversionBinaries.OUT_ADDR, b"\0" * 16)
        func = proj.factory.callable(proj.kb.functions[name].addr, base_state=state, prototype=prototype)
        func(TestVectorConversionBinaries.IN_ADDR, TestVectorConversionBinaries.OUT_ADDR)
        assert func.result_state is not None
        out = func.result_state.memory.load(TestVectorConversionBinaries.OUT_ADDR, 16)
        assert out.concrete, f"{name} produced a symbolic result: {out}"
        return out.concrete_value.to_bytes(16, "big")

    def _project(self, arch: str) -> angr.Project:
        proj = angr.Project(os.path.join(binaries_base, arch, "vector_conversions"), auto_load_libs=False)
        proj.analyses.CFG(normalize=True)
        return proj

    def test_amd64_sse(self):
        proj = self._project("x86_64")
        f2i = "void f(float *in, int *out)"
        i2f = "void f(int *in, float *out)"

        # cvttps2dq truncates towards zero whatever MXCSR says
        out = self._run(proj, "truncate_to_ints", f2i, struct.pack("<4f", 1.5, -2.5, 3.75, 100.0))
        assert struct.unpack("<4i", out) == (1, -2, 3, 100)
        # cvtps2dq rounds per MXCSR; integral inputs make every rounding mode agree
        out = self._run(proj, "round_to_ints", f2i, struct.pack("<4f", 1.0, -2.0, 3.0, 100.0))
        assert struct.unpack("<4i", out) == (1, -2, 3, 100)
        # cvtdq2ps
        out = self._run(proj, "ints_to_floats", i2f, struct.pack("<4i", 1, -2, 3, 100))
        assert struct.unpack("<4f", out) == (1.0, -2.0, 3.0, 100.0)

    def test_armhf_neon(self):
        proj = self._project("armhf")

        # vcvt.s32.f32 / vcvt.u32.f32 truncate towards zero
        out = self._run(
            proj, "truncate_to_ints", "void f(float *in, int *out)", struct.pack("<4f", 1.5, -2.5, 3.75, 100.0)
        )
        assert struct.unpack("<4i", out) == (1, -2, 3, 100)
        out = self._run(
            proj, "truncate_to_uints", "void f(float *in, unsigned int *out)", struct.pack("<4f", 1.5, 2.5, 3.75, 100.0)
        )
        assert struct.unpack("<4I", out) == (1, 2, 3, 100)
        # vcvt.f32.s32 / vcvt.f32.u32 carry no rounding mode (the deprecated _DEP ops)
        out = self._run(proj, "ints_to_floats", "void f(int *in, float *out)", struct.pack("<4i", 1, -2, 3, 100))
        assert struct.unpack("<4f", out) == (1.0, -2.0, 3.0, 100.0)
        out = self._run(
            proj, "uints_to_floats", "void f(unsigned int *in, float *out)", struct.pack("<4I", 1, 2, 3, 0xFFFFFFFC)
        )
        assert struct.unpack("<4f", out) == (1.0, 2.0, 3.0, 4294967296.0)


if __name__ == "__main__":
    main()

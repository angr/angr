# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

from unittest import TestCase, main

from angr import claripy
from angr.engines.vex.claripy.irop import vexop_to_simop

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


if __name__ == "__main__":
    main()

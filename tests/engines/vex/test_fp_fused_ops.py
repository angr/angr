# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import math
import struct
from unittest import TestCase, main

from angr import claripy
from angr.engines.vex.claripy.irop import vexop_to_simop

RNE = claripy.BVV(0, 32)
RTP = claripy.BVV(2, 32)
RZ = claripy.BVV(3, 32)


def _f64(value: float):
    return claripy.FPV(value, claripy.FSORT_DOUBLE)


def _f32x4(*lanes: float):
    """A V128 whose lane 0 is the first value."""
    return claripy.BVV(int.from_bytes(struct.pack("<4f", *lanes), "little"), 128)


def _lanes(v128) -> tuple[float, ...]:
    return struct.unpack("<4f", v128.concrete_value.to_bytes(16, "little"))


class TestFusedOps(TestCase):
    def test_madd_rounds_once(self):
        # (1 + 2^-52) * (1 - 2^-52) - 1 is -2^-104 exactly; rounding the product first gives 0
        a, b = _f64(1.0 + 2**-52), _f64(1.0 - 2**-52)
        result = vexop_to_simop("Iop_MAddF64").calculate(RNE, a, b, _f64(-1.0))
        assert result.concrete_value == -(2**-104)

    def test_msub_rounds_once(self):
        a, b = _f64(1.0 + 2**-52), _f64(1.0 - 2**-52)
        result = vexop_to_simop("Iop_MSubF64").calculate(RNE, a, b, _f64(1.0))
        assert result.concrete_value == -(2**-104)

    def test_madd_honors_a_directed_mode(self):
        # 1 * 1 + 2^-60 is 1 under nearest-even but the next double up toward +inf
        result = vexop_to_simop("Iop_MAddF64").calculate(RTP, _f64(1.0), _f64(1.0), _f64(2**-60))
        assert claripy.Solver().eval(result, 2) == [1.0 + 2**-52]

    def test_round_to_integral_by_mode(self):
        round_f64 = vexop_to_simop("Iop_RoundF64toInt")
        assert round_f64.calculate(RNE, _f64(2.5)).concrete_value == 2.0
        assert round_f64.calculate(RZ, _f64(-2.5)).concrete_value == -2.0
        assert round_f64.calculate(RNE, _f64(1e300)).concrete_value == 1e300
        assert math.isnan(round_f64.calculate(RNE, _f64(math.nan)).concrete_value)
        assert math.copysign(1.0, round_f64.calculate(RNE, _f64(-0.5)).concrete_value) == -1.0

    def test_round_f32x4_stays_float(self):
        result = vexop_to_simop("Iop_RoundF32x4_RN").calculate(_f32x4(1.5, -2.5, 3.75, 100.0))
        assert _lanes(result) == (2.0, -2.0, 4.0, 100.0)

    def test_scalar_lane_min_keeps_x86_semantics(self):
        # MINSS returns the second operand when either is NaN, which fp.min would not
        result = vexop_to_simop("Iop_Min32F0x4").calculate(_f32x4(1.0, 0, 0, 0), _f32x4(math.nan, 0, 0, 0))
        assert math.isnan(_lanes(result)[0])


if __name__ == "__main__":
    main()

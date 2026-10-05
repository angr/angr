# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
from unittest import TestCase, main

import angr
from angr import claripy, sim_options
from angr.engines.vex.claripy.irop import translate_rm, vexop_to_simop
from angr.engines.vex.heavy.resilience import HeavyResilienceMixin
from angr.errors import SimError, UnsupportedIROpError

binaries_base = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..", "binaries", "tests")

TWO = claripy.BVV(0x4000000000000000, 64)

# vsubpd zmm3 {k1} {z}, zmm18, zmm3, {rz-sae}: EVEX embedded rounding, which the AMD64 lifter
# gives a rounding-mode operand of 0x08 | EVEX.L'L
EVEX_STATIC_ROUNDING = ("x86_64", "windows", "1309c8993adeb587e629615eb6838a280f0a1faa6ac74fdb11b80d5bddc1c94f")
EVEX_STATIC_ROUNDING_ADDR = 0x140135B71


class TestRoundingModes(TestCase):
    def test_every_mode_libvex_declares_is_answered(self):
        # IRRoundingMode runs 0..8; claripy has the five IEEE modes, so 5, 6, 7 and the invalid 8 have no counterpart
        assert translate_rm(claripy.BVV(0, 32)) == claripy.fp.RM.RM_NearestTiesEven
        assert translate_rm(claripy.BVV(1, 32)) == claripy.fp.RM.RM_TowardsNegativeInf
        assert translate_rm(claripy.BVV(2, 32)) == claripy.fp.RM.RM_TowardsPositiveInf
        assert translate_rm(claripy.BVV(3, 32)) == claripy.fp.RM.RM_TowardsZero
        assert translate_rm(claripy.BVV(4, 32)) == claripy.fp.RM.RM_NearestTiesAwayFromZero
        for mode in (5, 6, 7, 8):
            with self.assertRaises(UnsupportedIROpError):
                translate_rm(claripy.BVV(mode, 32))

    def test_symbolic_mode_still_falls_back(self):
        assert translate_rm(claripy.BVS("rm", 32)) == claripy.fp.RM.default()

    def test_ties_away_from_zero_is_executable(self):
        # FCVTAS and FCVTAU lift to a conversion with mode 4
        assert vexop_to_simop("Iop_F64toI32S").calculate(claripy.BVV(4, 32), TWO).concrete_value == 2

    def test_an_unmodelled_mode_leaves_the_op_as_a_simerror(self):
        with self.assertRaises(SimError):
            vexop_to_simop("Iop_F64toI32S").calculate(claripy.BVV(9, 32), TWO)

    def test_an_evex_static_rounding_instruction_steps(self):
        proj = angr.Project(os.path.join(binaries_base, *EVEX_STATIC_ROUNDING), auto_load_libs=False)
        state = proj.factory.blank_state(
            addr=EVEX_STATIC_ROUNDING_ADDR, add_options={sim_options.BYPASS_UNSUPPORTED_IROP}
        )
        assert len(proj.factory.successors(state, num_inst=1).successors) == 1

    def test_the_concretizers_answer_every_mode_without_escaping(self):
        proj = angr.Project(os.path.join(binaries_base, *EVEX_STATIC_ROUNDING), auto_load_libs=False)
        state = proj.factory.blank_state(
            addr=EVEX_STATIC_ROUNDING_ADDR,
            add_options={sim_options.BYPASS_UNSUPPORTED_IROP, sim_options.UNSUPPORTED_FORCE_CONCRETIZE},
        )
        engine = proj.factory.default_engine
        assert isinstance(engine, HeavyResilienceMixin)
        engine.state = state
        # 4 reaches the concretizer, 5 does not; neither may leave this handler
        for mode in (0, 3, 4, 5):
            args = [claripy.BVV(mode, 32), TWO]
            got = engine._check_unsupported_op("Iop_F64toI64S", args)  # pylint:disable=protected-access
            assert isinstance(got, claripy.ast.BV)
            assert got.size() == 64


if __name__ == "__main__":
    main()

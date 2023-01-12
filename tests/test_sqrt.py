# pylint:disable=missing-class-docstring,no-self-use
import math
from unittest import TestCase, main

import claripy
import angr


class TestSqrt(TestCase):
    def test_sqrt_symbolic(self):
        ins_bytes = b"\xf3\x0f\x51\xc9"  # sqrtss  xmm1, xmm1
        proj = angr.load_shellcode(ins_bytes, "amd64", load_address=0)
        state = proj.factory.blank_state(addr=0)

        xmm1 = claripy.FPS("v", claripy.FSORT_FLOAT)
        state.regs.xmm1 = xmm1.to_bv()
        simgr = proj.factory.simgr(state)

        simgr.step(num_inst=1)
        assert len(simgr.active) == 1

        final = simgr.active[0]
        result = final.regs.xmm1[31:0].raw_to_fp()

        a = int(final.solver.eval(xmm1, extra_constraints=(result == 2.0,)))
        assert a == 4
        b = int(final.solver.eval(xmm1, extra_constraints=(result == 4.0,)))
        assert b == 16

    def test_sqrt_concrete(self):
        ins_bytes = b"\xf3\x0f\x51\xc9"  # sqrtss  xmm1, xmm1
        proj = angr.load_shellcode(ins_bytes, "amd64", load_address=0)
        state = proj.factory.blank_state(addr=0)

        xmm1 = claripy.FPV(200000, claripy.FSORT_FLOAT)
        state.regs.xmm1 = xmm1.to_bv()
        simgr = proj.factory.simgr(state)

        simgr.step(num_inst=1)
        assert len(simgr.active) == 1

        final = simgr.active[0]
        result = final.regs.xmm1[31:0].raw_to_fp()

        a = final.solver.eval(result)
        assert abs(a - math.sqrt(200000)) < 0.001

    def test_sqrt_concrete_eager_evaluation(self):
        a = claripy.FPV(2.0, claripy.FSORT_DOUBLE)
        b = claripy.fpSqrt(a)
        assert abs(b._model_concrete.value - 1.414) < 0.001


if __name__ == "__main__":
    main()

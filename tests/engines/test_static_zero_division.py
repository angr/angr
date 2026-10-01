# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

from unittest import TestCase, main

import angr


class TestStaticZeroDivision(TestCase):
    def test_static_mode_division_by_zero_is_bypassed(self):
        # xor edx, edx; mov eax, 1; div ecx; ret
        proj = angr.load_shellcode(b"\x31\xd2\xb8\x01\x00\x00\x00\xf7\xf1\xc3", "AMD64", load_address=0x1000)
        state = proj.factory.blank_state(addr=0x1000, mode="static")
        state.regs.rcx = 0
        # used to raise ValueError from TrackActionsMixin when the zero-division fallback retried the op
        succ = proj.factory.successors(state)
        assert succ.all_successors
        # the divisor is patched to 1, so eax = 1 / 1
        assert succ.all_successors[0].solver.eval_one(succ.all_successors[0].regs.eax) == 1


if __name__ == "__main__":
    main()

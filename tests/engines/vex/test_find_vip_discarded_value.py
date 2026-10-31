#!/usr/bin/env python3
# pylint:disable=missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.engines.vex"  # pylint:disable=redefined-builtin

import unittest

import archinfo
import pyvex

from angr.engines.vex.light.light import vip_value_discarded

INC_RDI = b"\x48\xff\xc7"
XOR_R8_RDI = b"\x49\x31\xf8"
SUB_R9_8 = b"\x49\x83\xe9\x08"
MOV_R9PTR_RDI = b"\x49\x89\x39"
PUSH_RDI = b"\x57"
MOV_RSI_RDI = b"\x48\x89\xfe"
MOVZX_EAX_RDIPTR = b"\x0f\xb6\x07"
FETCH_R11 = b"\x41\x8b\x3b" + b"\x49\x83\xc3\x04"  # mov edi, [r11]; add r11, 4
TAIL = b"\x44\x31\xc7" + b"\xff\xe0"  # xor edi, r8d; jmp rax


class TestFindVipDiscardedValue(unittest.TestCase):
    """A register value that the rest of the block drops without dereferencing it is not the VIP."""

    arch = archinfo.ArchAMD64()

    def _discarded(self, code, reg):
        irsb = pyvex.lift(code, 0x1000, self.arch, opt_level=1)
        # probe after the first instruction (inc rdi), like find_vip's mid-block probe
        probe = [i for i, s in enumerate(irsb.statements) if isinstance(s, pyvex.stmt.IMark)][1]
        return vip_value_discarded(self.arch, irsb, probe, self.arch.registers[reg])

    def test_operand_pushed_to_vstack_is_discarded(self):
        # netsky1_vmp 0x1400cb976: rdi steps by one, is pushed onto the virtual stack, then reused
        code = INC_RDI + XOR_R8_RDI + SUB_R9_8 + MOV_R9PTR_RDI + FETCH_R11 + TAIL
        assert self._discarded(code, "rdi")
        assert not self._discarded(code, "r11")

    def test_dereferenced_value_is_kept(self):
        code = INC_RDI + MOVZX_EAX_RDIPTR + FETCH_R11 + TAIL
        assert not self._discarded(code, "rdi")

    def test_value_copied_to_another_register_is_kept(self):
        code = INC_RDI + MOV_RSI_RDI + FETCH_R11 + TAIL
        assert not self._discarded(code, "rdi")

    def test_value_spilled_to_native_stack_is_kept(self):
        code = INC_RDI + PUSH_RDI + FETCH_R11 + TAIL
        assert not self._discarded(code, "rdi")

    def test_value_live_at_block_end_is_kept(self):
        code = INC_RDI + XOR_R8_RDI + b"\xff\xe0"
        assert not self._discarded(code, "rdi")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import claripy
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSprintf(unittest.TestCase):
    def test_sprintf(self):
        p = angr.Project(
            os.path.join(test_location, "x86_64", "sprintf_test"),
            auto_load_libs=False,
        )
        a = p.factory.simulation_manager().explore(find=0x4005C0)
        state = a.found[0]

        str1 = state.solver.eval(state.memory.load(0x600AD0, 13), cast_to=bytes)
        assert str1 == b"Immediate: 3\n"

        str2 = state.solver.eval(state.memory.load(0x600A70, 7), cast_to=bytes)
        assert str2 == b"Int: 3\n"

        str3 = state.solver.eval(state.memory.load(0x600AB0, 8), cast_to=bytes)
        assert str3 == b"Char: c\n"

        str4 = state.solver.eval(state.memory.load(0x600A50, 14), cast_to=bytes)
        assert str4 == b"Uninit int: 0\n"

        str5 = state.solver.eval(state.memory.load(0x600A90, 24), cast_to=bytes)
        assert str5 == b"Str on stack: A string.\n"

        str6 = state.solver.eval(state.memory.load(0x600A30, 21), cast_to=bytes)
        assert str6 == b"Global str: GLOB_STR\n"

    def _sprintf(self, fmt, value):
        p = angr.load_shellcode(b"\x90", arch="amd64")
        state = p.factory.blank_state()
        fmt_addr, out = 0x200000, 0x300000
        state.memory.store(fmt_addr, fmt + b"\x00")
        sprintf = angr.SIM_PROCEDURES["libc"]["sprintf"]()
        sprintf.execute(state, arguments=[out, fmt_addr, claripy.BVV(value, 64)])
        return state.solver.eval(state.memory.load(out, 32), cast_to=bytes).split(b"\x00")[0]

    def test_sprintf_hex_octal(self):
        # f"{c_val:x}"[2:] used to drop the first two digits (0xff -> "")
        assert self._sprintf(b"%x", 0xFF) == b"ff"
        assert self._sprintf(b"%x", 0xDEAD) == b"dead"
        assert self._sprintf(b"%X", 0xFF) == b"FF"
        assert self._sprintf(b"%08X", 0xAB) == b"000000AB"
        assert self._sprintf(b"%lX", 0xAB) == b"AB"
        assert self._sprintf(b"%o", 0o755) == b"755"

    def test_sprintf_unsigned_conversions(self):
        # unsigned conversions must not be printed as negative numbers
        assert self._sprintf(b"%x", 0xFFFFFFFF) == b"ffffffff"
        assert self._sprintf(b"%x", 0x80000000) == b"80000000"
        assert self._sprintf(b"%hhX", 0xAB) == b"AB"
        assert self._sprintf(b"%u", 0xFFFFFFFF) == b"4294967295"
        assert self._sprintf(b"%o", 0xFFFFFFFF) == b"37777777777"
        assert self._sprintf(b"%d", 0xFFFFFFFF) == b"-1"

    def test_sprintf_pointer(self):
        assert self._sprintf(b"%p", 0x401000) == b"0x401000"
        assert self._sprintf(b"%p", 0xFFFF800000000000) == b"0xffff800000000000"
        assert self._sprintf(b"%p", 0) == b"(nil)"

    def test_sprintf_char_above_0x7f(self):
        assert self._sprintf(b"%c", 0xC1) == b"\xc1"

    def test_sprintf_zero_padded_negative(self):
        assert self._sprintf(b"%05d", 0xFFFFFFFF) == b"-0001"
        assert self._sprintf(b"%05d", 42) == b"00042"

    def test_sprintf_ptrdiff_unsigned(self):
        assert self._sprintf(b"%tu", 0xFFFFFFFFFFFFFFFF) == b"18446744073709551615"
        assert self._sprintf(b"%td", 0xFFFFFFFFFFFFFFFF) == b"-1"


if __name__ == "__main__":
    unittest.main()

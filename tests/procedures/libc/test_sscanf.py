#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSscanf(unittest.TestCase):
    def test_sscanf_p_spec(self):
        # Regression for the scanf interpret() path: %p reads a hex pointer and
        # must parse like %x (base 16) instead of raising SimProcedureError.
        # Binary-free: drive the sscanf SimProcedure directly.
        p = angr.load_shellcode(b"\x90", arch="amd64")
        state = p.factory.blank_state()
        src, fmt, out = 0x100000, 0x200000, 0x300000
        state.memory.store(src, b"0xdeadbeef\x00")
        state.memory.store(fmt, b"%p\x00")

        sscanf = angr.SIM_PROCEDURES["libc"]["sscanf"]()
        sscanf.execute(state, arguments=[src, fmt, out])

        val = state.solver.eval(state.memory.load(out, 8, endness=p.arch.memory_endness))
        assert val == 0xDEADBEEF
        assert len(state.solver.constraints) == 0 or state.satisfiable()

    def test_sscanf_o_spec(self):
        # Regression for the scanf interpret() path: %o reads an octal integer and
        # must parse like the scanf-inject path (base 8) instead of raising
        # SimProcedureError. %o was recognized everywhere except interpret().
        # Binary-free: drive the sscanf SimProcedure directly. Mirrors the %p fix.
        p = angr.load_shellcode(b"\x90", arch="amd64")
        state = p.factory.blank_state()
        src, fmt, out = 0x100000, 0x200000, 0x300000
        state.memory.store(src, b"755\x00")
        state.memory.store(fmt, b"%o\x00")

        sscanf = angr.SIM_PROCEDURES["libc"]["sscanf"]()
        sscanf.execute(state, arguments=[src, fmt, out])

        val = state.solver.eval(state.memory.load(out, 4, endness=p.arch.memory_endness))
        assert val == 0o755
        assert len(state.solver.constraints) == 0 or state.satisfiable()

    def test_sscanf_X_spec(self):
        # Regression for the scanf interpret() path: %X (uppercase hex) is
        # recognized by _match_spec (basic_spec/int_sign) but was unhandled at
        # the dispatch sites — the non-SimPackets interpret() path raised
        # SimProcedureError and the SimPackets path mis-parsed it as base 10.
        # Must parse like %x (base 16). Binary-free.
        p = angr.load_shellcode(b"\x90", arch="amd64")
        state = p.factory.blank_state()
        src, fmt, out = 0x100000, 0x200000, 0x300000
        state.memory.store(src, b"DEADBEEF\x00")
        state.memory.store(fmt, b"%X\x00")

        sscanf = angr.SIM_PROCEDURES["libc"]["sscanf"]()
        sscanf.execute(state, arguments=[src, fmt, out])

        val = state.solver.eval(state.memory.load(out, 4, endness=p.arch.memory_endness))
        assert val == 0xDEADBEEF
        assert len(state.solver.constraints) == 0 or state.satisfiable()

    def test_scanf_p_spec_simpackets(self):
        # Regression for the OTHER interpret() dispatch site: the SimPackets
        # (stdin packet stream) path constrains input digits in base x/o/else
        # but lacked %p, so a scanf("%p") from stdin parsed the pointer as
        # base 10 instead of base 16. The addr-based path already handled %p;
        # this covers the SimPackets path. Binary-free: feed concrete stdin
        # "10" with %2p -> base 16 yields 0x10 (16), base 10 would yield 10.
        from angr import claripy

        p = angr.load_shellcode(b"\x90", arch="amd64")
        stdin = angr.SimPackets(name="stdin", content=[b"10"], writable=False)
        state = p.factory.entry_state(stdin=stdin)
        fmt, out = 0x200000, 0x300000
        state.memory.store(fmt, b"%2p\x00")

        scanf = angr.SIM_PROCEDURES["libc"]["scanf"]()
        scanf.execute(state, arguments=[fmt, out])

        val = state.solver.eval(claripy.Extract(63, 0, state.memory.load(out, 8, endness=p.arch.memory_endness)))
        assert val == 0x10, hex(val)
        assert state.satisfiable()

    def test_sprintf_hex_octal_no_digit_strip(self):
        # Regression for the printf replace() path: #5661 refactored
        # hex(c_val)[2:] -> f"{c_val:x}"[2:] (and the octal analog). hex()/oct()
        # carry a 2-char prefix that [2:] stripped, but the f-string forms have
        # no prefix, so [2:] silently dropped the first two significant digits
        # (0xFF -> ""). Also covers the new %X spec. Binary-free.
        from angr import claripy

        p = angr.load_shellcode(b"\x90", arch="amd64")
        fmt, out = 0x200000, 0x300000
        sprintf = angr.SIM_PROCEDURES["libc"]["sprintf"]()

        for spec, value, expected in [
            (b"%x\x00", 0xFF, b"ff"),
            (b"%X\x00", 0xFF, b"FF"),
            (b"%x\x00", 0xDEAD, b"dead"),
            (b"%o\x00", 0o755, b"755"),
        ]:
            state = p.factory.blank_state()
            state.memory.store(fmt, spec)
            sprintf.execute(state, arguments=[out, fmt, claripy.BVV(value, 64)])
            data = state.solver.eval(state.memory.load(out, len(expected) + 1), cast_to=bytes)
            assert data == expected + b"\x00", (spec, data)

    def test_sscanf(self):
        test_bin = os.path.join(test_location, "x86_64", "sscanf_test")
        b = angr.Project(test_bin, auto_load_libs=False)
        pg = b.factory.simulation_manager()
        # find the end of main
        expected_outputs = {
            b"0x worked\n",
            b"+0x worked\n",
            b"base +16 worked\n",
            b"base 16 worked\n",
            b"-0x worked\n",
            b"base -16 worked\n",
            b"base 16 length 2 worked\n",
            b"Nope x\n",
            b"base 8 worked\n",
            b"base +8 worked\n",
            b"base +10 worked\n",
            b"base 10 worked\n",
            b"base -8 worked\n",
            b"base -10 worked\n",
            b"Nope u\n",
            b"No switch\n",
        }
        pg.run()
        assert len(pg.deadended) == len(expected_outputs)
        assert {f.posix.dumps(1) for f in pg.deadended} == expected_outputs
        assert len(pg.active) == 0
        assert len(pg.errored) == 0

    def _sscanf(self, src, fmt, size):
        p = angr.load_shellcode(b"\x90", arch="amd64")
        state = p.factory.blank_state()
        src_addr, fmt_addr, out = 0x100000, 0x200000, 0x300000
        state.memory.store(src_addr, src + b"\x00")
        state.memory.store(fmt_addr, fmt + b"\x00")
        sscanf = angr.SIM_PROCEDURES["libc"]["sscanf"]()
        sscanf.execute(state, arguments=[src_addr, fmt_addr, out])
        return state.solver.eval(state.memory.load(out, size, endness=p.arch.memory_endness))

    def test_sscanf_pointer(self):
        # %p used to raise SimProcedureError in interpret()
        assert self._sscanf(b"0xdeadbeef", b"%p", 8) == 0xDEADBEEF

    def test_sscanf_octal(self):
        # %o used to raise SimProcedureError in interpret()
        assert self._sscanf(b"755", b"%o", 4) == 0o755
        # 8 is not an octal digit
        assert self._sscanf(b"78", b"%o", 4) == 7

    def test_sscanf_i_detects_base(self):
        assert self._sscanf(b"0x10", b"%i", 4) == 16
        assert self._sscanf(b"0X10", b"%i", 4) == 16
        assert self._sscanf(b"010", b"%i", 4) == 8
        assert self._sscanf(b"10", b"%i", 4) == 10


if __name__ == "__main__":
    unittest.main()

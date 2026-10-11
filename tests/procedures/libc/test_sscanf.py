#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSscanf(unittest.TestCase):
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

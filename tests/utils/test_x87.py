#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest

import archinfo
import pyvex

from angr.utils.x87 import X87Tracker


def _ftop_after(arch: archinfo.Arch, code: bytes) -> int | None:
    irsb = pyvex.lift(code, 0x1000, arch, opt_level=1)
    off, size = arch.registers["ftop"]
    tracker = X87Tracker(irsb, 0, off, size, (arch.registers["fpreg"][0], arch.registers["fptag"][0]))
    for stmt in irsb.statements:
        if not tracker.step(stmt):
            break
    return None if tracker.ftop is None else tracker.ftop % 8


class TestX87Tracker(unittest.TestCase):
    def test_push(self):
        # fld1; ret
        assert _ftop_after(archinfo.ArchX86(), b"\xd9\xe8\xc3") == 7

    def test_state_reinitialization_empties_stack(self):
        # fld1; <op> [eax]/fninit; ret
        for arch in (archinfo.ArchX86(), archinfo.ArchAMD64()):
            for op in (b"\xdd\x30", b"\xdb\xe3"):  # fnsave, fninit
                assert _ftop_after(arch, b"\xd9\xe8" + op + b"\xc3") == 0, (arch.name, op.hex())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.sim.exec_insn"  # pylint:disable=redefined-builtin

import itertools
import unittest

from angr.utils.bits import truncate_bits

from ...common import run_simple_unicorn_congruency_check


# pylint: disable=missing-class-docstring
class TestShl(unittest.TestCase):

    def test_shl(self):
        for reg, rbits in [("eax", 32), ("rax", 64)]:
            values = [
                0,
                1,
                truncate_bits(0x55555555_55555555, rbits),
                truncate_bits(0xAAAAAAAA_AAAAAAAA, rbits),
                truncate_bits(0xFFFFFFFF_FFFFFFFF, rbits),
                truncate_bits(0xFEDCBA98_87654321, rbits),
            ]
            shifts = [
                0,
                1,
                rbits // 2 - 1,
                rbits // 2,
                rbits - 1,
                rbits,
            ]
            for value, shift in itertools.product(values, shifts):
                asm = f"""\
                    mov {reg}, {value:#x}
                    shl {reg}, {shift:#x}
                    jmp .
                    """
                with self.subTest(asm=asm):
                    run_simple_unicorn_congruency_check(asm)


if __name__ == "__main__":
    unittest.main()

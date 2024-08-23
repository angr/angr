#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.sim.exec_insn"  # pylint:disable=redefined-builtin

import unittest

from ...common import run_simple_unicorn_congruency_check


# pylint: disable=missing-class-docstring
class TestImul(unittest.TestCase):

    def test_imul(self):
        values = [
            (0, 0),
            (0, 1),
            (0, -1),
            (1, 1),
            (1, -2),
            (0x3FFFFFFF, 2),
            (0x10000, 0x10000),  # +iv, +tv
            (0xFFFF, 0xFFFF),  # +iv, -tv
            (0x40000000, -4),  # -iv, +tv
            (0x3FE00000, -1024),  # -iv, -tv
        ]
        for f0, f1 in values:

            # 1-operand
            asm = f"""\
                mov eax, {f0:#x}
                mov edx, {f1:#x}
                imul edx
                jmp .
                """
            with self.subTest(asm=asm):
                run_simple_unicorn_congruency_check(asm)

            # 2-operand
            asm = f"""\
                mov eax, {f0:#x}
                mov edx, {f1:#x}
                imul eax, edx
                jmp .
                """
            with self.subTest(asm=asm):
                run_simple_unicorn_congruency_check(asm)


if __name__ == "__main__":
    unittest.main()

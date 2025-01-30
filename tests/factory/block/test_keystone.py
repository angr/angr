#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.factory.block"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import bin_location

# pylint: disable=missing-docstring,no-self-use


class TestKeyStone(unittest.TestCase):
    def _run_keystone(self, arch, insn_text):
        proj_arch = arch
        is_thumb = False
        if arch == "armel_thumb":
            is_thumb = True
            proj_arch = "armel"
        p = angr.Project(os.path.join(bin_location, "tests", proj_arch, "fauxware"), auto_load_libs=False)
        addr = p.loader.main_object.get_symbol("authenticate").rebased_addr

        sm = p.factory.simulation_manager()
        if arch in ["i386", "x86_64"]:
            sm.one_active.regs.eax = 3
        else:
            sm.one_active.regs.r1 = 3

        if is_thumb:
            addr |= 1
        insn_bytes = p.arch.asm(insn_text, addr=addr)
        block = p.factory.block(addr, insn_bytes=insn_bytes, thumb=is_thumb).vex

        assert block.instructions == 1

        sm.step(force_addr=addr, insn_text=insn_text, thumb=is_thumb)

        if arch in ["i386", "x86_64"]:
            assert sm.one_active.solver.eval(sm.one_active.regs.eax) == 0x12
        else:
            assert sm.one_active.solver.eval(sm.one_active.regs.r1) == 0x12

    def test_i386(self):
        self._run_keystone("i386", b"add eax, 0xf")

    def test_x86_64(self):
        self._run_keystone("x86_64", b"add rax, 0xf")

    def test_ppc(self):
        self._run_keystone("ppc", b"addi %r1, %r1, 0xf")

    def test_armel(self):
        self._run_keystone("armel", b"add r1, r1, 0xf")

    def test_armel_thumb(self):
        self._run_keystone("armel_thumb", b"add.w r1, r1, #0xf")

    def test_mips(self):
        self._run_keystone("mips", b"addi $1, $1, 0xf")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

import unittest

import archinfo

import angr
from angr.analyses.cfg import CFGBase


class TestNoopBlocks(unittest.TestCase):
    def test_x86_noop_blocks(self):
        # nop
        arch = archinfo.arch_from_id("x86")
        b = b"\x90\x90\x90\x90\x90\x90\x90\x90"
        p = angr.load_shellcode(b, arch, load_address=0x400000)
        block = p.factory.block(0x400000, opt_level=1, cross_insn_opt=False)
        assert CFGBase._is_noop_block(arch, block) is True
        block = p.factory.block(0x400000, opt_level=1, cross_insn_opt=True)
        assert CFGBase._is_noop_block(arch, block) is True

    def test_amd64_noop_blocks(self):
        # nop
        arch = archinfo.arch_from_id("amd64")
        b = b"\x90\x90\x90\x90\x90\x90\x90\x90"
        p = angr.load_shellcode(b, arch, load_address=0x400000)
        block = p.factory.block(0x400000, opt_level=1, cross_insn_opt=False)
        assert CFGBase._is_noop_block(arch, block) is True
        block = p.factory.block(0x400000, opt_level=1, cross_insn_opt=True)
        assert CFGBase._is_noop_block(arch, block) is True

    def test_arm_noop_blocks(self):
        arch = archinfo.arch_from_id("ARMEL")

        # andeq r0, r0, r0
        b = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        p = angr.load_shellcode(b, arch, load_address=0x400000)
        block = p.factory.block(0x400000, opt_level=1, cross_insn_opt=False)
        assert CFGBase._is_noop_block(arch, block) is True
        block = p.factory.block(0x400000, opt_level=1, cross_insn_opt=True)
        assert CFGBase._is_noop_block(arch, block) is True

        # mov r0, r0
        b = b"\x00\x00\xa0\xe1"
        p = angr.load_shellcode(b, arch, load_address=0x400000)
        block = p.factory.block(0x400000, opt_level=1, cross_insn_opt=False)
        assert CFGBase._is_noop_block(arch, block) is True
        block = p.factory.block(0x400000, opt_level=1, cross_insn_opt=True)
        assert CFGBase._is_noop_block(arch, block) is True


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const, Load, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.optimization_passes.const_derefs import BlockWalker
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "armel")
uboot_path = os.path.join(test_location, "decbench_uboot_O2_noinline_stripped")


class TestConstDerefOverlappingSections(unittest.TestCase):
    def test_efi_cin_read_key_stroke_ex_switch_survives(self):
        # u-boot overlays its (unallocated) .bss on .rel.dyn, so cle maps the address range read-only. The
        # constant-dereference passes folded the ldrb/ldrh switch-index loads of efi_cin_read_key_stroke_ex into
        # relocation bytes, leaving the jump-table block with a constant condition and no matching successor, which
        # made Phoenix fail on the function.
        proj, cfg = load_project_with_scoped_cfg(uboot_path, 0x60859C0C, window=0x200, expand_call_tree=False)
        dec = proj.analyses.Decompiler(cfg.functions[0x60859C0C], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "switch (" in text
        assert "g_6089b1a6" in text
        assert "if (0)" not in text

    def test_const_deref_reads_the_load_size(self):
        # ConstantDereferencesSimplifier read a pointer-sized word for every load; a byte load from .rodata must
        # fold into that byte only
        proj = angr.Project(uboot_path, auto_load_libs=False)
        manager = Manager()
        addr = 0x60875E40  # .rodata
        expected = proj.loader.memory.load(addr, 1)[0]
        load = Load(manager.next_atom(), Const(manager.next_atom(), addr, 32), 1, proj.arch.memory_endness)
        dst = VirtualVariable(manager.next_atom(), 0, 8, VirtualVariableCategory.REGISTER, 8)
        block = Block(0x1000, 4, statements=[Assignment(manager.next_atom(), dst, load)])

        new_block = BlockWalker(proj, manager).walk(block)

        assert new_block is not None
        src = new_block.statements[0].src
        assert isinstance(src, Const)
        assert src.bits == 8
        assert src.value == expected


if __name__ == "__main__":
    unittest.main()

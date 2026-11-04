#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import ailment
from angr.ailment.expression import Const, Load
from angr.analyses.decompiler.peephole_optimizations import ReadOnlyConstantDereferences
from tests.common import bin_location

BINARY = os.path.join(bin_location, "tests", "x86_64", "fauxware")
DATA = 0x601038  # .data: writable


class TestVMBytecodeDeref(unittest.TestCase):
    """VM peepholes read the VM's byte code as constants although its section is writable, unless the function
    writes the page."""

    def setUp(self):
        self.proj = angr.Project(BINARY, auto_load_libs=False)
        self.opt = ReadOnlyConstantDereferences(self.proj, self.proj.kb, ailment.Manager(), 0)

    def _load(self, addr, size):
        return Load(1, Const(2, addr, 64), size, "Iend_LE")

    def test_byte_code_region_is_constant(self):
        self.proj.byte_code_regions = [(DATA, DATA + 0x10)]
        self.proj.vm_written_image_pages = []
        out = self.opt.optimize(self._load(DATA + 4, 4))
        assert isinstance(out, Const)
        assert out.value == self.proj.loader.memory.unpack_word(DATA + 4, 4)
        # a read running past the region's end is not
        assert self.opt.optimize(self._load(DATA + 0xC, 8)) is None

    def test_a_page_the_function_writes_is_not_constant(self):
        # a global the devirtualized function itself sets, next to the byte code
        self.proj.byte_code_regions = [(DATA, DATA + 0x10)]
        self.proj.vm_written_image_pages = [DATA & ~0xFFF]
        assert self.opt.optimize(self._load(DATA + 4, 4)) is None

    def test_unknown_writes_are_not_constant(self):
        self.proj.byte_code_regions = [(DATA, DATA + 0x10)]
        self.proj.vm_written_image_pages = None
        assert self.opt.optimize(self._load(DATA + 4, 4)) is None

    def test_writable_section_is_not_constant(self):
        self.proj.byte_code_regions = None
        assert self.opt.optimize(self._load(DATA + 4, 4)) is None


if __name__ == "__main__":
    unittest.main()

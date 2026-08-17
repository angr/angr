#!/usr/bin/env python3
# pylint: disable=protected-access
from __future__ import annotations

__package__ = __package__ or "tests.simos"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.errors import SimMemoryError
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestSimLinuxStateBlank(unittest.TestCase):
    """
    Tests for the stack that SimLinux.state_blank() pre-grows.
    """

    binary = os.path.join(test_location, "x86_64", "fauxware")

    def test_stack_is_pre_grown(self):
        state = angr.Project(self.binary, auto_load_libs=False).factory.blank_state()
        sp = state.solver.eval(state.regs.sp)

        assert set(state.memory._pages) == set(range((sp - 0x20 * 0x1000) // 0x1000, sp // 0x1000))

    def test_stack_is_not_pre_grown_past_address_zero(self):
        project = angr.Project(self.binary, auto_load_libs=False)

        # 0x20 pages is more room than this stack has beneath it
        state = project.factory.blank_state(stack_end=0x10000)

        # none of them are pre-allocated, and in particular the excess does not wrap to the top of the address space
        assert not state.memory._pages
        with self.assertRaises(SimMemoryError):
            state.memory.permissions(0xFFFFFFFFFFFFF000)

    def test_pre_grown_stack_does_not_cover_the_loaded_image(self):
        # the same stack, with the image beneath it rather than above it
        project = angr.Project(
            self.binary,
            main_opts={"backend": "blob", "arch": "AMD64", "base_addr": 0x1000, "entry_point": 0x1000},
            auto_load_libs=False,
            simos="linux",
        )

        state = project.factory.blank_state(stack_end=0x10000)

        # pre-allocated stack pages are not backed by the loader, so clamping the pre-grow to the room that does
        # exist would hide the image behind blank pages
        assert state.solver.eval(state.memory.load(0x1000, 4, endness=archinfo.Endness.BE)) == 0x7F454C46


if __name__ == "__main__":
    unittest.main()

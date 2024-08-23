#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

import unittest

from angr import SimState


class TestMmap(unittest.TestCase):
    def test_mmap_base_copy(self):
        state = SimState(arch="AMD64", mode="symbolic")

        mmap_base = 0x12345678

        state.heap.mmap_base = mmap_base

        # Sanity check
        assert state.heap.mmap_base == mmap_base

        state_copy = state.copy()

        assert state_copy.heap.mmap_base == mmap_base


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.factory.block"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestBlockBytes(unittest.TestCase):
    def _lifted_blocks(self, p, addr, size):
        state = p.factory.blank_state()
        byte_string = p.loader.memory.load(addr, size)
        blocks = [
            p.factory.block(addr, size=size),
            p.factory.block(addr, size=size, backup_state=state),
            p.factory.block(addr, size=size, byte_string=byte_string),
        ]
        for block in blocks:
            _ = block.vex_nostmt
        return blocks

    def test_bytes_follow_size_after_lift(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        blocks = self._lifted_blocks(p, p.entry, 1024)

        assert blocks[0].size < 1024
        for block in blocks:
            assert block.size == blocks[0].size
            assert len(block.bytes) <= block.size
        assert blocks[0].bytes == blocks[1].bytes == blocks[2].bytes
        assert blocks[0] == blocks[1] == blocks[2]
        assert len({hash(block) for block in blocks}) == 1

    def test_bytes_follow_size_after_nodecode(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "ALLSTAR_9base_awk"), auto_load_libs=False)
        blocks = self._lifted_blocks(p, 0x4081B9, 1024)

        for block in blocks:
            assert block.vex_nostmt.jumpkind == "Ijk_NoDecode"
            assert block.size == 0
            assert block.bytes == b""


if __name__ == "__main__":
    unittest.main()

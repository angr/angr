# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest

from angr.analyses.decompiler.structured_codegen.base import InstructionMapping


class TestInstructionMapping(unittest.TestCase):
    def setUp(self):
        self.mapping = InstructionMapping()
        for ins_addr, pos in [(0x1010, 40), (0x1020, 80), (0x1030, 120)]:
            self.mapping.add_mapping(ins_addr, pos)

    def test_nearest_pos_inside_range(self):
        assert self.mapping.get_nearest_pos(0x1020) == 80
        assert self.mapping.get_nearest_pos(0x1014) == 40
        assert self.mapping.get_nearest_pos(0x101C) == 80

    def test_nearest_pos_below_first_mapped_address(self):
        # a function head that precedes the first rendered statement (e.g., a Go stack-check preamble)
        assert self.mapping.get_nearest_pos(0x1000) == 40

    def test_nearest_pos_above_last_mapped_address(self):
        assert self.mapping.get_nearest_pos(0x1040) == 120

    def test_nearest_pos_empty(self):
        assert InstructionMapping().get_nearest_pos(0x1000) is None


if __name__ == "__main__":
    unittest.main()

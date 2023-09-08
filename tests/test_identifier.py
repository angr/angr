#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
import logging
import os
import unittest

import angr

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries")


class TestIdentifier(unittest.TestCase):
    def test_comparison_identification(self):
        true_symbols = {0x804A3D0: "strncmp", 0x804A0F0: "strcmp", 0x8048E60: "memcmp", 0x8049F40: "strcasecmp"}

        p = angr.Project(os.path.join(bin_location, "tests", "i386", "identifiable"))
        idfer = p.analyses.Identifier(require_predecessors=False)

        seen = {}
        for addr, symbol in idfer.run():
            seen[addr] = symbol

        for addr, symbol in true_symbols.items():
            assert symbol == seen[addr]


if __name__ == "__main__":
    logging.getLogger("identifier").setLevel("DEBUG")
    unittest.main()

# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries")

import logging


class TestIdentifier(unittest.TestCase):
    def test_comparison_identification(self):
        true_symbols = {0x804A3D0: "strncmp", 0x804A0F0: "strcmp", 0x8048E60: "memcmp", 0x8049F40: "strcasecmp"}

        p = angr.Project(os.path.join(bin_location, "tests", "i386", "identifiable"))
        idfer = p.analyses.Identifier(require_predecessors=False)

        seen = {}
        for addr, symbol in idfer.run():
            seen[addr] = symbol

        for addr, symbol in true_symbols.items():
            assert true_symbols[addr] == seen[addr]

    def run_all(self):
        functions = globals()
        all_functions = dict(filter((lambda kv: kv[0].startswith("test_")), functions.items()))
        for f in sorted(all_functions.keys()):
            if hasattr(all_functions[f], "__call__"):
                all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("identifier").setLevel("DEBUG")
    unittest.main()

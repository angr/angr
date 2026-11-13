#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr
from angr.analyses.bindiff import NormalizedFunction
from tests.common import bin_location

l = logging.getLogger("angr.tests.test_bindiff")

test_location = os.path.join(bin_location, "tests")


# todo make a better test
# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestBindiff(unittest.TestCase):
    def test_normalized_call_sites(self):
        base = 0x400000
        first, second = base + 0x20, base + 0x21
        for targets in ((), (first,), (first, second), (first, second, first)):
            with self.subTest(targets=targets):
                code = bytearray()
                for target in targets:
                    code += b"\xe8" + (target - base - len(code) - 5).to_bytes(4, "little", signed=True)
                code += b"\xc3"
                code += b"\x90" * (0x20 - len(code)) + b"\xc3\xc3"
                project = angr.load_shellcode(bytes(code), "amd64", load_address=base)
                cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
                function = cfg.kb.functions[base]
                assert len(function.graph) == len(targets) + 1
                normalized = NormalizedFunction(function)
                assert len(normalized.graph) == 1
                assert normalized.call_sites.get(normalized.startpoint, []) == list(targets)

    def test_bindiff_x86_64(self):
        binary_path_1 = os.path.join(test_location, "x86_64", "bindiff_a")
        binary_path_2 = os.path.join(test_location, "x86_64", "bindiff_b")
        b = angr.Project(binary_path_1, load_options={"auto_load_libs": False})
        b2 = angr.Project(binary_path_2, load_options={"auto_load_libs": False})
        bindiff = b.analyses.BinDiff(b2)

        identical_functions = bindiff.identical_functions
        differing_functions = bindiff.differing_functions
        unmatched_functions = bindiff.unmatched_functions
        # check identical functions
        assert (0x40064C, 0x40066A) in identical_functions
        # check differing functions
        assert (0x400616, 0x400616) in differing_functions
        # check unmatched functions
        assert len(unmatched_functions[0]) <= 1
        assert len(unmatched_functions[1]) <= 2
        # check for no major regressions
        assert len(identical_functions) > len(differing_functions)
        assert len(differing_functions) < 4

        # check a function diff
        fdiff = bindiff.get_function_diff(0x400616, 0x400616)
        block_matches = {(a.addr, b.addr) for a, b in fdiff.block_matches}
        assert (0x40064A, 0x400668) in block_matches
        assert (0x400616, 0x400616) in block_matches
        assert (0x40061E, 0x40061E) in block_matches


if __name__ == "__main__":
    unittest.main()

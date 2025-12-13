#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr
from angr.analyses.bindiff import NormalizedFunction, NormalizedBlock

from tests.common import bin_location


l = logging.getLogger("angr.tests.test_bindiff")

test_location = os.path.join(bin_location, "tests")


# todo make a better test
# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestBindiff(unittest.TestCase):
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

    def test_normalized_func_callsites_x86_64(self):
        binary_path_1 = os.path.join(test_location, "x86_64", "df.o")
        b = angr.Project(binary_path_1, load_options={"auto_load_libs": False})
        cfg = b.analyses.CFGFast(normalize=True, data_references=True)

        func = b.kb.functions.get_by_addr(0x40054b)
        assert func is not None
        nf = NormalizedFunction(func)
        assert nf is not None
        assert len(nf.call_sites) == 2

        block_node = next(n for n in nf.graph.nodes() if n.addr == 0x40058f)
        nb = NormalizedBlock(block_node, nf)
        assert nb is not None
        assert sorted(nb.call_targets) == sorted([4195360, 4195276])

if __name__ == "__main__":
    unittest.main()

import logging
import os
import unittest

import angr

l = logging.getLogger("angr.tests.test_bindiff")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


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


if __name__ == "__main__":
    unittest.main()

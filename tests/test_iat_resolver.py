# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestIatResolver(unittest.TestCase):
    def test_iat(self):
        p = angr.Project(os.path.join(test_location, "i386", "simple_windows.exe"), auto_load_libs=False)
        cfg = p.analyses.CFGFast()

        strcmp_caller_bb = cfg.get_any_node(0x401010)
        assert len(strcmp_caller_bb.successors) == 1

        strcmp = strcmp_caller_bb.successors[0]
        assert strcmp.is_simprocedure
        assert strcmp.simprocedure_name == "strcmp"

        strcmp_successors = strcmp.successors
        assert len(strcmp_successors) == 1

        strcmp_ret_to = strcmp_successors[0]
        assert strcmp_ret_to.addr == 0x40102A


if __name__ == "__main__":
    unittest.main()

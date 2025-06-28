from __future__ import annotations
import os
import pytest
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")


class TestPerfCFGEmulated(unittest.TestCase):
    def __init__(self):
        self.p = angr.Project(os.path.join(test_location, "tests", "x86_64", "true"), auto_load_libs=False)
        self.funcs = list(self.p.analyses.CFGFast().functions.keys())

    @pytest.mark.benchmark
    def test_main(self):
        self.p.analyses.CFGEmulated(starts=self.funcs, call_depth=0)


if __name__ == "__main__":
    unittest.main()

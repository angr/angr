from __future__ import annotations
import os
import pytest
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")


class TestPerfCFGFast(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.p = angr.Project(os.path.join(test_location, "tests", "x86_64", "libc.so.6"), auto_load_libs=False)

    @pytest.mark.benchmark
    def test_main(self):
        self.p.analyses.CFGFast()


if __name__ == "__main__":
    unittest.main()

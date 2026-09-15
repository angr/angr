# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


class TestMipsGpPrologue(unittest.TestCase):
    def test_interleaved_gp_setup_mips64(self):
        # ldexpf sets $gp with lui/daddu/daddiu spread over the first 15 prologue instructions; stopping the scan
        # after the lui used to record a partial $gp
        bin_path = os.path.join(test_location, "mips64", "libc.so.6")
        proj, _ = load_project_with_scoped_cfg(bin_path, 0x453290, expand_call_tree=False, run_ccc=False)
        f = proj.kb.functions[0x453290]
        assert f.info["gp"] == 0x5B7810


if __name__ == "__main__":
    unittest.main()

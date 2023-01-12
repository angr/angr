import os
import unittest

import angr
import angr.analyses.decompiler


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestClinic(unittest.TestCase):
    def test_smoketest(self):
        binary_path = os.path.join(
            os.path.dirname(os.path.realpath(str(__file__))), "..", "..", "binaries", "tests", "x86_64", "all"
        )
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=True)

        cfg = proj.analyses.CFG(normalize=True)
        main_func = cfg.kb.functions["main"]

        proj.analyses.Clinic(main_func)


if __name__ == "__main__":
    unittest.main()

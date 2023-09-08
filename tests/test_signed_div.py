# pylint: disable=missing-class-docstring,no-self-use,line-too-long

import os
import subprocess
import sys
import unittest
from unittest import skipUnless

import angr

test_location = os.path.dirname(os.path.realpath(__file__))


class TestSignedDiv(unittest.TestCase):
    @skipUnless(sys.platform.startswith("linux"), "linux only")
    def test_signed_div(self):
        test_bin = os.path.join(test_location, "..", "..", "binaries", "tests", "x86_64", "test_signed_div")
        b = angr.Project(test_bin, auto_load_libs=False)

        pg = b.factory.simulation_manager()
        pg.explore()
        out_angr = pg.deadended[0].posix.dumps(1)
        with subprocess.Popen(test_bin, stdout=subprocess.PIPE) as proc:
            stdout_real, _ = proc.communicate()

        assert out_angr == stdout_real


if __name__ == "__main__":
    unittest.main()
